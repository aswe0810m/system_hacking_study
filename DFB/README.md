# Double Free Bug

# Memory Corruption: Double Free Bug

## 들어가며

---

Tcache와 bins는 해제된 메모리가 저장된다. 따라서 이를 다른 관점에서 보면, 오히려 free함수는 청크를 추가하는 함수, malloc은 청크를 꺼내는 함수로 볼 수 있다. 따라서 free를 두번 적용하는 것은, free list에 동일한 원소를 여러번 추가할 수 있음을 의미한다.

청크가 free list에 중복해서 존재하면 청크가 duplicated(복제) 되었다고 표현하는데, 해커들은 이를 이용하여 임의 주소에 청크를 할당할 수 있음을 밝혀냈다. 이러한 청크 중복 해제는 보안상의 약점으로 분류되어 **Double Free Bug (DFB)**라고 불린다.

스택에 대한 공격과 마찬가지로 힙에 대한 공격도 시간이 지나면서 발전되고 힙과 관련되 영역들의 새로운 보호 기법도 탄생되었다. 그로 인해서 Glibc 버전이 높아질수록 공격의 복잡도가 올라갔다. 이번 강의는 Glibc 2.27 버전이 내장된 Ubuntu 18.04 64-bit 환경을 기반으로 설명한다.

### 실습 환경 Dockerfile

UAF에서 세팅한 환경과 동일하게 맞추면 된다.

## Double Free Bug

---

ptmalloc2에서, free list의 각 청크들은 fd와 bk로 연결된다.

- fd : 자신보다 이후에 해제된 청크를 가리키는 포인터
- bk : 자신보다 이전에 해제된 청크를 가리키는 포인터

이때 해제된 청크에서 fd와 bk 값을 저장하는 공간은 할당된 청크에서 데이터를 저장하는데 사용된다. 따라서 만약 어떤 청크가 free list에 중복해서 포함된다면, 첫번째 할당에서 fd와 bk를 조작하여 free list에 임의 주소를 포함시킬 수 있다.

DFB를 이용하면 공격자에게 임의 주소 쓰기, 임의 주소 읽기, 임의 코드 실행, 서비스 거부 등의 수단으로 활용될 수 있다. 이때 dangling pointer가 생성되는지 그리고 이를 대상으로 free를 호출하는 것이 가능한지 살피면 Double Free Bug가 존재하는지 가늠할 수 있다.

초기에는 double free에 대한 검사가 미흡하여 Double Free Bug가 있으면 쉽게 트리거할 수 있었다. 특히, glibc 2.26 버전부터 도입된 tcache는 도입 당시에 보호 기법이 전무하여 double free의 쉬운 먹잇감이 되었다.

하지만 시간이 지나면서 이와 관련한 보호 기법이 glibc에 구현되었고 이를 우회하지 않으면 같은 청크를 두 번 해제하는 즉시 프로세스가 종료된다.

### Tcache Double Free

```c
// Name: dfb.c
// Compile: gcc -o dfb dfb.c

#include <stdio.h>
#include <stdlib.h>

int main() {
  char *chunk;
  chunk = malloc(0x50);

  printf("Address of chunk: %p\n", chunk);

  free(chunk);
  free(chunk); // Free again
}
```

```c
$ ./dfb
Address of chunk: 0x55ce62641260
free(): double free detected in tcache 2
zsh: abort      ./dfb
```

위의 코드 실행 결과를 보면 알 수 있듯이 동일한 chunk에 대해 free가 발생하면 프로세스가 그 즉시 종료된다.

# Mitigation for Tcache DFB

## 정적 패치 분석

---

### tcache_entry

Tcache에 도입된 보호 기법을 분석하기 위해, 패치된 코드의 diff를 살펴보자. 하단의 코드를 보면 double free를 탐지하기 위해 key 포인터가 tcache_entry에 추가되었음을 알 수 있다.

```c
typedef struct tcache_entry {
  struct tcache_entry *next;
+ /* This field exists to detect double frees.  */
+ struct tcache_perthread_struct *key;
} tcache_entry;
```

tcache_entry는 해제된 tcache 청크들이 갖는 구조이다. 이때 tcache는 단일 연결 리스트이므로, fd는 있지만 bk부분은 필요하지 않다. 따라서 bk부분 대신에 key가 들어가게된다.

### tcache_put

```c
tcache_put(mchunkptr chunk, size_t tc_idx) {
  tcache_entry *e = (tcache_entry *)chunk2mem(chunk);
  assert(tc_idx < TCACHE_MAX_BINS);
  
+ /* Mark this chunk as "in the tcache" so the test in _int_free will detect a
+      double free.  */
+ e->key = tcache;
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```

tcache_put은 해제한 청크를 tcache에 추가하는 함수이다. tcache_put 함수는 해제되는 청크의 key에 tcache라는 값을 대입하도록 변경되었다. 여기서 tcache는 tcache_perthread라는 구조체 변수를 가리킨다.

### tcache_get

```c
tcache_get (size_t tc_idx)
   assert (tcache->entries[tc_idx] > 0);
   tcache->entries[tc_idx] = e->next;
   --(tcache->counts[tc_idx]);
+  e->key = NULL;
   return (void *) e;
 }
```

tcache_get은 tcache에 연결된 청크를 재사용할 때 사용하는 함수로, key값에 NULL을 대입하도록 변경되었다.

### _int_free

_int_free는 청크를 해제할 때 호출되는 함수로, 재할당하려는 청크의 key 값이 tcache이면 Double Free가 발생했다고 의심한다. 이때 key값이 정말 낮은 확률로 tcache 값과 일치할 수도 있기 때문에, 해당 chunk 크기에 맞는 tcache bin에 그 청크가 이미 있는지 확인하고 있다면 프로그램을 abort시킨다.

```c
_int_free (mstate av, mchunkptr p, int have_lock)
 #if USE_TCACHE
    {
     size_t tc_idx = csize2tidx (size);
-
-    if (tcache
-       && tc_idx < mp_.tcache_bins
-       && tcache->counts[tc_idx] < mp_.tcache_count)
+    if (tcache != NULL && tc_idx < mp_.tcache_bins)
       {
-       tcache_put (p, tc_idx);
-       return;
+       /* Check to see if it's already in the tcache.  */
+       tcache_entry *e = (tcache_entry *) chunk2mem (p);
+
+       /* This test succeeds on double free.  However, we don't 100%
+          trust it (it also matches random payload data at a 1 in
+          2^<size_t> chance), so verify it's not an unlikely
+          coincidence before aborting.  */
+       if (__glibc_unlikely (e->key == tcache))
+         {
+           tcache_entry *tmp;
+           LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
+           for (tmp = tcache->entries[tc_idx];
+                tmp;
+                tmp = tmp->next)
+             if (tmp == e)
+               malloc_printerr ("free(): double free detected in tcache 2");
+           /* If we get here, it was a coincidence.  We've wasted a
+              few cycles, but don't abort.  */
+         }
+
+       if (tcache->counts[tc_idx] < mp_.tcache_count)
+         {
+           tcache_put (p, tc_idx);
+           return;
+         }
       }
   }
  #endif
```

이때 조건문에서 key가 tcache와 동일한지만 확인하므로, 만약 key 값을 변조할 수 있게된다면 double free를 일으킬 수 있다.

## 동적 분석

---

gdb를 이용하여 보호 기법의 적용 과정을 동적 분석해보자.

청크 할당 직후에 중단점을 설정하고 실행해보자.

```c
$ gdb -q double_free
pwndbg> disass main
   0x00005555555546da <+0>:     push   rbp
   0x00005555555546db <+1>:     mov    rbp,rsp
   0x00005555555546de <+4>:     sub    rsp,0x10
   0x00005555555546e2 <+8>:     mov    edi,0x50
   0x00005555555546e7 <+13>:    call   0x5555555545b0 <malloc@plt>
   0x00005555555546ec <+18>:    mov    QWORD PTR [rbp-0x8],rax
   ...
pwndbg> b *main+18
Breakpoint 1 at 0x5555555546ec
pwndbg> r
```

heap 명령으로 청크들의 정보를 보면 다음과 같다.

```c
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555756000
Size: 0x251

Allocated chunk | PREV_INUSE
Addr: 0x555555756250
Size: 0x61

Top chunk | PREV_INUSE
Addr: 0x5555557562b0
Size: 0x20d51
```

이 중 malloc(0x50)으로 생성한 chunk의 주소는 0x555555756250이다. 해당 메모리 값을 덤프하면, 아무런 데이터가 입력되지 않았음을 확인 할 수 있다.

```c
pwndbg> x/4gx 0x555555756250
0x555555756250: 0x0000000000000000      0x0000000000000061
0x555555756260: 0x0000000000000000      0x0000000000000000
```

이후의 참조를 위해서 gdb에서 chunk 변수로 정의하고 넘어가자. 이때 chunk는 prev_size, size, next, key가 각각 8바이트씩 존재하므로 chunk 변수로 정의하는 곳의 주소는 chunk의 시작 주소에 0x10을 더해야한다.

```c
pwndbg> set $chunk=(tcache_entry *)0x555555756260 // 0x555555756250 + 0x10
```

chunk를 해제할 때까지 실행하고, 청크의 메모리를 출력하면 다음과 같다.

```c
pwndbg> disass main
   0x0000555555554703 <+41>:    call   0x5555555545a0 <printf@plt>
   0x0000555555554708 <+46>:    mov    rax,QWORD PTR [rbp-0x8]
   0x000055555555470c <+50>:    mov    rdi,rax
   0x000055555555470f <+53>:    call   0x555555554590 <free@plt>
   0x0000555555554714 <+58>:    mov    rax,QWORD PTR [rbp-0x8]
pwndbg> b *main+58
Breakpoint 2 at 0x0000555555554714
pwndbg> c
pwndbg> print *$chunk
$1 = {
  next = 0x0,
  key = 0x555555756010
}
```

chunk의 key 값이 0x555555756010으로 설정된 것을 확인 할 수 있다.

이 주소의 메모리 값을 조회하면, 해제한 chunk의 주소 0x555555756260가 entry에 포함되어 있음을 알 수 있는데, 이는 tcache_perthread에 tcache들이 저장되기 때문이다. 헤더의 시작 주소가 아니라 데이터의 시작 주소를 알려주기 때문에 0x555555756250이 아니라 0x555555756260이 나온다.

```c
print *(tcache_perthread_struct *)0x555555756010
$2 = {
  counts = "\000\000\000\000\001", '\000' <repeats 58 times>,
  entries = {0x0, 0x0, 0x0, 0x0, 0x555555756260, 0x0 <repeats 59 times>}
}
```

이 상태에서 실행을 재개하면 key 값을 변경하지 않고, free를 호출하므로, abort가 발생한다.

### 우회 기법

앞의 분석에서 알 수 있듯이, if (__glibc_unlikely (e→key == tcache))만 통과하면 tcache 청크를 double free 시킬 수 있다. 

```c
+       /* This test succeeds on double free.  However, we don't 100%
+          trust it (it also matches random payload data at a 1 in
+          2^<size_t> chance), so verify it's not an unlikely
+          coincidence before aborting.  */
+       if (__glibc_unlikely (e->key == tcache)) // Bypass it!
+         {
+           ...
+             if (tmp == e)
+               malloc_printerr ("free(): double free detected in tcache 2");
+         }
+           ...
+       if (tcache->counts[tc_idx] < mp_.tcache_count)
+         {
+           tcache_put (p, tc_idx);
+           return;
+         }
       }
```

이때 정확히 일치하는지 확인하므로, key 값을 1비트만이라도 바꾸면, 이 보호 기법을 우회할 수 있다.

# Tcache Duplication

## Tcache Duplication

---

tcache에 적용된 double free 보호 기법을 우회하여 Double Free Bug를 트리거하는 코드를 보자.

```c
// Name: tcache_dup.c
// Compile: gcc -o tcache_dup tcache_dup.c

#include <stdio.h>
#include <stdlib.h>

int main() {
  void *chunk = malloc(0x20);
  printf("Chunk to be double-freed: %p\n", chunk);

  free(chunk);

  *(char *)(chunk + 8) = 0xff;  // manipulate chunk->key
  free(chunk);                  // free chunk in twice

  printf("First allocation: %p\n", malloc(0x20));
  printf("Second allocation: %p\n", malloc(0x20));

  return 0;
}
```

```c
$ ./tcache_dup
Chunk to be double-freed: 0x55d4db927260
First allocation: 0x55d4db927260
Second allocation: 0x55d4db927260
```

chunk의 주소는 데이터를 쓰는 곳이므로 next가 있는 위치이고 따라서 key를 바꾸기 위해서는 8바이트 만큼 이동해야한다. 이를 이용해 key 값을 변경하면 chunk가 tcache에 중복 연결되어 연속을 재할당 되는 것을 확인할 수 있다.

# Double Free Bug Lab

## Double Free Bug Lab 실습

---

[https://learn.dreamhack.io/labs/87242b18-bf9a-41ab-bde8-320a4427fb5e](https://learn.dreamhack.io/labs/87242b18-bf9a-41ab-bde8-320a4427fb5e)

여기서 lab 실습을 할 수 있다.

코드를 살펴보면 할당된 청크를 free로 해제한 뒤 포인터를 NULL로 변경하지 않아서 해제된 청크에 접근할 수 있다. 따라서 해제한 청크에 접근하여 key값을 변조한 뒤, 이를 이용해 Double Free Bug를 일으킬 수 있다.

# 실습

## Exploit Tech

---

[Exploit Tech: Tcache Poisoning](Exploit%20Tech%20Tcache%20Poisoning%2036aa9179d3af800f81c2fb1bcc28e267.md)

## Exercise

---

[Exercise: tcache_dup](Exercise%20tcache_dup%2036ba9179d3af80f398c4d217e652af00.md)

[Exercise: tcache_dup2](Exercise%20tcache_dup2%2036ca9179d3af80daa610fe4427c6767e.md)