# Path Traversal - C Language

# Logical Bug: Path Traversal

## 들어가며

---

리눅스 프로그램은 파일 시스템에 접근하여 어떤 파일의 데이터를 읽거나, 파일에 데이터를 쓸 수 있다. 예를 들어, 리눅스의 기본 유틸리티인 cat으로 파일의 데이터를 출력하게 하면, cat은 파일을 열고, 읽은 다음 stdout에 데이터를 출력한다.

로컬 파일 시스템에 접근하는 서비스를 외부에 공개할 때는 접근할 수 있는 파일의 경로에 제한을 두어야 한다. 예를 들어, 사용자에게 각자의 디렉토리를 생성해주고, 그 디렉토리를 자유롭게 활용할 수 있게 해주는 서비스가 있다고 하자. 이런 서비스를 개발할 때는 당연히 사용자 자신의 디렉토리만 접근할 수 있게 해야한다. 악의적인 사용자가 다른 사용자의 파일을 훔치거나, 서버의 파일을 조작하여 서버를 장악할 수 있기 때문이다.

**Path Traversal**은 이와 같은 서비스가 있을 때, 사용자가 허용되지 않은 경로에 접근할 수 있는 취약점을 말한다. 사용자가 접근하려는 경로에 대한 검사가 미흡하여 발생하며, 임의 파일 읽기 및 쓰기의 수단으로 활용될 수 있다.

# 리눅스 경로

## 절대 경로와 상대 경로

---

리눅스에는 파일의 경로를 지정하는 두 가지 방법으로 **절대 경로(Absolute Path)**와 **상대 경로(Relative Path)**가 있다.

- 절대 경로 : 루트 디렉토리부터 파일에 이를 때까지 거쳐야 하는 디렉토리 명을 모두 연결하여 구성한다.
- 상대 경로 : 현재 디렉토리를 기준으로 다른 파일에 이르는 경로를 상대적으로 표현한 것이다.
..은 이전 디렉토리, .은 현재 디렉토리를 의미한다.

드림핵에서는 절대 경로와 달리 상대 경로의 수는 무한하다고 하였지만, 실제로는 절대 경로의 수도 무한하다.

- “../”를 끼워 넣는 경우 : /etc/../etc/passwd
- 심볼릭 링크 : /tmp/link가 /etc를 가리키면 /tmp/link/passwd도 같은 파일
- 하드 링크 : 같은 inode를 가리키는 별도 경로
- bind mount : 같은 디렉토리가 다른 마운트 포인트에 걸려 있는 경우
- /proc/self/root/etc/passwd 같은 특수 경로

# Path Traversal

## Path Traversal

---

Path Traversal은 권한 없는 경로에 프로세스가 접근할 수 있는 취약점을 말한다. 여기서 권한은 리눅스의 파일 시스템의 권한이 아니라, 서비스 로직 관점에서의 권한을 의미한다.

### Path Traversal 예제 코드

```c
// Name: path_traversal.c
// Compile: gcc -o path_traversal path_traversal.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const int kMaxNameLen = 0x100;
const int kMaxPathLen = 0x200;
const int kMaxDataLen = 0x1000;
const char *kBasepath = "/tmp";

int main() {
  char file_name[kMaxNameLen];
  char file_path[kMaxPathLen];
  char data[kMaxDataLen];
  FILE *fp = NULL;

  // Initialize local variables
  memset(file_name, '\0', kMaxNameLen);
  memset(file_path, '\0', kMaxPathLen);
  memset(data, '\0', kMaxDataLen);

  // Receive input from user
  printf("File name: ");
  fgets(file_name, kMaxNameLen, stdin);

  // Trim trailing new line
  file_name[strcspn(file_name, "\n")] = '\0';

  // Construct the `file_path`
  snprintf(file_path, kMaxPathLen, "%s/%s", kBasepath, file_name);

  // Read the file and print its content
  if ((fp = fopen(file_path, "r")) == NULL) {
    fprintf(stderr, "No file named %s", file_name);
    return -1;
  }

  fgets(data, kMaxDataLen, fp);
  printf("%s", data);

  fclose(fp);

  return 0;
}

```

위 코드의 흐름을 따라가 보자.

**변수 선언**

```c
char file_name[kMaxNameLen];   // 0x100(256) 바이트 — 사용자 입력 저장용
char file_path[kMaxPathLen];   // 0x200(512) 바이트 — 최종 경로 저장용
char data[kMaxDataLen];        // 0x1000(4096) 바이트 — 파일 내용 저장용
FILE *fp = NULL;
```

**초기화**

```c
memset(file_name, '\0', kMaxNameLen);
memset(file_path, '\0', kMaxPathLen);
memset(data, '\0', kMaxDataLen);
```

새 버퍼를 전부 NULL 바이트로 밀어서 초기화한다.

**사용자 입력 받기**

```c
printf("File name: ");
fgets(file_name, kMaxNameLen, stdin);
```

fgets는 최대 kMaxNameLen - 1 (255) 바이트까지 읽고, 마지막에 NULL 종료자를 붙여준다. 개행문도자(\n)도 포함해서 저장한다.

**개행문자 제거**

```c
file_name[strcspn(file_name, "\n")] = '\0';
```

strcspn 함수는 “string complement span”의 약자로 문자열을 앞에서부터 한 글자씩 스캔하면서, 두번째 인자인 \n이 처음 나타나는 위치를 반환한다.

따라서 이 프로그램에서는 개행을 널로 변환한 것이다.

**경로 조합**

```c
snprintf(file_path, kMaxPathLen, "%s/%s", kBasepath, file_name);
```

snprintf 함수는 sprintf 함수에서 최대 쓰기 크기를 제한한 버전이다.

kBasepath가 “/tmp”이므로, 사용자가 hello.txt를 입력했다면 file_path는 “/tmp/hello.txt”가 된다. snprintf는 kMaxPathLen (512)을 넘지 않도록 잘라주므로 버퍼 오버플로우는 없다.

**파일 열기 및 읽기**

```c
if ((fp = fopen(file_path, "r")) == NULL) {
    fprintf(stderr, "No file named %s", file_name);
    return -1;
}
fgets(data, kMaxDataLen, fp);
printf("%s", data);
fclose(fp);
```

fopen으로 file_path를 읽기 모드로 연다. 파일이 없으면 에러 메세지가 출력되고, 성공하면 fgets로 첫 줄을 data에 읽어서 출력한 뒤 파일을 닫는다.

위 코드에서 /etc/passwd를 읽을 수 있는 입력은 ../etc/passwd 이다. 이렇게 되면 절대경로로 /tmp/../etc/passwd가 된다.