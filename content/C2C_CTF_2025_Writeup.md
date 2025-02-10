+++
title = "C2C CTF Writeup"
date = 2025-02-10
[taxonomies]
tags = ["CTF"]
+++

# この記事について
米国東部標準時間で 2025/2/7 の 22:00 から 2025/2/9 の 22:00 にかけて行われた C2C CTF 2025 の Writeup になります。

個人的にはPwnを期待していたのですが、Binary問に関してはどちらかというとReversingに近い問題でした。またBinary問は全5問と少なく、他参加者の解答数も多かったため比較的簡単な問題のようでした。

私が正解できたのは
- Binary問題のすべて
- Crypt: HuskyHunt
- Forensics: Unknown File type

の全7問です。


<!-- more-->
---

# Binary: HuskySniff
そのままhuskyusniffという実行ファイルが配られるのですが、stringsコマンド一発でフラグがゲットできました。
```
[figaro@figaro-endeavour huskysniff]$ strings huskysniff  | grep c2c
c2c_ctf{crwzotngdyqfqbjc}
```
よってフラグは`c2c_ctf{crwzotngdyqfqbjc}`となります。


# Binary: HuskyHungry
まずは実行から見ていきます
```
[figaro@figaro-endeavour huskyhungry]$ ./huskyhungry 
Arooo! Hey there, human friend-I'm feeling rumbly in my tummy again. If you bring me that tasty salmon I love so much, I'll let you in on a little secret...and by secret, I mean a very special flag! So don't keep a hungry Husky waiting-fetch that feast, and the flag is yours! Woof!
test
I sniff the bowl, wrinkle my nose, and whine softly—this meal just isn't doing it for me.
[figaro@figaro-endeavour huskyhungry]$ 
```
文字列testは私が単に入力しただけです。おそらくバイナリの中のわんちゃん(ハスキー)が納得する入力を与えればフラグを得られるのでしょう。となると静的解析をブン回すしかありません。


まずはHuskySniffと同様にstringsコマンドにかけてみたところ「UPX」なる圧縮がされているという文字列を見かけました(解凍して上書き済みなので証拠がありませんが...)。確かに不可思議な文字列が多く存在していたので圧縮されているのだろうと検討をつけ`upx -d huskyhungry`で解凍。

解凍した状態でもう一度stringsにかけてみると`n2n_neq{MfTjlbkFZysblJfG}`なる文字列を発見できます。CTFのフラグの形式にとても似ていたためこれをフラグにするような処理があるのだろうと考えました
```
[figaro@figaro-endeavour huskyhungry]$ strings huskyhungry
--前略--
zPLR
zPLR
zPLR
zPLR
zPLR
n2n_neq{MfTjlbkFZysblJfG} <-------------------------------------- これ
Mmm, this is perfect! I'm so happy I'm practically dancing
thanks for the yummy food. Here's your flag! Aroo! 
I sniff the bowl, wrinkle my nose, and whine softly
t[figaro@figaro-endeavour huskyhungry]$ ./huskyhungry 
Arooo! Hey there, human friend-I'm feeling rumbly in my tummy again. If you bring me that tasty salmon I love so much, I'll let you in on a little secret...and by secret, I mean a very special flag! So don't keep a hungry Husky waiting-fetch that feast, and the flag is yours! Woof!
test
I sniff the bowl, wrinkle my nose, and whine softly—this meal just isn't doing it for me.
[figaro@figaro-endeavour huskyhungry]$ 
his meal just isn't doing it for me.
Qjfs%rjfy%fsi%knxm
--後略--
```
また、フラグの下にあるテキストは、正しい入力によって正解した場合に出力されるテキストのように思えます。よってこの暗号化?されているフラグと正解後のテキストを元に、それらを参照している処理をGhidraから探し当てて解析していこうと考えました。実際Ghidraを起動して先程の暗号化されたフラグや正解時のテキストを参照するような処理を検索していくと、対象の処理にたどり着けます。ただ、その処理が(私には)難解で解読する気が起きなかったので、ここで方針を転換しました。

何をしたかと言うと、GDBで復号化をしているような処理に直接飛びました。Ghidraの解析から暗号化されたフラグは特定の入力を行えた際に復号化されることが判明したので、入力で条件をクリアするのではなく直接条件をクリアした後の処理に飛ぶことにしたのです。これは邪道というかDockerでバイナリが実行されているような状態では行えない方法なので、正直いい気はしませんがルール的には違反していないように思えたため行いました。

以下が当該処理とそのアドレスになります。

{{ image(src="/C2C_CTF_Images/huskyhungry_ghidra.png", alt="huskyhungry_ghidra", position="center") }}

ESIとRDIを設定させるためにも0x0040189bにRIPを設定すれば良いと分かります。おさらいですが、処理のフローとしては
- 入力
- 入力が正しいかどうか
	- 正しければ復号
	- 正しくなければ何もしない

ということなので、「入力が正しいかどうか」という条件分岐の直前まで実行を進め、その後に0x0040189bへジャンプします。そうでなければ復号処理以前にある、何かしら復号に必要な情報を欠落することになります。つまり、ジャンプして飛ばす処理は最小限(ここでは条件分岐のみ)に留めなければなりません。

このときのスクショは取っていないし、ghidraで再確認して再現するのも面倒なので詳細なものは載せませんが、これによってフラグを得ることができます。なおフラグは`c2c_ctf{BuIyaqzUOnhqaYuV}`です。

先程も言及しましたが、どう考えても期待された解法で無いことは明らかです。実際、この後の問題もそうでしたが、フラグを得るための正しい入力が存在しているようで、それをghidraなどで紐解くのが本来の解法のように思えます。~ある意味Hackでは?~

# Binary: huskywalk
例によってまずは実行してみます
```
[figaro@figaro-endeavour huskywalk]$ ./huskywalk 
Hey hooman! Can we pleaaase go to the park? I wanna run super fast, sniff all the things, and maybe make some new furry friends! Pretty please with extra belly rubs? Which park are we going to?!
test
Umm, hooman… not that park! It's boring, no good sniffs, and no fun friends to play with! Can we go somewhere way more exciting instead? Pleaaase?
```
あぁ... 先と同じですね?

さらにはstringsしてみるとまたUPXで圧縮されていたので解凍します(上書き以下略)。解凍したら得られた文字列を参照している処理をGhidraで見てみましょう。

{{ image(src="/C2C_CTF_Images/huskywalk_ghidra.png", alt="huskywakl_ghidra", position="center") }}

!? フラグ見えてるやんけ! というわけでフラグは`c2c_ctf{Qv7T8bWcY3nR}`です。なお後で気づきましたが、`Carter Playground`が期待する正しい入力で、その場合にフラグが出力されるようでした。

# Binary: huskyplay
```
[figaro@figaro-endeavour huskyplay]$ ./huskyplay
Hey hooman, I've been such a good pup today! Do you think maybe, just maybe, you have a little surprise for me? Something fun, something squeaky, something I can chase around and cuddle with? Pleeeease?
test
Hooman, I appreciate the effort, but... um, what is this? It doesn't squeak, it doesn't bounce, and it definitely doesn't taste like anything fun. Are you sure this is for me? Maybe we can, you know... trade it for something cooler? Just saying!
```
はい、正しい入力を渡しましょう。案の定stringsしてUPXで解凍で、該当処理をGhidraで解析します。

{{ image(src="/C2C_CTF_Images/huskyplay_ghidra.png", alt="huskyplay_ghidra", position="center") }}

やることは同じです。正しい入力なんて考えていられないのでGDBでジャンプします。はいフラグ`c2c_ctf{qxoPvvViujwagNRl}`

# Binary: huskyrescue
これは正規の方法で答えたので丁寧に解説します。

まずは実行してみます。
```
[figaro@figaro-endeavour huskyrescue]$ ./huskyrescue 
Woof woof! It's me, Husky! I'm stuck in this big, confusing maze, and I really need your help to find my way out. I can move up (1), down (2), left (3), or right (4), but some paths are blocked, and I don't want to get lost! Please tell me the right sequence of moves all at once so I can make it to the exit safely. I promise I'll be the best boy and listen carefully! I know you won't let me down! Enter movement sequence (1=Up, 2=Down, 3=Left, 4=Right): 2
Wait... this isn't right... I think I'm lost!
```

どうやらハスキーは迷路の中で迷っており、「1, 2, 3, 4」の組み合わせで出口まで案内する必要があるようです。

stringsを使って文字列を抽出してみます。なお今回はUPXによる圧縮がありませんでした。

```
[figaro@figaro-endeavour huskyrescue]$ strings ./huskyrescue 
--前略--
Woof woof! It's me, Husky! I'm stuck in this big, confusing maze, and I really need your help to find my way out. I can move up (1), down (2), left (3), or right (4), but some paths are blocked, and I don't want to get lost! Please tell me the right sequence of moves all at once so I can make it to the exit safely. I promise I'll be the best boy and listen carefully! I know you won't let me down! Enter movement sequence (1=Up, 2=Down, 3=Left, 4=Right): 
Uh-oh! That doesn't look right... I don't understand this! Can you give me the moves in the correct format?
Wait... this isn't right... I think I'm lost!
Yay! You did it! I made it out of the maze, all thanks to you! You're the best! As a reward for rescuing me, here's something special. Take it and wear it proudly! %s
--後略--
```

実行したときに見えた文字列と、おそらく正解したときに出現する文字列があるようです。これら文字列を元にGhidraを使って、文字列を参照している関数などを検索してみます。(というかシンボルが残っているのでmainがghidraから探せるはずでもあります)

{{ image(src="/C2C_CTF_Images/huskyrescue_ghidra_1.png", alt="huskyrescue_ghidra", position="center") }}

ありました。上の文字列は実行したときに見える説明と入力を促すテキストであり、下のテキストはおそらく正解した際に出力されるテキストであるということが推測できます。

注目してほしいのはmove_husky()関数であり、1-4の入力の組み合わせがmove_husky()関数によって処理され、その結果如何によってハズレの処理か、正解の復号化を行う処理化が分岐するということが見て取れます。次はmove_husky()関数を覗いてみましょう。

画像では無いのですが、中の処理は以下のとおりでした。(ある程度変数名を命名し直しています。)

```c
bool move_husky(char *param_1)

{
  size_t param_str_len;
  char *pcVar1;
  uint Y;
  uint X;
  char input;
  
  param_str_len = strlen(param_1);
  X = 0;
  Y = 0;
  pcVar1 = param_1 + param_str_len;
  do {
    if (pcVar1 == param_1) {
      return X == 3 && Y == 3;
    }
    input = *param_1;
    if (input == '3') {
      X = X - 1;
    }
    else if (input < '4') {
      if (input == '1') {
        Y = Y - 1;
      }
      else {
        if (input != '2') {
          return false;
        }
        Y = Y + 1;
      }
    }
    else {
      if (input != '4') {
        return false;
      }
      X = X + 1;
    }
    if (3 < Y) {
      return false;
    }
    if (3 < X) {
      return false;
    }
    param_1 = param_1 + 1;
  } while (*(int *)(&maze + ((long)(int)X + (long)(int)Y * 4) * 4) == 0);
  	  return false;
}
```

この処理から分かることは以下の通りです
- XとY、mazeが存在している
- XとYがとり得るのは初期値0から最大3までの4通りである
- 移動指定である1-4までの文字の組み合わせによってXとYの値は増減する(例: 2(down)はY=Y-1する)
- while処理で、XとYはmazeに渡されて参照されることから、XとYはmazeのIndexである
- XとYが0-3までと制限されていることから、mazeは最大でも`maze[3][3]`であり、つまりmazeは4*4の配列である
- XとYの初期値が0ということは、ハスキーは最初`maze[0][0]`にいる
- また、while処理で`maze[x][y] == 0`である場合は、入力した文字列(1-4の組み合わせ)を処理し続ける
- move_husky()は、移動指定によって移動する先が0なら移動し、0以外なら通れずにfalseを返す
- falseを返すということはフラグが出現しないため、0以外の「壁」に遭遇した瞬間にフラグは得られない
- もしX=Y=3であればfalseではないものを返す (mainを見れば分かるが、move_husky()が0ことfalseを返すときはフラグが復号化されない)

このことを総合すると、1-4までの移動指定で0の道を通りながら`maze[0][0]`から`maze[3][3]`に到達する必要が有り、壁(0以外)に遭遇してはいけないと分かります。

これを考慮してmazeを参照してみましょう
```
00 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00
```
このようなバイト列が存在していました。我々の想定どおりで、0と1(0以外と想定しており実際は1だった)のみが存在しています。

ここで次の問題に遭遇します。mazeは確かに0と1のみで構成されているが、これをどのようにして迷路と考えることができるのかということです。

そして、答えは`maze[3][3]`にあります。つまり私達は`4*4`の配列が存在することを期待していたことを思い出してください。上記バイト列は64byteですから、これが4*4の配列になるように整列させれば良いのです。ということで整列させてみましょう。
```
00 00 00 00  01 00 00 00  01 00 00 00  01 00 00 00 
00 00 00 00  00 00 00 00  01 00 00 00  01 00 00 00 
01 00 00 00  00 00 00 00  00 00 00 00  01 00 00 00 
01 00 00 00  01 00 00 00  00 00 00 00  00 00 00 00
```

あぁ... 一目瞭然ですね。

おそらく`4*4`の配列ですから、4byteを1つの塊として考えなくてはいけません。つまり`00 00 00 00`は`0`であり、`01 00 00 00`は`1`です。これを考慮して再構成します。(多分リトルエンディアンだからでしょう)

```
0 1 1 1
0 0 1 1
1 0 0 1
1 1 0 0
```

よろしい。ハスキーは`maze[0][0]`にいますから、`maze[3][3]`へたどり着くには`1`を回避するようにして
```
2 Down
4 Right
2 Down
4 Right
2 Down 
4 Right
```
とすれば壁(1)に移動せず`maze[3][3]`にたどり着けます。

では実際に入力を与えてみましょう。(見やすいように改行を入れています)

```
[figaro@figaro-endeavour huskyrescue]$ ./huskyrescue 
Woof woof! It's me, Husky! I'm stuck in this big, confusing maze, and I really need your help to find my way out. 
I can move up (1), down (2), left (3), or right (4), but some paths are blocked, and I don't want to get lost! 
Please tell me the right sequence of moves all at once so I can make it to the exit safely. I promise I'll be the best boy and listen carefully! 

I know you won't let me down! Enter movement sequence
(1=Up, 2=Down, 3=Left, 4=Right): 242424

Yay! You did it! I made it out of the maze, all thanks to you! You're the best! As a reward for rescuing me, here's something special. 
Take it and wear it proudly! c2c_ctf{lzrtrdtEDFuxmvaD5Uguva}
```

入手できました。フラグは`c2c_ctf{lzrtrdtEDFuxmvaD5Uguva}`となります。

---

# Crypt: husky hunt
以下の文字列が渡されます。
```
S2lsbyBSb21lbyBFY2hvIE5vdmVtYmVyIFRhbmdvIFp1bHUgTWlrZSBBbHBoYSBOb3ZlbWJlcg==
```
Cryptで、最後に`=`があることからこれはBase64でエンコードされていると考えられます。デコードしてみましょう。結果は以下のとおりです。
```
Kilo Romeo Echo November Tango Zulu Mike Alpha November
```
フォネティックコードですね。頭文字をとってみたらいい感じかもしれません。(実際にそう思ったのでやりました)
```
KRENTZMAN
```
なんか名前っぽいしフラグかな? -> 正解! (`C2C_CTF{KRENTZMAN}`)

---

# Forensics: Unknown File Type
`OSINT-SuperEasy.gb`というファイルが与えれます。`.gb`はゲームボーイのROMファイルだそうです。なので、エミュレータで起動してみました。そうしたら以下の文字列が見えました。
```
C2CCTF{2443f7d3eb2f47412b324dc0f4fdd194914dada963e830a6d46d489e7323d089}
```
何の捻りもないマ?

---

# 最後に
全く関係ないのですが、画像を貼ると見栄えが悪いですね。それに文章を書き殴ったので分かりにくいかもしれません。

ちなみに、ゲームボーイのROMファイルに関しては知り合いのオタクが魔改造3DSでこれを起動し、フラグを見ていました。
