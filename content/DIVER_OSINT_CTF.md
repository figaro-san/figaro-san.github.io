+++
date = 2024-06-13
title = "DIVER OSINT CTF writeup"
[taxonomies]
tags = ["CTF"]
+++

# この記事について
この記事は2024/6/8 12:00 から 2024/6/9 12:00までに行われたDIVER OSINT CTFにおいて、私が正解した問題などのWriteupになります。チームのWriteupもありますが、個人用にも残しておこうと思い上げました。

# Welcome / Welcome
>DIVER OSINT CTFへようこそ！
ルールのページからFlagを見つけて入力してください。
正解すると、ほかの問題がアンロックされます！

ルールに書いてあるフラグを入力して終了。
```
Diver24{ganbarou!}
```

# introducion / Dream
>画像に写っているパイプオルガンがある施設の郵便番号を答えなさい。

あまりにも特徴的なパイプオルガンと「夢」という文字だったので、画像検索。
すると大阪府大東市赤井1丁目4番1号にあるポップタウン住道 オペラパークという施設が引っかかるので、ここの郵便番号をフラグとして入力すれば正解しました。

# introduction / serial
>これらの動画の背景に映っている航空機のシリアル番号は何か？ 

動画より、機体にはANAとJA222Aという文字が見えます。
なのでそのまま調べると、シリアル番号が分かります。

# introduction / 246
> 画像が撮影された場所から最も近い交差点名を答えよ。

画像には特徴的な橋が写っており、画像検索から関門橋らしいことが分かります。あとは橋との位置関係が写真と同じような場所をGoogle mapで調べ回ると、「長州藩下関前田台場跡」近くがそれっぽいので、そこから一番近い「前田」が正解の交差点名でした。

# military / osprey1
> 2023年11月29日、アメリカ軍のオスプレイ（V-22）が日本の屋久島沖で墜落した。この機体の番号と、墜落時のコールサインは何か。

適当に記事を検索してみると
> アメリカ空軍の第353特殊作戦航空団所属で横田基地配備のCV-22Bオスプレイ

ということが分かります。
あとは適当にCV-22Bとかオスプレイとかの単語でツイッターを漁ると[ここ](https://x.com/oldconnie/status/1730235904592134469)に答えがありました。
よって機体番号は12-0056、コールサイン「GUNDAM22」が答えです。

# military / osprey2
> 2024年2月15日、ある米軍基地でこの事故に関する追悼式典が実施された。16:46:37ごろ、その式典はどこで実施されていたか。
OpenStreetMapのWay番号で答えよ。

osprey memorial ceremonyとかで調べると[こんなの](https://www.stripes.com/branches/air_force/2024-02-15/osprey-crash-japan-yokota-service-13010379.html)が出てきます。東京都西多摩にある横田基地で行われたようです。記事には
> A half-hour before sunset, approximately 600 people, mostly airmen in uniform, gathered for a brief retreat ceremony on the athletic field outside Yokota’s Samurai Fitness Center.

とあるように、日没の30分前に式典が行われていたそうです。ちなみに2024/2/15の西多摩の日没は17:24であり、その30分前は16:46:37ごろにだいぶ近いので、おそらくここで間違いないと、この時点で思いました。

さらに調べていくと、より詳細なページが[見つかります](https://www.yokota.af.mil/News/Latest-Announcements/Article/3672888/gundam-22-memorial-service/)
> RETREAT CEREMONY
>
> Date: Thursday, Feb. 15
>
> Time: 5 p.m. to 5:10 p.m. (All formation participants to form up by 4:45 p.m.)
>
> Location: Track and Field area, across from the Samurai Fitness Center (Bldg. 689)

これは先程の情報とも矛盾がないため、OSMでこのSamurai Fitness Center上の陸上競技場を調べ、Way番号を得れば正解です。

ちなみに、この時私はOSMに始めて触れたためWayが全然分からず、しまいには陸上競技場の外周のWayを回答にひたすら送っていたりしました。(答えは地物から遊園地というものを選択して、そのWayを見る必要があった)

# military / osprey3
> 墜落した機体は2018年11月15日の夜、ある空港に駐機していたらしい。その地点の標高（フィート）を整数で答えよ。なお、各種データソースの時刻にズレはないと仮定してよい。また、空港に関する情報は最新のものを参照してよい（2018年時点のデータを用いる必要はない）。

osprey1で得た機体番号を検索にかけていくと、[この画像](https://www.jetphotos.com/photo/9144357)に出会います。まさしく2018/11/15の深夜に見えますね。
ページによると、この機体は「ヨハネパウロ2世・クラクフ・バリツェ国際空港」にいたそうです。Wikiなどで見ると、標高は791ftとなっていますが、これは空港の建物の高さを含んでいるため、答えではありません。

画像とGoogle mapを照らし合わせると、「Polska Agencja Żeglugi Powietrznej」が画像中央のオスプレイの真後ろにあり、左側は明るいため空港で、右は格納庫のように見えます。Google mapで見ると、大体「Polska Agencja Żeglugi Powietrznej」を南にした時、オスプレイが北の位置にいるので、「Polska Agencja Żeglugi Powietrznej」から見て北側の滑走路にオスプレイがいたと推測できます。

krakow elevation とかで調べるとこの[資料](https://www.ais.pansa.pl/aip/pliki/EP_AD_2_EPKK_en.pdf)が出てきました。あとはそれっぽい単語を調べると774ftと出てくるのでこれが答えです。

なんですが、なんかまぐれ当たり感が拭えない。この資料本当に正しいのだろうか。
他のwriteupを見るとこのような[資料](https://krakowairport.pl/storage/2021-01/ep-ad-2-epkk-1-1-1-en1-1611834393HArbS.pdf)が出てきて、当該箇所はMILITARY APRON 3という場所で774ftだと分かるのですが、これが一番キレイな回答に思えます。

ちなみに「Polska Agencja Żeglugi Powietrznej」って何...? 管制塔?

# 解けてないけど investigetion_request / mapper
> あなた方は極めて高い調査スキルを持っていると聞いた。我々の身分は明かせなくて申し訳ないのだが、一つ調査依頼を受けてくれないだろうか。
我々はある男を追っている。
情報が見つからず困っていたのだが、彼が撮ってアップロードした写真を見つけた。現地時間でいつ撮影されたのか特定してほしい。

当該画像の場所を見つけたり(岐阜駅前)、写真が取られた時期を頑張って推測したり、Facebookのメタデータが怪しくて一生ドハマりしていました。
答えられなくて本当に悔しい。

どうやらMapillaryに当該画像があり、2023/2/6に撮られたようです。[画像](https://www.mapillary.com/app/?lat=35.412007&lng=136.756698&z=18.507253381463244&focus=photo&pKey=438678415240541)
あとはsun-calcとかで時間出すんですかね...?

# 最後に
OSINTは初体験でしたが、楽しかったのでまたやりたい。
