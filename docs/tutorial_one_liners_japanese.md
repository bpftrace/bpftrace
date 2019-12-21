# bpftrace ワンライナーチュートリアル

12個の簡単なレッスンで Linux の bpftrace を学びましょう．各レッスンはワンライナーです．すぐに試すことができ，一連のワンライナーで bpftrace の要点が分かります．bpftrace の詳細は[リファレンスガイド](reference_guide.md)を参照して下さい．

- 執筆：Brendan Gregg, Netflix (2018)．FreeBSD [DTrace Tutorial](https://wiki.freebsd.org/DTrace/Tutorial)（Brendan Gregg 著）に基づく．
- 原文：[The bpftrace One-Liner Tutorial](https://github.com/iovisor/bpftrace/blob/master/docs/tutorial_one_liners.md)

# レッスン 1. プローブの表示

```
bpftrace -l 'tracepoint:syscalls:sys_enter_*'
```

"bpftrace -l" は全てのプローブを表示します．後ろに検索語を付けることができます．

- プローブはイベントデータを捕捉するための計装点です．
- 検索語にはワイルドカード／グロブ（`*`及び`?`）が使用できます．
- 完全な正規表現を利用したい場合は "bpftrace -l" の出力を grep(1) にパイプできます．

# レッスン 2. Hello World

```
# bpftrace -e 'BEGIN { printf("hello world\n"); }'
Attaching 1 probe...
hello world
^C
```

"hello world" を表示します．Ctrl-Cで実行を終了します．

- `BEGIN`は特別なプローブで，プログラムの開始時にイベントが発生します（awk の BEGIN と同様です）．変数の初期化やヘッダの出力に利用できます．
- { } の中でプローブに関連付けるアクションを定義します．この例ではイベントが発生したときに printf() を実行します．

# レッスン 3. ファイルのオープン

```
# bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("%s %s\n", comm, str(args->filename)); }'
Attaching 1 probe...
snmp-pass /proc/cpuinfo
snmp-pass /proc/stat
snmpd /proc/net/dev
snmpd /proc/net/if_inet6
^C
```

ファイルのオープンの発生をトレースし，そのときのプロセス名とファイルのパス名を表示します．

- `tracepoint:syscalls:sys_enter_openat` は tracepoint プローブ（カーネルの静的トレーシング）です．これにより `openat()` システムコール呼び出し時にイベントが発生します．Tracepoint の API は安定性が保証されているため，kprobe（カーネルの動的トレーシング，レッスン6で紹介）よりも利用が推奨されます．なお，最近の Linux（カーネル2.26以上）では `open` 関数は常に `openat` システムコールを呼びます．
- `comm` はビルトイン変数の一つで，現在のプロセス名を保持します．同様のビルトイン変数に pid や tid があります．
- `args` は対象の tracepoint の全ての引数を含む構造体へのポインタです．この構造体は tracepoint の情報に基づいて bpftrace が自動で生成します．構造体のメンバの情報は `bpftrace -vl tracepoint:syscalls:sys_enter_openat` で調べることができます．
- `args->filename` は `args` 構造体を参照してメンバ変数 `filename` の値を取得します．
- `str()` はポインタを文字列に変換します．（訳注：bpftrace はポインタと文字列を別々のものとして扱います．printf("%s") の引数には文字列を与える必要があります． ）




# レッスン 4. プロセスごとのシステムコール呼び出し回数

```
bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'
Attaching 1 probe...
^C

@[bpftrace]: 6
@[systemd]: 24
@[snmp-pass]: 96
@[sshd]: 125
```

プロセスごとにシステムコール呼び出しの回数を計数します．集計結果は Ctrl-C でプログラムを終了した際に表示されます．

- @: これはマップと呼ばれる特殊な変数です．マップはさまざまな方法でデータの格納や集計ができます．@ の後ろに変数名（例えば "@num"）を付けることもできます．これにより可読性や識別性を向上できます．
- []: マップの後ろに大括弧をつけると，連想配列のようにキーが指定できます．これは省略可能です．
- count(): これはマップに対する関数の一つで，呼び出された回数を計数します．今回の場合マップには comm をキーとして count() の値が保存されます．結果としてプロセスごとのシステムコール呼び出しの回数が計数されます．

マップに格納された値は bpftrace が終了したとき（Ctrl-Cを押したときなど）に自動で表示されます．

# レッスン 5. read() のバイト数の分布

```
# bpftrace -e 'tracepoint:syscalls:sys_exit_read /pid == 18644/ { @bytes = hist(args->ret); }'
Attaching 1 probe...
^C

@bytes:
[0, 1]                12 |@@@@@@@@@@@@@@@@@@@@                                |
[2, 4)                18 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                     |
[4, 8)                 0 |                                                    |
[8, 16)                0 |                                                    |
[16, 32)               0 |                                                    |
[32, 64)              30 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[64, 128)             19 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                    |
[128, 256)             1 |@
```

PID 18644 のプロセスによるカーネル関数 sys_read() の戻り値をヒストグラムにまとめます．

- /.../: これはフィルタ（述語ともいう）です．アクションはこのフィルタ式が真のときのみ実行されます．今回の場合はPIDが18644のときにアクションが実行されます．フィルタ内ではブール値のオペレーター（"&&", "||"）が利用できます．
- ret: 関数の戻り値を意味します． sys_read() の場合，戻り値は -1 (エラー）か，read に成功したバイト数です．
- @: 前のレッスンと同様にマップです．今回はキー（大括弧）が無く，"bytes" という名前がついています．この名前は最後の結果の出力のときに表示されます．
- hist(): 底2の対数スケールのヒストグラムとして値を集計するマップ関数です．出力の行の先頭は値のインターバルを示します．例えば，`[128, 256)` は値が128以上256未満であることを意味します．その横は発生回数及び，ASCII文字による発生回数のヒストグラムです．ヒストグラムはの分布の多峰性の調査に活用できます．
- 他のマップ関数として lhist()（線形スケールのヒストグラム），sum()，avg()，min() そして max() があります．

# レッスン 6. カーネル動的トレーシングによる read() のバイト数の集計

```
# bpftrace -e 'kretprobe:vfs_read { @bytes = lhist(retval, 0, 2000, 200); }'
Attaching 1 probe...
^C

@bytes:
(...,0]                0 |                                                    |
[0, 200)              66 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[200, 400)             2 |@                                                   |
[400, 600)             3 |@@                                                  |
[600, 800)             0 |                                                    |
[800, 1000)            5 |@@@                                                 |
[1000, 1200)           0 |                                                    |
[1200, 1400)           0 |                                                    |
[1400, 1600)           0 |                                                    |
[1600, 1800)           0 |                                                    |
[1800, 2000)           0 |                                                    |
[2000,...)            39 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                      |
```

read() のバイト数を線形スケールのヒストグラムとして集計します．トレースにはカーネルの動的トレーシングを利用します．

- `kretprobe:vfs_read` は kretprobe プローブ（関数の戻りに対するカーネル動的トレーシング）を `vfs_read()` カーネル関数に設定します．関数の実行開始時にイベントを発生させる kprobe プローブ（次のレッスンで紹介）もあります．これらは強力なプローブタイプで，数万の異なるカーネル関数をトレースすることができます．しかしこれらは「不安定」なプローブです．なぜなら，カーネル関数の名称，引数，戻り値，そして役割はカーネルバージョンごとに変わる可能性があるためです．kprobe/kretprobe が異なるカーネルで動作する保証はありません．また，生のカーネル関数をトレースすることになるため，プローブや引数，戻り値の意味を理解するためにはカーネルのソースコードを参照する必要があるでしょう．
- lhist(): 線形スケールのヒストグラムを作成します．引数は 値，最小値，最大値，ステップ です．最初の引数（`retval`）は vfs_read() の戻り値で，これは読み出したバイト数です．

# レッスン 7. read() の実行時間の測定

```
# bpftrace -e 'kprobe:vfs_read { @start[tid] = nsecs; } kretprobe:vfs_read /@start[tid]/ { @ns[comm] = hist(nsecs - @start[tid]); delete(@start[tid]); }'
Attaching 2 probes...

[...]
@ns[snmp-pass]:
[0, 1]                 0 |                                                    |
[2, 4)                 0 |                                                    |
[4, 8)                 0 |                                                    |
[8, 16)                0 |                                                    |
[16, 32)               0 |                                                    |
[32, 64)               0 |                                                    |
[64, 128)              0 |                                                    |
[128, 256)             0 |                                                    |
[256, 512)            27 |@@@@@@@@@                                           |
[512, 1k)            125 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@       |
[1k, 2k)              22 |@@@@@@@                                             |
[2k, 4k)               1 |                                                    |
[4k, 8k)              10 |@@@                                                 |
[8k, 16k)              1 |                                                    |
[16k, 32k)             3 |@                                                   |
[32k, 64k)           144 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[64k, 128k)            7 |@@                                                  |
[128k, 256k)          28 |@@@@@@@@@@                                          |
[256k, 512k)           2 |                                                    |
[512k, 1M)             3 |@                                                   |
[1M, 2M)               1 |                                                    |
```

read() の実行時間をナノ秒単位で計測し，プロセスごとにヒストグラムで集計します．

- @start[tid]: これはマップのキーにスレッドIDを利用しています．read は同時に複数実行される可能性があります．それぞれの開始時刻をどう保存すれば良いでしょうか？それぞれの read に対して一意の識別子が生成できれば，それをキーとして利用できます．あるカーネルスレッドは一度に一つのシステムコールしか実行できないため，スレッドIDを一意の識別子として利用できます．
- nsecs: マシン起動からのナノ秒を意味します．これは高精度のタイムスタンプカウンターの値で，イベント時刻の測定に利用できます．
- /@start[tid]/: このフィルタは開始時間が記録されているかをチェックします．このフィルタが無い場合，このプログラムはある read の開始後に実行され，その read の終了のイベントのみを捕捉する可能性があります．この場合，結果として 現在時刻 - 開始時間ではなく，現在時刻 - 0 を計算することになります．（訳注：存在しないキーに対するマップアクセスは0を返します）

- delete(@start[tid]]): 変数を解放します．（訳注：delete をしたマップの値は，プログラム終了時に表示されません．）

# レッスン 8. プロセスレベルのイベントの計数

```
# bpftrace -e 'tracepoint:sched:sched* { @[probe] = count(); } interval:s:5 { exit(); }'
Attaching 25 probes...
@[tracepoint:sched:sched_wakeup_new]: 1
@[tracepoint:sched:sched_process_fork]: 1
@[tracepoint:sched:sched_process_exec]: 1
@[tracepoint:sched:sched_process_exit]: 1
@[tracepoint:sched:sched_process_free]: 2
@[tracepoint:sched:sched_process_wait]: 7
@[tracepoint:sched:sched_wake_idle_without_ipi]: 53
@[tracepoint:sched:sched_stat_runtime]: 212
@[tracepoint:sched:sched_wakeup]: 253
@[tracepoint:sched:sched_waking]: 253
@[tracepoint:sched:sched_switch]: 510
```

5秒間プロセスレベルのイベントを計数し，サマリを出力します．

- sched: tracepoint の `sched` プローブカテゴリには，fork や exec，コンテキストスイッチなどの高位のスケジューラとプロセスに関するイベントがあります．
- probe: プローブの正式名を保持するビルトイン変数です．（訳注：`tracepoint:sched:sched*` はマッチした全てのプローブにアクションを紐付けます．probe を利用して，実際のプローブの名称をプログラム内から参照できます．）
- interval:s:5: ある一つのCPU上で5秒間に一度実行されるプローブです．スクリプトによるインターバルあるいはタイムアウトイベントの作成に利用できます．
- exit(): bpftrace を終了します．

# レッスン 9. CPU上のカーネルスタックのプロファイリング

```
# bpftrace -e 'profile:hz:99 { @[kstack] = count(); }'
Attaching 1 probe...
^C

[...]
@[
filemap_map_pages+181
__handle_mm_fault+2905
handle_mm_fault+250
__do_page_fault+599
async_page_fault+69
]: 12
[...]
@[
cpuidle_enter_state+164
do_idle+390
cpu_startup_entry+111
start_secondary+423
secondary_startup_64+165
]: 22122
```

99ヘルツでカーネルスタックのプロファイリングをおこない，その出現頻度を出力します．

- profile:hz:99: 全てのCPU上で99ヘルツでイベントが発生します．何故100や1000ではなく99でしょうか？プロファイル頻度は実行を俯瞰的にも局所的にも捉えることができるほど十分かつ，パフォーマンスを乱さない程度である必要があります．100ヘルツは十分な頻度ですが，100の場合他のタイマによるロック間隔と同じ頻度でサンプリングされる可能性があります．そこで99を利用します．
- kstack: カーネルのスタックトレースを返します．これはマップのキーとして利用可能で，count() と合わせて頻度の計数ができます．この出力は flame graph として可視化するのに最適です．また，ユーザレベルのスタックトレース用に `ustack` があります．

# Lesson 10. スケジューラのトレーシング

```
# bpftrace -e 'tracepoint:sched:sched_switch { @[kstack] = count(); }'
^C
[...]

@[
__schedule+697
__schedule+697
schedule+50
schedule_timeout+365
xfsaild+274
kthread+248
ret_from_fork+53
]: 73
@[
__schedule+697
__schedule+697
schedule_idle+40
do_idle+356
cpu_startup_entry+111
start_secondary+423
secondary_startup_64+165
]: 305
```

コンテキストスイッチ（off-CPU）イベントに繋がるスタックトレースを計数します．上記は出力の最後の二つのみを表示しています．

- sched: tracepoint の sched カテゴリにはカーネルのスケジューライベントに関する tracepoint が複数あります．sched_switch, sched_wakeup, sched_migrate_task など．
- sched_switch: このプローブはスレッドが CPU から離れる時に発生します．これは I/O 待ちやタイマ，ページング/スワッピング，ロックなどのブロッキングイベントのときに起こります．
- kstack: カーネルのスタックトレースです．
- sched_switch はスレッドコンテキスト内で発生します．そのためスタックはCPUから離れるスレッドのものです．他のプローブタイプを利用するときはコンテキストに注意を払う必要があります．comm や pid, kstack などはプローブの対象を参照していない場合があります．

# Lesson 11. ブロック I/O のトレーシング

```
# bpftrace -e 'tracepoint:block:block_rq_issue { @ = hist(args->bytes); }'
Attaching 1 probe...
^C

@:
[0, 1]                 1 |@@                                                  |
[2, 4)                 0 |                                                    |
[4, 8)                 0 |                                                    |
[8, 16)                0 |                                                    |
[16, 32)               0 |                                                    |
[32, 64)               0 |                                                    |
[64, 128)              0 |                                                    |
[128, 256)             0 |                                                    |
[256, 512)             0 |                                                    |
[512, 1K)              0 |                                                    |
[1K, 2K)               0 |                                                    |
[2K, 4K)               0 |                                                    |
[4K, 8K)              24 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[8K, 16K)              2 |@@@@                                                |
[16K, 32K)             6 |@@@@@@@@@@@@@                                       |
[32K, 64K)             5 |@@@@@@@@@@                                          |
[64K, 128K)            0 |                                                    |
[128K, 256K)           1 |@@                                                  |

```

ブロックI/O要求をバイト単位でヒストグラムとして表示します．

- tracepoint:block: tracepoint の block カテゴリは様々なブロックI/O（ストレージ）イベントをトレースします．
- block_rq_issue: デバイスに I/O が発行された時にイベントが発生します．
- args->bytes: Tracepoint の block_rq_issue の引数のメンバ変数で，ブロックI/Oのサイズをバイト単位で表します．

このプローブのコンテキストは重要です．このイベントはデバイスに対して I/O が発行されたときに発生します．これはよくプロセスコンテキストで発生し，その場合ビルトイン変数，例えば comm はそのときのプロセス名を意味しますが，このイベントはカーネルコンテキスト（例えば readahead）でも発生します．この場合 pid や comm は予期しないものになるでしょう．

# Lesson 12. カーネル構造体のトレーシング

```
# cat path.bt
#include <linux/path.h>
#include <linux/dcache.h>

kprobe:vfs_open
{
	printf("open path: %s\n", str(((path *)arg0)->dentry->d_name.name));
}

# bpftrace path.bt
Attaching 1 probe...
open path: dev
open path: if_inet6
open path: retrans_time_ms
[...]
```

カーネルの動的トレーシングで vfs_open() をトレーシングします．この関数は (struct path *) を第一引数に取ります．

- kprobe: 以前説明したように，これはカーネルの動的トレーシングをおこなうプローブタイプで，カーネル関数の開始をトレースします（関数からの戻りのトレースには kretprobe を利用します）．
- `arg0` はビルトイン変数で，プローブの最初の引数を意味します．これはプローブタイプごとに意味が異なり，`kprobe` の場合は関数の最初の引数を意味します．他の引数には arg1, ..., argN でアクセスできます．
- `((path *)arg0)->dentry->d_name.name`: `arg0` を `path *` にキャストしてから dentry や後続のメンバ変数を参照します．
- #include: path と dentry の構造体定義のために必要なファイルをインクルードします．

カーネル構造体のサポートは bcc と同様にカーネルヘッダを利用します．したがって多くの構造体が利用可能ですが，全てではありません．場合によっては手動で構造体を定義する必要があります．例えば [dcsnoop tool](../tools/dcsnoop.bt) では nameidata 構造体の一部を手動で定義しています．これはこの構造体がヘッダ内で定義されていないためです．LinuxカーネルのBTFデータがある場合，全ての構造体が利用可能です．

ここまでで bpftrace の多くを理解し，強力なワンライナーを作成・利用することができます．bpftrace のその他の機能については [リファレンスガイド](reference_guide.md) を参照して下さい．

