# Zabbix 8.0 — coverage-guided fuzzing harnesses (libFuzzer + ASan)

Security-research harnesses used to fuzz unauthenticated / attacker-reachable
C parsers in Zabbix 8.0. Each target is a libFuzzer entry point
(`LLVMFuzzerTestOneInput`) linked against the instrumented Zabbix static libs.

## Build

```sh
# from the repo root
./bootstrap.sh
./configure --enable-agent --disable-server --disable-proxy \
    CC=clang CFLAGS="-g -O1 -fsanitize=address,fuzzer-no-link -fno-omit-frame-pointer"
(cd src/libs && make -j4)          # build instrumented libs (+ zbxeval, zbxprometheus, zbxxml)

LIBS=$(find src/libs -name '*.a' | tr '\n' ' ')
clang -g -O1 -fsanitize=address,fuzzer -I include -I include/common -I. \
    security-research/fuzzing/fuzz_json.c \
    -Wl,--start-group $LIBS -Wl,--end-group -lpcre2-8 -lm -lpthread -lresolv \
    -o fuzz_json
```

## Targets

| Harness              | Function under test        | Attacker-reachable via |
|----------------------|----------------------------|------------------------|
| `fuzz_json.c`        | `zbx_json_open` + walk     | trapper / active-checks / sender protocol (unauth) |
| `fuzz_itemkey.c`     | `zbx_parse_item_key`       | item key `key[params]` quoting |
| `fuzz_prometheus.c`  | `zbx_prometheus_to_json`   | Prometheus metric data from a monitored target |
| `fuzz_jsonpath.c`    | `zbx_jsonpath_compile` / `zbx_jsonpath_query` | JSONPath preprocessing on item values |
| `fuzz_eval.c`        | `zbx_eval_parse_expression`| trigger / calculated expressions |
| `fuzz_regexpsub.c`   | `zbx_regexp_sub`           | regex-substitution preprocessing on item values |
| `fuzz_csv_to_json.c` | `item_preproc_csv_to_json` | "CSV to JSON" preprocessing on item values from a monitored target |

`fuzz_csv_to_json.c` links a stand-alone ASan build of
`src/libs/zbxpreproc/item_preproc.c` (that library is not built by the
`--disable-server --disable-proxy` config above):

```sh
clang -g -O1 -fsanitize=address,fuzzer-no-link -fno-omit-frame-pointer -c \
    -I include -I include/common -I src/libs/zbxpreproc -I. \
    src/libs/zbxpreproc/item_preproc.c -o item_preproc.o
clang -g -O1 -fsanitize=address,fuzzer -I include -I include/common -I. \
    security-research/fuzzing/fuzz_csv_to_json.c item_preproc.o \
    -Wl,--start-group $(find src/libs -name '*.a'|tr '\n' ' ') -Wl,--end-group \
    -lpcre2-8 -lm -lpthread -lresolv -o fuzz_csv
```

## Result

The JSON, item-key, Prometheus, JSONPath, eval and regexp-sub parsers sustained
millions of ASan executions without a crash (JSON ~5.5M, item key ~1M,
Prometheus ~3.1M, JSONPath ~4.7M + a 30-min extended run, eval ~4.9M,
regexp-sub ~5.1M; ~25M+ executions total) — robust.

`fuzz_csv_to_json.c` found a **1-byte heap out-of-bounds read** in the "sep="
line handling of `item_preproc_csv_to_json()` (`item_preproc.c`): a value of the
form `sep=X\r` (single-char separator declaration ended by a lone CR, no LF)
made the code advance the parse cursor by 2 assuming CRLF, overshooting the NUL
terminator by one byte. The fix only advances by 2 when a `\n` actually follows.
After the fix the same harness runs 3.9M executions clean.

These harnesses are kept for reproducibility and future extended campaigns.
