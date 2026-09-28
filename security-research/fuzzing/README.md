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

## Result

No memory-safety issue found. Each target sustained millions of ASan
executions without a crash (JSON ~5.5M, item key ~1M, Prometheus ~3.1M,
JSONPath ~4.7M + a 30-min extended run, eval ~4.9M, regexp-sub ~5.1M;
~25M+ executions total). The exercised parsers are robust.

These harnesses are kept for reproducibility and future extended campaigns.
