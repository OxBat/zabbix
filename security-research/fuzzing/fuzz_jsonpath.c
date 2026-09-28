/* Fuzz Zabbix JSONPath compiler + query engine. Input: <path>\n<json-data>. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "zbxjson.h"
#include "zbxstr.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const uint8_t *nl = memchr(data, '\n', size);
    size_t plen = nl ? (size_t)(nl - data) : size;
    size_t dlen = nl ? size - plen - 1 : 0;
    if (plen > 4096) plen = 4096;
    char *path = (char*)malloc(plen+1); if(!path) return 0;
    memcpy(path, data, plen); path[plen]=0;
    char *json = (char*)malloc(dlen+1); if(!json){free(path);return 0;}
    if (dlen) memcpy(json, data+plen+1, dlen); json[dlen]=0;

    /* compiler path */
    zbx_jsonpath_t jp_path;
    if (SUCCEED == zbx_jsonpath_compile(path, &jp_path))
        zbx_jsonpath_clear(&jp_path);

    /* query engine on attacker json data */
    struct zbx_json_parse jp;
    if (SUCCEED == zbx_json_open(json, &jp)) {
        char *out = NULL;
        if (SUCCEED == zbx_jsonpath_query(&jp, path, &out))
            zbx_free(out);
    }
    free(path); free(json);
    return 0;
}
