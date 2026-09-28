#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "zbxeval.h"
#include "zbxstr.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *buf=(char*)malloc(size+1); if(!buf)return 0; memcpy(buf,data,size); buf[size]=0;
    zbx_eval_context_t ctx; char *error=NULL;
    if (SUCCEED == zbx_eval_parse_expression(&ctx, buf, ZBX_EVAL_PARSE_CALC_EXPRESSION, &error))
        zbx_eval_clear(&ctx);
    zbx_free(error); free(buf); return 0;
}
