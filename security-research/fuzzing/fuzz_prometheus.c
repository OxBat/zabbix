/* Fuzz Zabbix Prometheus parser (attacker-controlled metric data from a monitored target). */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "zbxprometheus.h"
#include "zbxstr.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *buf = (char*)malloc(size+1); if(!buf) return 0;
    memcpy(buf,data,size); buf[size]=0;
    char *value=NULL, *error=NULL;
    if (SUCCEED == zbx_prometheus_to_json(buf, "", &value, &error))
        zbx_free(value);
    zbx_free(error);
    free(buf);
    return 0;
}
