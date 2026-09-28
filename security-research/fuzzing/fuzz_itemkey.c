/* Fuzz Zabbix item key parser (key[params] quoting logic). */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "zbxsysinfo.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *buf = (char*)malloc(size+1); if(!buf) return 0;
    memcpy(buf,data,size); buf[size]=0;
    AGENT_REQUEST request;
    zbx_init_agent_request(&request);
    zbx_parse_item_key(buf, &request);
    zbx_free_agent_request(&request);
    free(buf);
    return 0;
}
