#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "zbxregexp.h"
#include "zbxstr.h"
static char* field(const char**p,const char*end){
    const char*s=*p; const char*nl=memchr(s,'\n',end-s); const char*e=nl?nl:end;
    char*r=(char*)malloc(e-s+1); memcpy(r,s,e-s); r[e-s]=0; *p=nl?nl+1:end; return r;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    const char*p=(const char*)data,*end=p+size;
    char*pattern=field(&p,end); char*tmpl=field(&p,end); char*str=field(&p,end);
    if(strlen(pattern)<200){
        char*out=NULL;
        if(SUCCEED==zbx_regexp_sub(str,pattern,tmpl,&out)) zbx_free(out);
    }
    free(pattern);free(tmpl);free(str); return 0;
}
