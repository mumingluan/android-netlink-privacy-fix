#include "../src/policy_header.h"
#include <stdio.h>
#include <stdlib.h>
static void require(bool condition) { if (!condition) { fputs("policy header assertion failed\n",stderr);exit(1); } }
int main(int argc,char **argv) {
    if (argc!=2) return 2;
    FILE *file=fopen(argv[1],"rb");require(file!=NULL);require(!fseek(file,0,SEEK_END));long size=ftell(file);
    require(size>0&&size<=32*1024*1024);rewind(file);unsigned char *data=malloc((size_t)size),*before=malloc((size_t)size);
    require(data&&before);require(fread(data,1,(size_t)size,file)==(size_t)size);fclose(file);memcpy(before,data,(size_t)size);
    struct policy_header header;require(policy_header_read(data,(size_t)size,&header));require((header.config&ANDROID_FLAGS)==ANDROID_FLAGS);
    for (size_t length=0;length<header.config_offset+sizeof(uint32_t);++length)require(!policy_header_read(data,length,&header));
    require(policy_header_read(data,(size_t)size,&header));size_t offset=header.config_offset;
    policy_config_write(data,offset,header.config&~ANDROID_FLAGS);struct policy_header changed;require(policy_header_read(data,(size_t)size,&changed));
    require(changed.config==(header.config&~ANDROID_FLAGS));policy_config_write(data,offset,(changed.config&~ANDROID_FLAGS)|(header.config&ANDROID_FLAGS));
    require(memcmp(data,before,(size_t)size)==0);
    data[0]^=1;require(!policy_header_read(data,(size_t)size,&changed));data[0]^=1;
    policy_config_write(data,4,0xffffffffu);require(!policy_header_read(data,(size_t)size,&changed));memcpy(data,before,(size_t)size);
    policy_config_write(data,offset-4,0xffffffffu);require(!policy_header_read(data,(size_t)size,&changed));
    printf("PASS policydb version=%u derived-config-offset=%zu flags=0x%08x; truncation, overflow, identity, unknown-format and byte-preservation checks\n",header.version,offset,header.config);
    free(data);free(before);return 0;
}
