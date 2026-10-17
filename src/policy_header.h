#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ANDROID_FLAGS 0xc0000000u
struct policy_header { uint32_t version, config; size_t config_offset; };
static inline uint32_t policy_le32(const unsigned char *data) {
    return (uint32_t)data[0]|(uint32_t)data[1]<<8|(uint32_t)data[2]<<16|(uint32_t)data[3]<<24;
}
static inline bool policy_header_read(const unsigned char *data, size_t length, struct policy_header *result) {
    static const char identifier[] = "SE Linux";
    if (!data || !result || length < 8) return false;
    uint32_t idlen=policy_le32(data+4);
    if (policy_le32(data)!=0xf97cff8cu || idlen!=sizeof(identifier)-1 || idlen>length-8) return false;
    if (memcmp(data+8,identifier,idlen) || length-8-idlen<2*sizeof(uint32_t)) return false;
    size_t version_at=8+(size_t)idlen,config_at=version_at+sizeof(uint32_t);
    uint32_t version=policy_le32(data+version_at);
    // policydb binary format versions, not Android or firmware versions.
    // Unknown binary layouts must not be sent back to the kernel by this tool.
    if (version<26 || version>33) return false;
    *result=(struct policy_header){version,policy_le32(data+config_at),config_at};return true;
}
static inline void policy_config_write(unsigned char *data, size_t offset, uint32_t flags) {
    for (unsigned i=0;i<sizeof(flags);++i)data[offset+i]=(unsigned char)(flags>>(8*i));
}
