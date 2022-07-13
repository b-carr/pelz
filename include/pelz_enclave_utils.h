#ifndef _PELZ_ENCLAVE_UTILS_H_
#define _PELZ_ENCLAVE_UTILS_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
  
void* safe_ocall_malloc(size_t size);
void safe_ocall_free(void* ptr, size_t size);


#ifdef __cplusplus
}
#endif


#endif
