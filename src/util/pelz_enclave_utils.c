#include <stddef.h>

#include "pelz_enclave_utils.h"
#include "sgx_trts.h"
#include ENCLAVE_HEADER_TRUSTED

void* safe_ocall_malloc(size_t size){
  void* buf = NULL;
  ocall_malloc(size, (unsigned char**)&buf);
  if(buf == NULL || !sgx_is_outside_enclave(buf, size))
  {
    buf = NULL;
  }
  return buf;
}


void safe_ocall_free(void* ptr, size_t size)
{
  if(sgx_is_outside_enclave(ptr, size))
  {
    ocall_free(ptr, size);
  }
}
