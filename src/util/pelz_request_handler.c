#include "charbuf.h"
#include "pelz_request_handler.h"
#include "common_table.h"
#include "aes_keywrap_3394nopad.h"
#include "aes_gcm.h"

#include "sgx_trts.h"
#include ENCLAVE_HEADER_TRUSTED

RequestResponseStatus pelz_request_handler(RequestType request_type, charbuf key_id, charbuf data, charbuf data_block, charbuf cipher, charbuf * output)
{
  charbuf outData;
  int index;

  if (table_lookup(KEY, key_id, &index))
  {
    return KEK_NOT_LOADED;
  }

  //Encrypt or Decrypt data per request_type
  switch (request_type)
  {
  case REQ_ENC:
    if ((key_table.entries[index].value.key.len < 16 || key_table.entries[index].value.key.len % 8 != 0) || (data.len < 16
        || data.len % 8 != 0))
    {
      return KEY_OR_DATA_ERROR;
    }
    if (aes_keywrap_3394nopad_encrypt(key_table.entries[index].value.key.chars, key_table.entries[index].value.key.len,
        data.chars, data.len, &outData.chars, &outData.len))
    {
      return ENCRYPT_ERROR;
    }
    break;
  case REQ_DEC:
    if ((key_table.entries[index].value.key.len < 16 || key_table.entries[index].value.key.len % 8 != 0) || (data.len < 24
        || data.len % 8 != 0))
    {
      return KEY_OR_DATA_ERROR;
    }
    if (aes_keywrap_3394nopad_decrypt(key_table.entries[index].value.key.chars, key_table.entries[index].value.key.len,
        data.chars, data.len, &outData.chars, &outData.len))
    {
      return DECRYPT_ERROR;
    }
    break;
  case REQ_DATA_DEC:
    if ((key_table.entries[index].value.key.len < 16 || key_table.entries[index].value.key.len % 8 != 0) || (data.len < 24
        || data.len % 8 != 0))
    {
      return KEY_OR_DATA_ERROR;
    }
    charbuf out_key;
    if (aes_keywrap_3394nopad_decrypt(key_table.entries[index].value.key.chars, key_table.entries[index].value.key.len,
        data.chars, data.len, &out_key.chars, &out_key.len))
    {
      return DECRYPT_ERROR;
    }
    if (aes_gcm_decrypt(out_key.chars, out_key.len, data_block.chars, data_block.len, &outData.chars, &outData.len))
    {
      return DECRYPT_ERROR;
    }
  default:
    return REQUEST_TYPE_ERROR;

  }
  output->len = outData.len;
  ocall_malloc(output->len, &output->chars);
  memcpy(output->chars, outData.chars, output->len);
  return REQUEST_OK;
}
