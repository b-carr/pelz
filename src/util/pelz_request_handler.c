#include "charbuf.h"
#include "pelz_request_handler.h"
#include "common_table.h"
#include "cipher/cipher.h"

#include "sgx_trts.h"
#include ENCLAVE_HEADER_TRUSTED

RequestResponseStatus pelz_request_handler(RequestType request_type, charbuf key_id, charbuf data, charbuf cipher, charbuf tag, charbuf iv, charbuf * output)
{
  charbuf outData;
  int index;

  //unsigned char* cipher_string = null_terminated_string_from_charbuf(cipher);
  char* cipher_string = "AES/KeyWrap/RFC3394NoPadding/256";
  cipher_t cipher_struct = kmyth_get_cipher_t_from_string((char*)cipher_string);
	 //  free(cipher_string);

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
    if(cipher_struct.encrypt_fn(key_table.entries[index].value.key.chars, key_table.entries[index].value.key.len, data.chars, data.len, &outData.chars, &outData.len))
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
    // Depending on the cipher we may have to do some data formatting.
    size_t total_cipher_len = iv.len + tag.len + data.len;
    unsigned char* ciphertext = malloc(total_cipher_len);
    if(iv.len > 0)
    {
      memcpy(ciphertext, iv.chars, iv.len);
    }
    memcpy(ciphertext+iv.len, data.chars, data.len);
    if(tag.len > 0)
    {
      memcpy(ciphertext+iv.len+data.len, tag.chars, tag.len);
    }
    if (cipher_struct.decrypt_fn(key_table.entries[index].value.key.chars, key_table.entries[index].value.key.len, ciphertext, total_cipher_len, &outData.chars, &outData.len))
    {
      free(ciphertext);
      return DECRYPT_ERROR;
    }
    free(ciphertext);
    break;
  default:
    return REQUEST_TYPE_ERROR;

  }
  output->len = outData.len;
  ocall_malloc(output->len, &output->chars);
  memcpy(output->chars, outData.chars, output->len);
  return REQUEST_OK;
}
