/*
 * pelz_json_parser_suite.c
 */

#include "pelz_json_parser_test_suite.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <cjson/cJSON.h>

#include <charbuf.h>
#include <pelz_log.h>

// Adds all key table tests to main test runner.
int pelz_json_parser_suite_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite, "Test Decoding of JSON formatted Request", test_request_decoder))
  {
    return (1);
  }
  if (NULL == CU_add_test(suite, "Test Encoding of JSON formatted Response Message", test_message_encoder))
  {
    return (1);
  }
  if (NULL == CU_add_test(suite, "Test Encoding of JSON formatted Error Message", test_error_message_encoder))
  {
    return (1);
  }
  return (0);
}

void test_request_decoder(void)
{
  charbuf request;
  char *tmp;
  RequestType request_type;
  charbuf key_id;
  charbuf json_data;
  charbuf request_sig;
  charbuf requestor_cert;
  charbuf cipher;
  charbuf iv;
  charbuf tag;
  cJSON *json_enc;
  cJSON *json_dec;
  cJSON *json_enc_signed;
  cJSON *json_dec_signed;

  const char *invalid_request[4] = {
    "{\"key_id_len\": 28, \"key_id\": \"file:/test/testkeys/key2.txt\"}",
    "{\"request_type\": \"one\"}", "{\"request_type\": 0}", "{\"request_type\": 7}"
  };
  const char *json_key_id[6] = {
    "file:/test/key1.txt", "file:/test/key2.txt", "file:/test/key3.txt",
    "file:/test/key4.txt", "file:/test/key5.txt", "file:/test/key6.txt"
  };
  unsigned int json_key_id_len = 19;

  const char *enc_data[6] = {
    "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY=\n", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=\n",
    "QUJDREVGR0hJSktMTU5PUFFSU1RVVldY\n", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4\n",
    "QUJDREVGR0hJSktMTU5PUA==\n", "YWJjZGVmZ2hpamtsbW5vcA==\n"
  };
  unsigned int enc_data_len[6] = {
    45, 45, 33, 33, 25, 25
  };

  pelz_log(LOG_DEBUG, "Start Request Decoder Test");
  //Test Invalid Requests with bad request_types
  for (int i = 0; i < 4; i++)
  {
    request = new_charbuf(strlen(invalid_request[i]));
    memcpy(request.chars, invalid_request[i], request.len);
    CU_ASSERT(request_decoder(request, &request_type, &key_id, &json_data, &cipher, &iv, &tag, &request_sig, &requestor_cert) == 1);
    free_charbuf(&request);
    request_type = REQ_UNK;
  }
  
  //Building of the json request and most combinations
  json_enc = cJSON_CreateObject();
  json_dec = cJSON_CreateObject();
  json_enc_signed = cJSON_CreateObject();
  json_dec_signed = cJSON_CreateObject();
  cJSON_AddItemToObject(json_enc, "request_type", cJSON_CreateNumber(1));
  cJSON_AddItemToObject(json_dec, "request_type", cJSON_CreateNumber(2));
  cJSON_AddItemToObject(json_enc_signed, "request_type", cJSON_CreateNumber(3));
  cJSON_AddItemToObject(json_dec_signed, "request_type", cJSON_CreateNumber(4));

  tmp = cJSON_PrintUnformatted(json_enc);
  request = new_charbuf(strlen(tmp));
  memcpy(request.chars, tmp, request.len);
  free(tmp);
  CU_ASSERT(request_decoder(request, &request_type, &key_id, &json_data, &cipher, &iv, &tag, &request_sig, &requestor_cert) == 1);
  free_charbuf(&json_data);
  free_charbuf(&request);
  request_type = REQ_UNK;
  
  tmp = cJSON_PrintUnformatted(json_dec);
  request = new_charbuf(strlen(tmp));
  memcpy(request.chars, tmp, request.len);
  free(tmp);
  CU_ASSERT(request_decoder(request, &request_type, &key_id, &json_data, &cipher, &iv, &tag, &request_sig, &requestor_cert) == 1);
  free_charbuf(&json_data);
  free_charbuf(&request);
  request_type = REQ_UNK;
  
  for (int i = 0; i < 6; i++)
  {
    cJSON_AddItemToObject(json_enc, "key_id", cJSON_CreateString(json_key_id[i]));
    cJSON_AddItemToObject(json_enc, "key_id_len", cJSON_CreateNumber(json_key_id_len));
    cJSON_AddItemToObject(json_enc, "data", cJSON_CreateString(enc_data[i]));
    cJSON_AddItemToObject(json_enc, "data_len", cJSON_CreateNumber(enc_data_len[i]));
    cJSON_AddItemToObject(json_enc, "cipher", cJSON_CreateString("AES256-GCM"));

    //Creating the request charbuf for the JSON then testing request_decoder for encryption
    tmp = cJSON_PrintUnformatted(json_enc);
    request = new_charbuf(strlen(tmp));
    memcpy(request.chars, tmp, request.len);
    free(tmp);
    CU_ASSERT(request_decoder(request, &request_type, &key_id, &json_data, &cipher, &iv, &tag, &request_sig, &requestor_cert) == 0);
    CU_ASSERT(request_type == REQ_ENC);
    CU_ASSERT(key_id.len == json_key_id_len);
    CU_ASSERT(memcmp(key_id.chars, json_key_id[i], key_id.len) == 0);
    CU_ASSERT(json_data.len == enc_data_len[i]);
    CU_ASSERT(memcmp(json_data.chars, enc_data[i], json_data.len) == 0);
    free_charbuf(&request);
    request_type = REQ_UNK;
    free_charbuf(&key_id);
    free_charbuf(&json_data);

    //Free the cJSON Objects to allow the addition of the next Object per the loop
    cJSON_DeleteItemFromObject(json_enc, "data");
    cJSON_DeleteItemFromObject(json_enc, "data_len");
    cJSON_DeleteItemFromObject(json_enc, "key_id");
    cJSON_DeleteItemFromObject(json_enc, "key_id_len");
    cJSON_DeleteItemFromObject(json_dec, "key_id");
    cJSON_DeleteItemFromObject(json_dec, "key_id_len");
    cJSON_DeleteItemFromObject(json_enc, "cipher");
  }
 
  cJSON_Delete(json_enc);
}

void test_message_encoder(void)
{
  charbuf key_id;
  charbuf data;
  charbuf request_sig;
  charbuf requestor_cert;
  charbuf message;
  const char *test[5] = { "file:/test/key1.txt", "test/key1.txt", "file", "anything", "" };
  const char *valid_enc_message[5] =
    { "{\"key_id\":\"file:/test/key1.txt\",\"key_id_len\":19,\"data\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"data_len\":57}",
    "{\"key_id\":\"test/key1.txt\",\"key_id_len\":13,\"data\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"data_len\":57}",
    "{\"key_id\":\"file\",\"key_id_len\":4,\"data\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"data_len\":57}",
    "{\"key_id\":\"anything\",\"key_id_len\":8,\"data\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"data_len\":57}",
    "{\"key_id\":\"\",\"key_id_len\":0,\"data\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"data_len\":57}"
  };
  const char *valid_dec_message[5] =
    { "{\"key_id\":\"file:/test/key1.txt\",\"key_id_len\":19,\"data\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"data_len\":57}",
    "{\"key_id\":\"test/key1.txt\",\"key_id_len\":13,\"data\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"data_len\":57}",
    "{\"key_id\":\"file\",\"key_id_len\":4,\"data\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"data_len\":57}",
    "{\"key_id\":\"anything\",\"key_id_len\":8,\"data\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"data_len\":57}",
    "{\"key_id\":\"\",\"key_id_len\":0,\"data\":\"SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\\n\",\"data_len\":57}"
  };
  
  //Start Message Encoder Test
  pelz_log(LOG_DEBUG, "Start Message Encoder Test");

  data = new_charbuf(57);
  memcpy(data.chars, "SwqqSZbNtN2SOfKGtE2jfklrcARSCZE9Tdl93pggkIsRkY3MrjevmQ==\n", data.len);
  key_id = new_charbuf(strlen(test[0]));
  memcpy(key_id.chars, test[0], key_id.len);

  request_sig = new_charbuf(11);
  memcpy(request_sig.chars, "HelloWorld\n", request_sig.len);
  requestor_cert = new_charbuf(11);
  memcpy(requestor_cert.chars, "PelzProject\n", requestor_cert.len);

  // Testing unknown request
  CU_ASSERT(message_encoder(REQ_UNK, key_id, data, &message) == 1);

  // Testing a request without signatures/certificates (This will be removed after they are required)
  free_charbuf(&request_sig);
  free_charbuf(&requestor_cert);
  CU_ASSERT(message_encoder(REQ_ENC, key_id, data, &message) == 0);
  free_charbuf(&key_id);
  // Restore values
  request_sig = new_charbuf(11);
  memcpy(request_sig.chars, "HelloWorld\n", request_sig.len);
  requestor_cert = new_charbuf(11);
  memcpy(requestor_cert.chars, "PelzProject\n", requestor_cert.len);

  for (int i = 0; i < 5; i++)
  {
    key_id = new_charbuf(strlen(test[i]));
    memcpy(key_id.chars, test[i], key_id.len);
    CU_ASSERT(message_encoder(REQ_ENC, key_id, data, &message) == 0);
    CU_ASSERT(memcmp(message.chars, valid_enc_message[i], message.len) == 0);
    free_charbuf(&message);
    CU_ASSERT(message_encoder(REQ_DEC, key_id, data, &message) == 0);
    CU_ASSERT(memcmp(message.chars, valid_dec_message[i], message.len) == 0);
    free_charbuf(&message);
    free_charbuf(&key_id);
  }
  free_charbuf(&data);
}

void test_error_message_encoder(void)
{
  pelz_log(LOG_DEBUG, "Test err msg");
  const char *err_msg[5] = {
    "Missing Data", "missing data", "akdifid", "Error", "Any message"
  };
  charbuf message;

  for (int i = 0; i < 5; i++)
  {
    CU_ASSERT(error_message_encoder(&message, err_msg[i]) == 0);
    pelz_log(LOG_DEBUG, "Error Message: %.*s", message.len, message.chars);
    free_charbuf(&message);
  }
}
