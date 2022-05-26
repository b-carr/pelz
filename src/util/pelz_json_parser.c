/*
 * json_parser.c
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <cjson/cJSON.h>

#include <pelz_json_parser.h>
#include <pelz_request_handler.h>
#include <charbuf.h>
#include <pelz_log.h>

/**
 * <pre>
 * Helper function to extract fields from JSON structs. The fields must have
 * an associated length field whose name is <field_name>_len.
 * <pre>
 *
 * @param[in] json       The JSON structure.
 * @param[in] field_name The name of the desired field.
 *
 * @return A charbuf containing the data from the field, or a charbuf
 *         of length 0 on error.
 */
static charbuf get_JSON_string_field(cJSON* json, const char* field_name)
{
  charbuf field;
  if(!cJSON_HasObjectItem(json, field_name) || !cJSON_IsString(cJSON_GetObjectItem(json, field_name)))
  {
    pelz_log(LOG_ERR, "Missing JSON field %s.", field_name);
    return new_charbuf(0);
  } 
  if(cJSON_GetObjectItemCaseSensitive(json, field_name)->valuestring != NULL)
  {
    field = new_charbuf(strlen(cJSON_GetObjectItemCaseSensitive(json, field_name)->valuestring));
    if(field.len == 0 || field.chars == NULL)
    {  
      pelz_log(LOG_ERR, "Failed to allocate memory to extract JSON field %s.", field_name);
      return new_charbuf(0);
    }
    memcpy(field.chars, cJSON_GetObjectItemCaseSensitive(json, field_name)->valuestring, field.len);
  }
  else
  {
    pelz_log(LOG_ERR, "No value in JSON field %s.", field_name);
    return new_charbuf(0);
  }
  return field;
}

static int get_JSON_int_field(cJSON* json, const char* field_name, int* value)
{
  if(!cJSON_HasObjectItem(json, field_name) || !cJSON_IsNumber(cJSON_GetObjectItem(json, field_name)))
  {
    pelz_log(LOG_ERR, "Missing JSON field %s.", field_name);
    return 1;
  }
  *value = cJSON_GetObjectItemCaseSensitive(json, field_name)->valueint;
  return 0;
}

int request_decoder(charbuf request, RequestType * request_type, charbuf * key_id, charbuf * data, charbuf* cipher, charbuf* iv, charbuf* tag, charbuf * request_sig, charbuf * requestor_cert)
{
  cJSON *json;
  unsigned char* str = null_terminated_string_from_charbuf(request);
  json = cJSON_Parse((char*)str);
  free(str);

  if(get_JSON_int_field(json, "request_type", (int*)request_type))
  {
    pelz_log(LOG_ERR, "Missing required JSON key: request_type.");
    cJSON_Delete(json);
    return (1);
  }

  *key_id = get_JSON_string_field(json, "key_id");
  if(key_id->len == 0 || key_id->chars == NULL)
  {
    pelz_log(LOG_ERR, "Failed to extract key_id from JSON.");
    free_charbuf(key_id);
    return 1;
  }
  *data = get_JSON_string_field(json, "data");
  if(data->len == 0 || data->chars == NULL)
  {
    pelz_log(LOG_ERR, "Failed to extract data from JSON.");
    free_charbuf(key_id);
    free_charbuf(data);
    return 1;
  }
  *cipher = get_JSON_string_field(json, "cipher");
  if(cipher->len == 0 || cipher->chars == NULL)
  {
    pelz_log(LOG_ERR, "Failed to extract cipher from JSON.");
    free_charbuf(cipher);
    free_charbuf(key_id);
    free_charbuf(data);
    return 1;
  }
  switch (*request_type)
  {    
  case REQ_ENC_SIGNED:
    *request_sig = get_JSON_string_field(json, "request_sig");
    *requestor_cert = get_JSON_string_field(json, "requester_cert");
  // Intentional fallthrough
  case REQ_ENC:
    break;
  case REQ_DEC_SIGNED:
    *request_sig = get_JSON_string_field(json, "request_sig");
    *requestor_cert = get_JSON_string_field(json, "requestor_cert");
  // Intentional fallthrough
  case REQ_DEC:
    *iv = get_JSON_string_field(json, "iv");
    *tag = get_JSON_string_field(json, "tag");
    break;
  default:
    pelz_log(LOG_WARNING, "Invalid Request Type");
    cJSON_Delete(json);
    return (1);
  }
  if ( (*request_type == REQ_ENC_SIGNED) || (*request_type == REQ_DEC_SIGNED) )
  {
    if (signed_parser(json, request_sig, requestor_cert) )
    {
      pelz_log(LOG_ERR, "Encrypt/Decrypt Signed Parser Error");
      cJSON_Delete(json);
      return (1);
    }
    if ( validate_signature(request_type, key_id, data, request_sig, requestor_cert) )
    {
      pelz_log(LOG_ERR, "Signature Validation Error");
      cJSON_Delete(json);
      return (1);
    }
  }
  cJSON_Delete(json);
  return (0);
}

int error_message_encoder(charbuf * message, const char *err_message)
{
  cJSON *root;
  char *tmp = NULL;

  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "error", cJSON_CreateString(err_message));
  if (cJSON_IsInvalid(root))
  {
    pelz_log(LOG_ERR, "JSON Message Creation Failed");
    cJSON_Delete(root);
    return (1);
  }
  tmp = cJSON_PrintUnformatted(root);
  *message = new_charbuf(strlen(tmp));
  memcpy(message->chars, tmp, message->len);
  cJSON_Delete(root);
  free(tmp);
  return (0);
}

int message_encoder(RequestType request_type, charbuf key_id, charbuf data, charbuf * message)
{
  cJSON *root;
  char *tmp = NULL;

  root = cJSON_CreateObject();
  switch (request_type)
  {
  case REQ_ENC:
    tmp = (char *) calloc((key_id.len + 1), sizeof(char));
    memcpy(tmp, key_id.chars, key_id.len);
    cJSON_AddItemToObject(root, "key_id", cJSON_CreateString(tmp));
    free(tmp);
    cJSON_AddItemToObject(root, "key_id_len", cJSON_CreateNumber(key_id.len));
    tmp = (char *) calloc((data.len + 1), sizeof(char));
    memcpy(tmp, data.chars, data.len);
    cJSON_AddItemToObject(root, "data", cJSON_CreateString(tmp));
    free(tmp);
    cJSON_AddItemToObject(root, "data_len", cJSON_CreateNumber(data.len));
    break;
  case REQ_DEC:
    tmp = (char *) calloc((key_id.len + 1), sizeof(char));
    memcpy(tmp, key_id.chars, key_id.len);
    cJSON_AddItemToObject(root, "key_id", cJSON_CreateString(tmp));
    free(tmp);
    cJSON_AddItemToObject(root, "key_id_len", cJSON_CreateNumber(key_id.len));
    tmp = (char *) calloc((data.len + 1), sizeof(char));
    memcpy(tmp, data.chars, data.len);
    cJSON_AddItemToObject(root, "data", cJSON_CreateString(tmp));
    free(tmp);
    cJSON_AddItemToObject(root, "data_len", cJSON_CreateNumber(data.len));
    break;
  default:
    pelz_log(LOG_ERR, "Request Type not recognized.");
    cJSON_Delete(root);
    return (1);
  }
  if (cJSON_IsInvalid(root))
  {
    pelz_log(LOG_ERR, "JSON Message Creation Failed");
    cJSON_Delete(root);
    return (1);
  }
  tmp = cJSON_PrintUnformatted(root);
  *message = new_charbuf(strlen(tmp));
  memcpy(message->chars, tmp, message->len);
  cJSON_Delete(root);
  free(tmp);
  return (0);
}

int signed_parser(cJSON * json, charbuf * request_sig, charbuf * requestor_cert)
{
  if (!cJSON_HasObjectItem(json, "request_sig"))
  {
    pelz_log(LOG_ERR, "Missing required JSON key: request_sig.");
    return (1);
  }
  else if (!cJSON_HasObjectItem(json, "request_sig_len"))
  {
    pelz_log(LOG_ERR, "Missing required JSON key: request_sig_len.");
    return (1);
  }
  else if (!cJSON_HasObjectItem(json, "requestor_cert"))
  {
    pelz_log(LOG_ERR, "Missing required JSON key: requestor_cert.");
    return (1);
  }
  else if (!cJSON_HasObjectItem(json, "requestor_cert_len"))
  {
    pelz_log(LOG_ERR, "Missing required JSON key: requestor_cert_len.");
    return (1);
  }
  
  if (!cJSON_IsNumber(cJSON_GetObjectItem(json, "request_sig_len")))
  {
    pelz_log(LOG_ERR, "Incorrect data type of JSON value of JSON key: request_sig_len. Data type should be integer.");
    return (1);
  }
  *request_sig = new_charbuf(cJSON_GetObjectItemCaseSensitive(json, "request_sig_len")->valueint);
  if (!cJSON_IsString(cJSON_GetObjectItem(json, "request_sig")))
  {
    pelz_log(LOG_ERR, "Incorrect data type of JSON value of JSON key: request_sig. Data type should be string.");
    free_charbuf(request_sig);
    return (1);
  }
  if (cJSON_GetObjectItemCaseSensitive(json, "request_sig")->valuestring != NULL)
  {
    if (strlen(cJSON_GetObjectItemCaseSensitive(json, "request_sig")->valuestring) != request_sig->len)
    {     
      pelz_log(LOG_ERR, "Length of value in JSON key: request_sig does not match value in JSON key: request_sig_len.");
      free_charbuf(request_sig);
      return (1);
    }
    memcpy(request_sig->chars, cJSON_GetObjectItemCaseSensitive(json, "request_sig")->valuestring, request_sig->len);
  }
  else
  {
    pelz_log(LOG_ERR, "No value in JSON key: request_sig.");
    free_charbuf(request_sig);
    return (1);
  }
  if (!cJSON_IsNumber(cJSON_GetObjectItem(json, "requestor_cert_len")))
  {
    pelz_log(LOG_ERR, "Incorrect data type of JSON value of JSON key: requestor_cert_len. Data type should be integer.");
    free_charbuf(request_sig);
    return (1);
  }
  *requestor_cert = new_charbuf(cJSON_GetObjectItemCaseSensitive(json, "requestor_cert_len")->valueint);
  if (!cJSON_IsString(cJSON_GetObjectItem(json, "requestor_cert")))
  {
    pelz_log(LOG_ERR, "Incorrect data type of JSON value of JSON key: requestor_cert. Data type should be string.");
    free_charbuf(request_sig);
    free_charbuf(requestor_cert);
    return (1);
  }
  if (cJSON_GetObjectItemCaseSensitive(json, "requestor_cert")->valuestring != NULL)
  {
    if (strlen(cJSON_GetObjectItemCaseSensitive(json, "requestor_cert")->valuestring) != requestor_cert->len)
    {
      pelz_log(LOG_ERR, "Length of value in JSON key: requestor_cert does not match value in JSON key: requestor_cert_len.");
      free_charbuf(request_sig);
      free_charbuf(requestor_cert);
      return (1);
    }
    memcpy(requestor_cert->chars, cJSON_GetObjectItemCaseSensitive(json, "requestor_cert")->valuestring, requestor_cert->len);
  }
  else
  {
    pelz_log(LOG_ERR, "No value in JSON key: requestor_cert.");
    free_charbuf(request_sig);
    free_charbuf(requestor_cert);
    return (1);
  }
  return (0);
}

// At some point this function will have to contain a concatenated string of the buffer fields to ensure order when comparing info
int validate_signature(RequestType * request_type, charbuf * key_id, charbuf * data, charbuf * request_sig, charbuf * requestor_cert)
{
  // Stub
  return 0;
}
