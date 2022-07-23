#include <stdio.h>
#include <stdlib.h>
#include <CUnit/CUnit.h>
#include <uriparser/Uri.h>

#include "charbuf.h"
#include "pelz_log.h"
#include "pelz_uri_helpers.h"

#include "test_pelz_uri_helpers.h"

int test_pelz_uri_helpers_suite_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite, "Test scheme extraction", test_scheme_extraction))
  {
    return 1;
  }
  if (NULL == CU_add_test(suite, "Test query string extraction", test_query_string_extraction))
  {
    return 1;
  }
  return 0;
}

void test_scheme_extraction(void)
{
  const char *file_uri = "file:/filename";
  const char *file_uri_2 = "file:///filename";
  const char *pelz_uri = "pelz://common_name/0/key_uid/other_data";
  UriUriA uri;

  pelz_log(LOG_DEBUG, "Start URI functions");
  uriParseSingleUriA(&uri, file_uri, NULL);
  CU_ASSERT(get_uri_scheme(uri) == FILE_URI);
  char *filename = get_filename_from_key_id(uri);

  CU_ASSERT(strncmp((char *) filename, "/filename", strlen("/filename")) == 0);
  free(filename);
  uriFreeUriMembersA(&uri);

  uriParseSingleUriA(&uri, file_uri_2, NULL);
  CU_ASSERT(get_uri_scheme(uri) == FILE_URI);
  filename = get_filename_from_key_id(uri);
  CU_ASSERT(strncmp((char *) filename, "/filename", strlen("/filename")) == 0);
  free(filename);
  uriFreeUriMembersA(&uri);

  uriParseSingleUriA(&uri, pelz_uri, NULL);
  CU_ASSERT(get_uri_scheme(uri) == PELZ_URI);
  pelz_log(LOG_DEBUG, "Finish URI functions");

  charbuf common_name;
  int port = -1;
  charbuf key_id;
  charbuf additional_data;

  pelz_log(LOG_DEBUG, "Start URI Helper functions");
  get_pelz_uri_hostname(uri, &common_name);
  CU_ASSERT(common_name.len == strlen("common_name"));
  CU_ASSERT(memcmp(common_name.chars, "common_name", strlen("common_name")) == 0);
  pelz_log(LOG_DEBUG, "Finish URI hostname");

  get_pelz_uri_port(uri, &port);
  CU_ASSERT(port == 0);
  pelz_log(LOG_DEBUG, "Finish URI port");

  get_pelz_uri_key_UID(uri, &key_id);
  CU_ASSERT(key_id.len == strlen("key_uid"));
  CU_ASSERT(memcmp(key_id.chars, "key_uid", strlen("key_uid")) == 0);
  pelz_log(LOG_DEBUG, "Finish URI key UID");

  get_pelz_uri_additional_data(uri, &additional_data);
  CU_ASSERT(additional_data.len == strlen("other_data"));
  CU_ASSERT(memcmp(additional_data.chars, "other_data", strlen("other_data")) == 0);
  pelz_log(LOG_DEBUG, "Finish URI Helper functions");

  free_charbuf(&common_name);
  free_charbuf(&key_id);
  free_charbuf(&additional_data);
  uriFreeUriMembersA(&uri);
  return;
}

void test_query_string_extraction(void)
{
  const char* uri_string = "pelz://common_name/0/key_uid/other_data?file:/filename";
  const char* query_string = "file:/filename";
  UriUriA uri;
  uriParseSingleUriA(&uri, uri_string, NULL);
  charbuf query_buf;
  CU_ASSERT(get_pelz_query_string(uri, &query_buf) == 0);
  CU_ASSERT(query_buf.len == strlen(query_string));
  CU_ASSERT(memcmp(query_buf.chars, query_string, query_buf.len) == 0);
  free_charbuf(&query_buf);
  uriFreeUriMembersA(&uri); 
  return;
}
