#ifndef INCLUDE_PELZ_IO_H_
#define INCLUDE_PELZ_IO_H_

#include "charbuf.h"
#include "pelz_request_handler.h"

#define PELZSERVICEIN "/tmp/pelzServiceIn"
#define PELZSERVICEOUT "/tmp/pelzServiceOut"

typedef enum
{ INVALID, EXIT, UNABLE_RD_F, TPM_UNSEAL_FAIL, SGX_UNSEAL_FAIL, ADD_CERT_FAIL, LOAD_CERT, INVALID_EXT_CERT,
  ADD_PRIV_FAIL, LOAD_PRIV, INVALID_EXT_PRIV, RM_CERT_FAIL, RM_CERT, CERT_TAB_DEST_FAIL, RM_ALL_CERT, RM_KEK_FAIL,
  RM_KEK, KEK_TAB_DEST_FAIL, KEK_TAB_INIT_FAIL, RM_KEK_ALL, ERR_CHARBUF
} ParseResponseStatus;

typedef enum
{ NO_EXT, NKL, SKI } ExtensionType;

#ifdef __cplusplus
extern "C"
{
#endif
/**
 * <pre>
 * This function returns an ExtensionType to tell program if filename has a .nkl or .ski extension
 * </pre>
 *
 * @param[in] filename Contains the file name string
 *
 * @return ExtensionType
 */
  ExtensionType get_file_ext(char *filename);

/**
 * <pre>
 * Load key from location stated by Key ID
 * <pre>
 *
 * @param[in] key_id.len     the length of the key identifier
 * @param[in] key_id.chars   the key identifier
 *
 * @return 0 on success, 1 on error
 */
  int key_load(charbuf key_id);

/**
 * <pre>
 * Using key_id to check if there is actual file
 * <pre>
 *
 * @param[in] key_id The Identifier for the Key which is also file path and name
 *
 * @return 0 on success, 1 on error
 */
  int file_check(char *file_path);

/**
 * <pre>
 * Writes a message to the FIFO pipe
 * </pre>
 *
 * @param[in] pipe The FIFO pipe name
 * @param[in] msg Message to be sent along the pipe
 *
 * @return 0 if success, 1 if error
 */
  int write_to_pipe(char *pipe, char *msg);

/**
 * <pre>
 * Reads a message from the FIFO pipe
 * </pre>
 *
 * @param[in] pipe The FIFO pipe name
 * @param[out] msg Message sent along the pipe
 *
 * @return 0 if success, 1 if error
 */
  int read_from_pipe(char *pipe, char **msg);

/**
 * <pre>
 * Splits a message on the pelz pipe into tokens. Assumes a delimiter of ' '
 * </pre>
 *
 * @param[out] Reference to a double pointer intended to hold tokens
 * @param[out] The number of tokens output
 * @param[in]  The message to be tokenized
 * @param[in]  The length of the message being tokenized
 *
 * @return 0 if success, 1 if error
 */
  int tokenize_pipe_message(char ***tokens, size_t * num_tokens, char *message, size_t message_length);

/**
 * <pre>
 * Takes a message from the Pelz FIFO pipe then parses and executes the command
 * from message
 * </pre>
 *
 * @param[in] tokens Tokenized message from the pipe to be parsed and executed
 * @param[in] num_tokens The number of tokens output
 * @param[out] response Response to be sent to the second pipe 
 *
 * @return ParseResponseStatus status message indicating the outcome of parse
 */
  ParseResponseStatus parse_pipe_message(char **tokens, size_t num_tokens);

/**
 * <pre>
 * Send the specified command msg over send_pipe and waits to receive a
 * response on receive_pipe.
 * </pre>
 *
 * @param[in] msg          Null-terminated message to send.
 *
 * @return 0 on success, 1 on error
 */
  int pelz_send_command(char *msg);
#ifdef __cplusplus
}
#endif

#endif
