/*                               -*- Mode: C -*- 
 * @file: message.h
 * @brief: 
 * @author: jesus
 * Maintainer: 
 * @date: mié jul 18 15:47:16 2012 (+0200)
 * @version: 
 * Last-Updated: lun abr  1 13:30:33 2013 (+0200)
 *           By: jesus
 *     Update #: 26
 * URL: 
 */

#ifndef _MESSAGE_H
#define _MESSAGE_H

#include <stdint.h>
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/** 
 * @struct message_t
 * Defines a message structure. Currently it just contains the message bytes as
 * an array and the length of the array.
 */
typedef struct _message_t {
  byte_t *bytes; /**< Message data (bytes). Will be processed depending on
		    the message representation. */
  uint64_t length; /**< Size of data (in number of bytes). */
} message_t;

/** 
 * @fn message_t* message_init()
 * Initializes a message structure, setting its variables to default values.
 * 
 * @return A pointer to the allocated memory or NULL if error.
 */
 message_t* message_init();

/**
 * @fn message_t* message_from_string(char *str)
 * Creates a new message from the received string.
 *
 * @param[in] string The string to be stored as a message. Will be duplicated.
 *
 * @return A pointer to the generated message.
 */
 message_t* message_from_string(char *str);

/**
 * @fn message_t* message_from_bytes(byte_t *bytes, uint64_t length)
 * Creates a new message from the received string.
 *
 * @param[in] bytes The bytes to be stored as a message.
 * @param[in] length The number of bytes in the byte array..
 *
 * @return A pointer to the generated message.
 */
 message_t* message_from_bytes(byte_t *bytes, uint64_t length);

/** 
 * @fn int message_free(message_t *msg)
 * Frees a message structure, including its internal variables and the received 
 * pointer.
 *
 * @param[in,out] msg The message to free.
 * 
 * @return IOK.
 */
int message_free(message_t *msg);

/**
 * @fn int message_set_bytes(message_t *msg, byte_t *bytes, uint64_t length)
 * Sets the message bytes to the ones received. The memory is duplicated.
 *
 * @param[in,out] msg The message whose bytes will be set to the received ones.
 *  Must have been initialized by the caller.
 * @param[in] bytes The bytes to copy.
 * @param[in] length The number of received bytes.
 *
 * @return IOK or IERROR with errno updated
 */
int message_set_bytes(message_t *msg, byte_t *bytes, uint64_t length);

/**
 * @fn int message_set_bytes_from_string(message_t *msg, char *string)
 * Sets the message contents from the received string. The memory is duplicated.
 *
 * @param[in,out] msg The message whose bytes will be updated. Must have been
 *  initialized by the caller.
 * @param[in] string The string to copy
 *
 * @return IOK or IERROR with errno updated
 */
int message_set_bytes_from_string(message_t *msg, char *string);

/** 
 * @fn int message_copy(message_t *dst, message_t *src)
 * Copies the contents of the source message into the destination message. 
 *
 * @param[in,out] dst The destination message. Must have been initialized 
 *  by the caller.
 * @param[in] src The source message.
 * 
 * @return IOK or IERROR with errno updated.
 */
int message_copy(message_t *dst, message_t *src);

/** 
 * @fn char* message_to_string(message_t *msg)
 * Converts the received message to a string.
 *
 * @param[in] msg The message to convert.
 * 
 * @return A pointer to the produced string or NULL if error with errno updated.
 */
char* message_to_string(message_t *msg);

/** 
 * @fn char* message_to_base64(message_t *msg)
 * Converts the received message to a base64 string.
 *
 * @param[in] msg The message to convert.
 * 
 * @return A pointer to the produced string or NULL if error with errno updated.
 */
char* message_to_base64(message_t *msg);

/** 
 * @fn message_t* message_from_base64(char *b64)
 * Decodes the given base64 string and uses the result to set a message_t 
 * struct.
 *
 * @param[in] b64 The base64 string to decode.
 * 
 * @return A pointer to the produced message or NULL if error with errno 
 *  updated.
 */  
message_t* message_from_base64(char *b64); 

/** 
 * @fn int message_json_get_key(char **value, message_t *msg, char *key)
 * In a message with JSON format, fetches the value of the given key entry.
 *
 * @param[in,out] value Will be set to the retrieved value. if *value is NULL,
 *  memory is allocated internally.
 * @param[in] msg The message to parse.
 * @param[in] key The key to fetch.
 * 
 * @return The imported message or NULL with errno updated.
 */
int message_json_get_key(char **value, message_t *msg, char *key);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif
  
#endif /* _MESSAGE_H */

/* message.h ends here */
