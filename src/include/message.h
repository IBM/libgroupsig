/* 
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#ifndef _MESSAGE_H
#define _MESSAGE_H

#include <stdint.h>
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Type definitions */
typedef enum {
  MESSAGE_FORMAT_NULL_FILE, /* A file with unformatted contents */
  MESSAGE_FORMAT_STRING_B64, /* Just a base64 (char *) */
} message_format_t;

/* Supported message formats */
#define SUPPORTED_MESSAGE_FORMATS_N 2
static const int SUPPORTED_MESSAGE_FORMATS[SUPPORTED_MESSAGE_FORMATS_N] = { 
  MESSAGE_FORMAT_NULL_FILE,
  MESSAGE_FORMAT_STRING_B64,
};

/** 
 * @struct message_t
 * Defines a message structure. Currently it just contains the message bytes as
 * an array and the length of the array. In the future, this struct shall contain
 * meta information like the format.
 */
typedef struct _message_t {
  byte_t *bytes; /**< Message bytes. */
  uint64_t length; /**< Number of bytes */
} message_t;

/** 
 * @fn message_t* message_init(void)
 * Initializes a message structure, setting its variables to default values.
 * 
 * @return A pointer to the allocated memory or NULL if error.
 */
message_t* message_init(void);

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
 * @fn int message_export(void *dst, message_format_t format, message_t *msg)
 * Exports the received message to the specified format, and stores the result
 * in (or makes it be pointed by) <i>dst</i>.
 *
 * @param[in,out] dst Will contain the converted message or a pointer to it.
 * @param[in] format The formatting to be applied to the message.
 * @param[in] msg The message to convert.
 * 
 * @return IOK or IERROR with errno updated
 */
int message_export(void *dst, message_format_t, message_t *msg);

/** 
 * @fn int message_import(message_t *msg, message_format_t format, void *src)
 * Imports the message of format <i>format</i> contained in <i>src</i> into the
 * given message.
 *
 * @param[in,out] msg The message to be updated. Must have been initialized by
 *  the caller.
 * @param[in] format The format of the source.
 * @param[in] src The message source.
 * 
 * @return IOK or IERROR with errno updated.
 */
int message_import(message_t *msg, message_format_t format, void *src);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif
  

#endif /* _MESSAGE_H */

/* message.h ends here */
