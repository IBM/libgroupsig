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

#ifndef _GROUPSIG_BLINDSIG_H
#define _GROUPSIG_BLINDSIG_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Type definitions */

/**
 * @struct groupsig_blindsig_t
 * @brief Main structure for blinded signatures.
 * Some schemes' operations may require blinding their signatures. Use this
 * data structure for that. 
 */
typedef struct {
  uint8_t scheme;
  void *sig;
} groupsig_blindsig_t;

/* Pointers to functions: 
   The functions of specific schemes must follow these definitions
*/

/**
 * @typedef groupsig_blindsig_t* (*groupsig_blindsig_init_f)(void)
 * @brief Type of functions for initializing blinded group signatures.
 *
 * @return A pointer to an initialized blinded group signature, or NULL if error.
 */
typedef groupsig_blindsig_t* (*groupsig_blindsig_init_f)(void);

/** 
 * @typedef int (*groupsig_blindsig_free_f)(groupsig_blindsig_t *blindsig);
 * @brief Type of functions for freeing blinded group signatures.
 *
 * @param[in,out] blindsig The blinded group signature to free.
 * 
 * @return IOK or IERROR.
 */
typedef int (*groupsig_blindsig_free_f)(groupsig_blindsig_t *blindsig);

/** 
 * @typedef int (*groupsig_blindsig_copy_f)(groupsig_blindsig_t *dst, groupsig_blindsig_t *src);
 * @brief Type of functions for copying blinded group signatures.
 *
 * @param[in,out] dst The destination blinded group signature. Must have been initialized
 *  by the caller.
 * @param[in] src The source blinded group signature.
 * 
 * @return IOK or IERROR.
 */
typedef int (*groupsig_blindsig_copy_f)(groupsig_blindsig_t *dst, groupsig_blindsig_t *src);

/** 
 * @typedef int (*groupsig_blindsig_get_size_in_format_f)(groupsig_blindsig_t *sig);
 * @brief Type of functions for getting the size in bytes of a blinded group
 *  signature.
 *
 * @param[in] sig The signature.
 * 
 * @return The number of bytes required to represent sig, or -1 if error.
 */
typedef int (*groupsig_blindsig_get_size_f)(groupsig_blindsig_t *sig);

/** 
 * @typedef int (*groupsig_blindsig_export_f)(byte_t **bytes,
 *                                            uint32_t *size,
 *                                            groupsig_blindsig_t *blindsig)
 * @brief Type of functions for exporting blinded group signatures.
 * 
 * @param[in,out] bytes A pointer to the array of bytes. If <i>*bytes</i> is NULL,
 *  memory is internally allocated.
 * @param[in,out] size Will be set to the number of bytes written into <i>*bytes</i>.
 * @param[in] signature The blinded group signature to export.
 * 
 * @return IOK or IERROR.
 */
typedef int (*groupsig_blindsig_export_f)(byte_t **bytes,
					  uint32_t *size,
					  groupsig_blindsig_t *signature);

/** 
 * @typedef groupsig_blindsig_t* (*groupsig_blindsig_import_f)(byte_t *source,
 *                                                             uint32_t size)
 * @brief Type of functions for importing blinded group signatures.
 * 
 * @param[in] source The array of bytes to parse.
 * @param[in] size The number of bytes in <i>source</i>.
 * 
 * @return A pointer to the imported blinded signature, or NULL if error.
 */
typedef groupsig_blindsig_t* (*groupsig_blindsig_import_f)(byte_t *source,
							   uint32_t size);

/** 
 * @typedef char* (*groupsig_blindsig_to_string_f)(groupsig_blindsig_t *blindsig)
 * @brief Type of functions for obtaining printable strings of blinded group signatures.
 *
 * @param[in] blindsig The blinded group signature to convert.
 * 
 * @return A pointer to the produced string or NULL if error.
 */
typedef char* (*groupsig_blindsig_to_string_f)(groupsig_blindsig_t *blindsig);

/**
 * @struct groupsig_blindsig_handle_t
 * @brief Struct containing the set of handles for managing blinded group signatures.
 */
typedef struct {
  uint8_t scheme; /**< The group blindsig scheme. */
  groupsig_blindsig_init_f init; /**< Initializes blinded group signatures. */
  groupsig_blindsig_free_f free; /**< Frees blinded group signatures. */
  groupsig_blindsig_copy_f copy; /**< Copies blinded group signatures. */
  groupsig_blindsig_get_size_f get_size; /**< Returns the size in bytes
					      of specific signatures. */
  groupsig_blindsig_export_f gexport; /**< Exports blinded group signatures. */
  groupsig_blindsig_import_f gimport; /**< Imports blinded group signatures. */
  groupsig_blindsig_to_string_f to_string; /**< Gets printable strings of blinded group signatures. */
} groupsig_blindsig_handle_t; 

/** 
 * @fn const groupsig_blindsig_handle_t* groupsig_blindsig_handle_from_code(uint8_t code);
 * @brief Returns the set of handles for managing blinded group signatures of scheme <i>code</i>.
 *
 * @param[in] code The blinded group signature scheme code.
 * 
 * @return A pointer to the struct of handles to manage blinded group signatures of the
 *  scheme <i>code</i> or NULL if error.
 */
const groupsig_blindsig_handle_t* groupsig_blindsig_handle_from_code(uint8_t code);

/** 
 * @fn groupsig_blindsig_t* groupsig_blindsig_init(uint8_t code)
 * @brief Initializes a blinded group signature of scheme <i>code</i>.
 *
 * @param[in] code The scheme code.
 * 
 * @return A pointer to the initialized blinded group signature or NULL if error.
 */
groupsig_blindsig_t* groupsig_blindsig_init(uint8_t code);

/** 
 * @fn int groupsig_blindsig_free(groupsig_blindsig_t *sig)
 * @brief Frees the memory allocated for the given blinded group signature.
 *
 * @param[in,out] sig The blinded group signature to free.
 * 
 * @return IOK or IERROR.
 */
int groupsig_blindsig_free(groupsig_blindsig_t *sig);

/** 
 * @fn int groupsig_blindsig_copy(groupsig_blindsig_t *dst, groupsig_blindsig_t *src)
 * @brief Copies the blinded group signature in <i>src</i> into <i>dst</i>.
 *
 * @param[in,out] dst The destination blinded group signature. Must have been initialized
 *  by the caller.
 * @param[in] src The source blinded group signature.
 * 
 * @return IOK or IERROR.
 */
int groupsig_blindsig_copy(groupsig_blindsig_t *dst, groupsig_blindsig_t *src);

/** 
 * @fn int groupsig_blindsig_get_size_in_format(groupsig_blindsig_t *sig)
 * @brief Returns the exact number of bytes needed to represent the blinded
 *  group signature.
 *
 * @param[in] sig The blinded group signature.
 * 
 * @return The number of bytes needed to represent <i>sig</i>, or -1 if error.
 */
int groupsig_blindsig_get_size(groupsig_blindsig_t *sig);

/** 
 * @fn int groupsig_blindsig_export(byte_t **dst, 
 *                                  uint32_t *size,
 *                                  groupsig_blindsig_t *sig)
 * @brief Exports <i>sig</i> into <i>dst</i>.
 *
 * @param[in,out] dst A pointer to the array of bytes that will contain the 
 *  exported key.
 * @param[in,out] size A pointer to a uint32_t variable that will be set to the 
 *  number of bytes written into dst.
 * @param[in] sig The blinded signature to export. 
 * 
 * @return IOK or IERROR.
 */
int groupsig_blindsig_export(byte_t **dst,
			     uint32_t *size,
			     groupsig_blindsig_t *sig);

/** 
 * @fn groupsig_blindsig_t* groupsig_blindsig_import(uint8_t code
 *                                                   byte_t *source,
 *                                                   uint32_t size);
 * @brief Imports the blinded group signature stored in <i>source</i>.
 *
 * @param[in] code The scheme code.
 * @param[in] source The array of bytes to parse.
 * @param[in] size The number of bytes in <i>source</i>.
 * 
 * @return A pointer to the imported blinded group signature or NULL if error.
 */
groupsig_blindsig_t* groupsig_blindsig_import(uint8_t code,
					      byte_t *source,
					      uint32_t size);

/** 
 * @fn char* groupsig_blindsig_to_string(groupsig_blindsig_t *sig)
 * @brief Returns a printable string of <i>sig</i>.
 *
 * @param[in] sig The blinded group signature.
 * 
 * @return A pointer to the obtained string or NULL if error.
 */
char* groupsig_blindsig_to_string(groupsig_blindsig_t *sig);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif
  
#endif /* _GROUPSIG_BLINDSIG_H */

/* blindsig.h ends here */
