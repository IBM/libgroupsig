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

#ifndef _GROUPSIG_SIGNATURE_H
#define _GROUPSIG_SIGNATURE_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Type definitions */

/**
 * @struct groupsig_signature_t
 * @brief Main structure for group signatures.
 */
typedef struct {
  uint8_t scheme; /**< The scheme of which this signature is an instance of. */
  void *sig; /**< The signature itself. */
} groupsig_signature_t;

/* Pointers to functions: 
   The functions of specific schemes must follow these definitions
 */

/**
 * @typedef groupsig_signature_t* (*groupsig_signature_init_f)(void)
 * @brief Type of functions for initializing group signatures.
 *
 * @return A pointer to an initialized group signature, or NULL if error.
 */
typedef groupsig_signature_t* (*groupsig_signature_init_f)(void);

/** 
 * @typedef int (*groupsig_signature_free_f)(groupsig_signature_t *signature);
 * @brief Type of functions for freeing group signatures.
 *
 * @param[in,out] signature The group signature to free.
 * 
 * @return IOK or IERROR.
 */
typedef int (*groupsig_signature_free_f)(groupsig_signature_t *signature);

/** 
 * @typedef int (*groupsig_signature_copy_f)(groupsig_signature_t *dst,
 *                                           groupsig_signature_t *src);
 * @brief Type of functions for copying group signatures.
 *
 * @param[in,out] dst The destination group signature. Must have been initialized
 *  by the caller.
 * @param[in] src The source group signature.
 * 
 * @return IOK or IERROR.
 */
typedef int (*groupsig_signature_copy_f)(groupsig_signature_t *dst,
					 groupsig_signature_t *src);

/** 
 * @typedef int (*groupsig_signature_get_size_f)(groupsig_signature_t *sig);
 * @brief Type of functions for getting the size in bytes of a group signature.
 *
 * @param[in] sig The signature.
 * 
 * @return IOK or IERROR.
 */
typedef int (*groupsig_signature_get_size_f)(groupsig_signature_t *sig);

/** 
 * @typedef int (*groupsig_signature_export_f)(byte_t **bytes,
 *                                             uint32_t *size,
 *                                             groupsig_signature_t *signature)
 * @brief Type of functions for exporting group signatures to an array of bytes.
 *
 * @param[in,out] bytes A pointer to the array of bytes. If <i>*bytes</i> is NULL,
 *  memory is internally allocated.
 * @param[in,out] size Will be set to the number of bytes written into <i>*bytes</i>.
 * @param[in] signature The group signature to export.
 * 
 * @return IOK or IERROR.
 */
typedef int (*groupsig_signature_export_f)(byte_t **bytes,
					   uint32_t *size,
					   groupsig_signature_t *signature);

/** 
 * @typedef groupsig_signature_t* (*groupsig_signature_import_f)(byte_t *source,
 *                                                               uint32_t size)
 * @brief Type of functions for importing group signatures from an array of bytes.
 * 
 * @param[in] source The array of bytes to parse.
 * @param[in] size The number of bytes in <i>source</i>.
 * 
 * @return A pointer to the imported signature, or NULL if error.
 */
typedef groupsig_signature_t* (*groupsig_signature_import_f)(byte_t *source,
							     uint32_t size);

/** 
 * @typedef char* (*groupsig_signature_to_string_f)(groupsig_signature_t *signature)
 * @brief Type of functions for obtaining printable strings of group signatures.
 *
 * @param[in] signature The group signature to convert.
 * 
 * @return A pointer to the produced string or NULL if error.
 */
typedef char* (*groupsig_signature_to_string_f)(groupsig_signature_t *signature);

/**
 * @struct groupsig_signature_handle_t
 * @brief Struct containing the set of handles for managing group signatures.
 */
typedef struct {
  uint8_t scheme; /**< The group signature scheme. */
  groupsig_signature_init_f init; /**< Initializes group signatures. */
  groupsig_signature_free_f free; /**< Frees group signatures. */
  groupsig_signature_copy_f copy; /**< Copies group signatures. */
  groupsig_signature_get_size_f get_size; /**< Returns the size in bytes
					     of specific signatures. */
  groupsig_signature_export_f gexport; /**< Exports group signatures. */
  groupsig_signature_import_f gimport; /**< Imports group signatures. */
  groupsig_signature_to_string_f to_string; /**< Gets printable strings of group signatures. */
} groupsig_signature_handle_t; 

/** 
 * @fn const groupsig_signature_handle_t* groupsig_signature_handle_from_code(uint8_t code);
 * @brief Returns the set of handles for managing group signatures of scheme <i>code</i>.
 *
 * @param[in] code The group signature scheme code.
 * 
 * @return A pointer to the struct of handles to manage group signatures of the
 *  scheme <i>code</i> or NULL if error.
 */
const groupsig_signature_handle_t* groupsig_signature_handle_from_code(uint8_t code);

/** 
 * @fn groupsig_signature_t* groupsig_signature_init(uint8_t code)
 * @brief Initializes a group signature of scheme <i>code</i>.
 *
 * @param[in] code The scheme code.
 * 
 * @return A pointer to the initialized group signature or NULL if error.
 */
groupsig_signature_t* groupsig_signature_init(uint8_t code);

/** 
 * @fn int groupsig_signature_free(groupsig_signature_t *sig)
 * @brief Frees the memory allocated for the given group signature.
 *
 * @param[in,out] sig The group signature to free.
 * 
 * @return IOK or IERROR.
 */
int groupsig_signature_free(groupsig_signature_t *sig);

/** 
 * @fn int groupsig_signature_copy(groupsig_signature_t *dst, groupsig_signature_t *src)
 * @brief Copies the group signature in <i>src</i> into <i>dst</i>.
 *
 * @param[in,out] dst The destination group signature. Must have been initialized
 *  by the caller.
 * @param[in] src The source group signature.
 * 
 * @return IOK or IERROR.
 */
int groupsig_signature_copy(groupsig_signature_t *dst, groupsig_signature_t *src);

/** 
 * @fn int groupsig_signature_get_size(groupsig_signature_t *sig)
 * @brief Returns the exact number of bytes needed to represent the group signature
 *  <i>sig</i>.
 *
 * @param[in] sig The group signature.
 * 
 * @return The number of bytes needed to represent <i>sig</i> or
 *  -1 if error, with errno appropriately set.
 */
int groupsig_signature_get_size(groupsig_signature_t *sig);

/** 
 * @fn int groupsig_signature_export(byte_t **dst, 
 *                                   uint32_t *size, 
 *                                   groupsig_signature_t *sig)
 * @brief Exports <i>sig</i> into <i>dst</i>.
 *
 * @param[in,out] dst A pointer to the array of bytes that will contain the 
 *  exported key.
 * @param[in,out] size A pointer to a uint32_t variable that will be set to the 
 *  number of bytes written into dst.
 * @param[in] key The key to export. 
 * 
 * @return IOK or IERROR.
 */
int groupsig_signature_export(byte_t **dst,
			      uint32_t *size,
			      groupsig_signature_t *sig);

/** 
 * @fn groupsig_signature_t* groupsig_signature_import(uint8_t code
 *                                                     byte_t *source,
 *                                                     uint32_t size);
 * @brief Imports the group signature stored in <i>src</i>.
 *
 * @param[in] code The scheme code.
 * @param[in] source The array of bytes to parse.
 * @param[in] size The number of bytes in <i>source</i>.
 * 
 * @return A pointer to the imported group signature or NULL if error.
 */
groupsig_signature_t* groupsig_signature_import(uint8_t code,
						byte_t *source,
						uint32_t size);

/** 
 * @fn char* groupsig_signature_to_string(groupsig_signature_t *sig)
 * @brief Returns a printable string of <i>sig</i>.
 *
 * @param[in] sig The group signature.
 * 
 * @return A pointer to the obtained string or NULL if error.
 */
char* groupsig_signature_to_string(groupsig_signature_t *sig);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _GROUPSIG_SIGNATURE_H */

/* signature.h ends here */
