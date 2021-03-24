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

#ifndef _PROOF_H
#define _PROOF_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Type definitions */

/**
 * @struct groupsig_proof_t
 * @brief Structure for group signature schemes general ZK proofs.
 */
typedef struct {
  uint8_t scheme; /**< The scheme of which this proof is an instance of. */
  void *proof; /**< The proof itself. */
} groupsig_proof_t;

/* Pointers to functions: 
   The functions of specific schemes must follow these definitions
 */

/**
 * @typedef groupsig_proof_t* (*groupsig_proof_init_f)(void);
 * @brief Type of functions for initializing proofs.
 *
 * @return A pointer to the initialized proof or NULL if error.
 */
typedef groupsig_proof_t* (*groupsig_proof_init_f)(void);

/**
 * @typedef int (*groupsig_proof_free_f)(groupsig_proof_t *proof);
 * @brief Type of functions for freeing proofs.
 *
 * @param[in,out] proof The proof to be freed.
 *
 * @return IOK or IERROR.
 */
typedef int (*groupsig_proof_free_f)(groupsig_proof_t *proof);

/** 
 * @typedef int (*groupsig_proof_copy_f)(groupsig_proof_t *dst,
 *                                           groupsig_proof_t *src);
 * @brief Type of functions for copying group proofs.
 *
 * @param[in,out] dst The destination group proof. Must have been initialized
 *  by the caller.
 * @param[in] src The source group proof.
 * 
 * @return IOK or IERROR.
 */
typedef int (*groupsig_proof_copy_f)(groupsig_proof_t *dst,
				     groupsig_proof_t *src);

/** 
 * @typedef int (*groupsig_proof_get_size_f)(groupsig_proof_t *proof);
 * @brief Type of functions for getting the size in bytes of the <i>proof</i>.
 * 
 * @param[in] proof The proof.
 * 
 * @return The number of bytes needed to represent <i>proof</i> in <i>format</i> format.
 *  On error, errno must be set appropriately.
 */
typedef int (*groupsig_proof_get_size_f)(groupsig_proof_t *proof);

/** 
 * @typedef int (*groupsig_proof_export_f)(byte_t **bytes,
 *					   uint32_t *size,
 *					   groupsig_proof_t *proof)
 * @brief Type of functions for exporting proofs.
 *
 * @param[in,out] bytes A pointer to the array of bytes. If <i>*bytes</i> is NULL,
 *  memory is internally allocated.
 * @param[in,out] size Will be set to the number of bytes written into <i>*bytes</i>.
 * @param[in] proof The proof to export.
 * 
 * @return IOK or IERROR.
 */
typedef int (*groupsig_proof_export_f)(byte_t **bytes,
				       uint32_t *size,
				       groupsig_proof_t *proof);

/** 
 * @typedef groupsig_proof_t* (*groupsig_proof_import_f)(byte_t *source, 
 *                                                       uint32_t size);
 * @brief Type of functions for importing proofs.
 *
 * @param[in] source The array of bytes to parse.
 * @param[in] size The number of bytes in <i>source</i>.
 * 
 * @return A pointer to the retrieved proof or NULL if error.
 */
typedef groupsig_proof_t* (*groupsig_proof_import_f)(byte_t *source, 
						     uint32_t size);

/** 
 * @fn typedef char* (*groupsig_proof_to_string_f)(groupsig_proof_t *proof);
 * @brief Type of functions for producing printable strings representations of
 *  proofs.
 *
 * @param[in] proof The proof.
 * 
 * @return A pointer to the produced string or NULL if error.
 */
typedef char* (*groupsig_proof_to_string_f)(groupsig_proof_t *proof);

/**
 * @struct groupsig_proof_handle_t
 * @brief Bundles together all the function handles for managing proofs.
 */
typedef struct {
  uint8_t scheme; /**< The scheme code. */
  groupsig_proof_init_f init; /**< Initializes proofs. */
  groupsig_proof_free_f free; /**< Frees proofs. */
  groupsig_proof_get_size_f get_size; /**< Returns the size in
					 bytes needed to represent
					 a proof. */
  groupsig_proof_copy_f copy; /**< Copies group proofs. */  
  groupsig_proof_export_f gexport; /**< Exports proofs. */
  groupsig_proof_import_f gimport; /**< Imports proofs. */
  groupsig_proof_to_string_f to_string; /**< Produces printable string versions 
					   of proofs. */
} groupsig_proof_handle_t;

/** 
 * @fn const groupsig_proof_handle_t* groupsig_proof_handle_from_code(uint8_t code);
 * @brief Returns the bundle of function handles for managing proofs of the
 *  given scheme.
 *
 * @param[in] code The scheme code.
 * 
 * @return A pointer to the functions bundle or NULL if error.
 */
const groupsig_proof_handle_t* groupsig_proof_handle_from_code(uint8_t code);

/** 
 * @fn groupsig_proof_t* groupsig_proof_init(uint8_t code);
 * @brief Initializes a proof of the given scheme.
 *
 * @param[in] code The scheme code.
 * 
 * @return A pointer to the initialized proof or NULL if error.
 */
groupsig_proof_t* groupsig_proof_init(uint8_t code);

/** 
 * @fn int groupsig_proof_free(groupsig_proof_t *proof);
 * @brief Frees the memory allocated for the given proof.
 *
 * @param[in,out] proof The proof to free.
 * 
 * @return IOK or IERROR.
 */
int groupsig_proof_free(groupsig_proof_t *proof);

/** 
 * @fn int groupsig_proof_get_size_in_format(groupsig_proof_t *proof);
 * @brief Returns the number of bytes necessary to represent <i>proof</i>.
 *
 * @param[in] proof The proof.
 * 
 * @return The number of bytes necessary to represent the proof. On error, errno
 *  must be set appropriately.
 */
int groupsig_proof_get_size(groupsig_proof_t *proof);

/** 
 * @fn int groupsig_proof_copy(groupsig_proof_t *dst, groupsig_proof_t *src)
 * @brief Copies the group proof in <i>src</i> into <i>dst</i>.
 *
 * @param[in,out] dst The destination group proof. Must have been initialized
 *  by the caller.
 * @param[in] src The source group proof.
 * 
 * @return IOK or IERROR.
 */
int groupsig_proof_copy(groupsig_proof_t *dst, groupsig_proof_t *src);

/** 
 * @fn int groupsig_proof_export(byte_t **bytes,
 *			         uint32_t *size,
 *			         groupsig_proof_t *proof);
 * @brief Exports <i>proof</i> to <i>dst</i>.
 *
 * @param[in,out] dst A pointer to the array of bytes that will contain the 
 *  exported proof.
 * @param[in,out] size A pointer to a uint32_t variable that will be set to the 
 *  number of bytes written into dst.
 * @param[in] proof The proof to export.
 * 
 * @return IOK or IERROR.
 */
int groupsig_proof_export(byte_t **bytes,
			  uint32_t *size,
			  groupsig_proof_t *proof);

/** 
 * @fn groupsig_proof_t* groupsig_proof_import(uint8_t code, 
 *					       byte_t *source,
 *					       uint32_t size);
 * @brief Imports a proof of the scheme <i>code</i>, stored in <i>src</i>.
 * 
 * @param[in] code The scheme code.
 * @param[in] source The array of bytes to parse.
 * @param[in] size The number of bytes in <i>source</i>.
 * 
 * @return A pointer to the recovered proof or NULL if error.
 */
groupsig_proof_t* groupsig_proof_import(uint8_t code, 
					byte_t *source,
					uint32_t size);

/** 
 * @fn char* groupsig_proof_to_string(groupsig_proof_t *proof);
 * @brief Returns a printable string version of the given proof.
 *
 * @param[in] proof The proof.
 * 
 * @return A pointer to the produced string or NULL if error.
 */
char* groupsig_proof_to_string(groupsig_proof_t *proof);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif
  
#endif /* _PROOF_H */

/* proof.h ends here */
