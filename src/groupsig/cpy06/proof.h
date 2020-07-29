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

#ifndef _CPY06_PROOF_H
#define _CPY06_PROOF_H

#include <stdint.h>
#include <pbc/pbc.h>
#include "include/proof.h"
#include "cpy06.h"

/**
 * @def CPY06_SUPPORTED_PROOF_FORMATS_N
 * @brief Number of proof formats supported in CPY06.
 */
#define CPY06_SUPPORTED_PROOF_FORMATS_N 6

/**
 * @var CPY06_SUPPORTED_PROOF_FORMATS
 * @brief List of proof formats supported in CPY06.
 */
static const int CPY06_SUPPORTED_PROOF_FORMATS[CPY06_SUPPORTED_PROOF_FORMATS_N] = { 
  GROUPSIG_PROOF_FORMAT_FILE_NULL,
  GROUPSIG_PROOF_FORMAT_FILE_NULL_B64,
  GROUPSIG_PROOF_FORMAT_BYTEARRAY,
  GROUPSIG_PROOF_FORMAT_STRING_NULL_B64,
  GROUPSIG_PROOF_FORMAT_MESSAGE_NULL,
  GROUPSIG_PROOF_FORMAT_MESSAGE_NULL_B64,
};


/**
 * @struct cpy06_proof_t
 * @brief General NIZK proofs of knowledge for CPY06.
 */
typedef struct {
  element_t c; /**< */
  element_t s; /**< */
} cpy06_proof_t;

/** 
 * @fn struct groupsig_proof_t* cpy06_proof_init()
 * @brief Initializes the fields of a CPY06 proof.
 *
 * @return A pointer to the allocated proof or NULL if error.
 */
groupsig_proof_t* cpy06_proof_init();

/** 
 * @fn int cpy06_proof_free(groupsig_proof_t *proof)
 * @brief Frees the alloc'ed fields of the given CPY06 proof.
 *
 * @param[in,out] proof The proof to free.
 * 
 * @return IOK or IERROR
 */
int cpy06_proof_free(groupsig_proof_t *proof);

/** 
 * @fn int cpy06_proof_init_set_c(cpy06_proof_t *proof, bigz_t c)
 * Initializes the c field of the given proof and sets it to the specified value.
 * 
 * @param[in,out] proof The proof whose c field is to be initialized and set.
 * @param[in] c The value to copy into proof->c.
 * 
 * @return IOK or IERROR
 */
int cpy06_proof_init_set_c(cpy06_proof_t *proof, bigz_t c);

/** 
 * @fn int cpy06_proof_init_set_s(cpy06_proof_t *proof, bigz_t s)
 * Initializes the s field of the given proof and sets it to the specified value.
 * 
 * @param[in,out] proof The proof whose s field is to be initialized and set.
 * @param[in] s The value to copy into proof->s.
 * 
 * @return IOK or IERROR
 */
int cpy06_proof_init_set_s(cpy06_proof_t *proof, bigz_t s);

/** 
 * @fn void* cpy06_proof_copy(void *proof)
 * @brief Copies the given proof into a new one.
 *
 * @param[in] proof The proof to copy. 
 * 
 * @return A newly allocated proof (similar to the one received) or NULL
 *  if error.
 */
void* cpy06_proof_copy(void *proof);

/** 
 * @fn int cpy06_proof_to_string
 * @brief Returns a printable string representing the current proof.
 *
 * @param[in] proof The proof to print.
 * 
 * @return IOK or IERROR
 */
char* cpy06_proof_to_string(groupsig_proof_t *proof);

/** 
 * @fn int cpy06_proof_get_size_in_format(groupsig_proof_t *proof, 
 *                                        groupsig_proof_format_t format)
 * @brief Returns the size of the proof in the specified format. Useful when you have
 * to export the proof and pre-allocate the destination.
 *
 * @param[in] proof The proof.
 * @param[in] format The format.
 * 
 * @return -1 if error, the size that this proof would have in case of
 *  being exported to the specified format.
 */
int cpy06_proof_get_size_in_format(groupsig_proof_t *proof, groupsig_proof_format_t format);

/** 
 * @fn int cpy06_proof_export(groupsig_proof_t *proof, 
 *                              groupsig_proof_format_t format, void *dst);
 * @brief Prints the given proof as a base64 string into the specified
 *  file descriptor.
 *
 * @param[in] proof The proof to export.
 * @param[in] format The destination format.
 * @param[in,out] dst The destination (e.g., the filename to store it in).
 * 
 * @return IOK or IERROR with errno updated.
 */
int cpy06_proof_export(groupsig_proof_t *proof, groupsig_proof_format_t format, void *dst);

/** 
 * @fn int cpy06_proof_import(groupsig_proof_format_t format, void *source)
 * @brief Imports a proof according to the specified format.
 *
 * @param[in] format The format of the proof to import.
 * @param[in] source The proof to be imported.
 * 
 * @return IOK or IERROR
 */
groupsig_proof_t* cpy06_proof_import(groupsig_proof_format_t format, void *source);

/**
 * @var cpy06_proof_handle
 * @brief Set of functions to manage CPY06 proofs.
 */
static const groupsig_proof_handle_t cpy06_proof_handle = {
  GROUPSIG_CPY06_CODE, /**< The scheme code. */
  &cpy06_proof_init, /**< Initalizes proofs. */
  &cpy06_proof_free, /**< Frees proofs. */
  &cpy06_proof_get_size_in_format, /**< Gets the size of a proof in the
				      specified format. */
  &cpy06_proof_export, /**< Exports proofs. */
  &cpy06_proof_import, /**< Imports proofs. */
  &cpy06_proof_to_string /**< Gets printable representations of proofs. */
};

#endif /* _CPY06_PROOF_H */

/* proof.h ends here */
