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

#ifndef _DL21_PROOF_H
#define _DL21_PROOF_H

#include <stdint.h>
#include "include/proof.h"
#include "crypto/spk.h"
#include "dl21.h"

/**
 * @struct dl21_proof_t
 * @brief General NIZK proofs of knowledge for DL21.
 */
typedef spk_dlog_t dl21_proof_t;

/** 
 * @fn struct groupsig_proof_t* dl21_proof_init()
 * @brief Initializes the fields of a DL21 proof.
 *
 * @return A pointer to the allocated proof or NULL if error.
 */
groupsig_proof_t* dl21_proof_init();

/** 
 * @fn int dl21_proof_free(groupsig_proof_t *proof)
 * @brief Frees the alloc'ed fields of the given DL21 proof.
 *
 * @param[in,out] proof The proof to free.
 * 
 * @return IOK or IERROR
 */
int dl21_proof_free(groupsig_proof_t *proof);

/** 
 * @fn int dl21_proof_to_string
 * @brief Returns a printable string representing the current proof.
 *
 * @param[in] proof The proof to print.
 * 
 * @return IOK or IERROR
 */
char* dl21_proof_to_string(groupsig_proof_t *proof);
  
/** 
 * @fn int dl21_proof_get_size_in_format(groupsig_proof_t *proof)
 * @brief Returns the size of the proof as an array of bytes.
 *
 * @param[in] proof The proof.
 * 
 * @return -1 if error, the size that this proof would have in case of
 *  being exported to an array of bytes.
 */
int dl21_proof_get_size(groupsig_proof_t *proof);

/** 
 * @fn int dl21_proof_copy(groupsig_proof_t *dst, 
 *                            groupsig_proof_t *src)
 * @brief Copies the given source proof into the destination proof.
 *
 * @param[in,out] dst The destination proof. Initialized by the caller.
 * @param[in] src The proof to copy. 
 * 
 * @return IOK or IERROR.
 */
int dl21_proof_copy(groupsig_proof_t *dst, groupsig_proof_t *src);

/** 
 * @fn int dl21_proof_export(byte_t **bytes, uint32_t *size, groupsig_proof_t *proof);
 * @brief Writes a bytearray representation of the given signature, with format
 *  | DL21_CODE | size_proof | proof |
 *
 * @param[in,out] bytes A pointer to the array that will contain the exported 
 *  proof. If <i>*bytes</i> is NULL, memory will be internally allocated.
 * @param[in,out] size Will be set to the number of bytes written in <i>*bytes</i>.
 * @param[in] proof The proof to export.
 * 
 * @return IOK or IERROR with errno updated.
 */
int dl21_proof_export(byte_t **bytes, uint32_t *size, groupsig_proof_t *proof);
  
/** 
 * @fn int dl21_proof_import(byte_t *source, uint32_t size)
 * @brief Imports a DL21 link proof.
 *
 * Imports a DL21 open proof from the specified array of bytes.
 *
 * @param[in] source The array of bytes containing the proof to import.
 * @param[in] size The number of bytes in <i>source</i>.
 * 
 * @return A pointer to the imported proof, or NULL if error.
 */
groupsig_proof_t* dl21_proof_import(byte_t *source, uint32_t size);

/**
 * @var dl21_proof_handle
 * @brief Set of functions to manage DL21 proofs.
 */
static const groupsig_proof_handle_t dl21_proof_handle = {
  .scheme = GROUPSIG_DL21_CODE, /**< The scheme code. */
  .init = &dl21_proof_init, /**< Initalizes proofs. */
  .free = &dl21_proof_free, /**< Frees proofs. */
  .copy = &dl21_proof_copy, /**< Copies proofs. */
  .get_size = &dl21_proof_get_size, /**< Gets the size of a proof as a byte array. */
  .gexport = &dl21_proof_export, /**< Exports proofs. */
  .gimport = &dl21_proof_import, /**< Imports proofs. */
  .to_string = &dl21_proof_to_string /**< Gets printable representations of proofs. */
};

#endif /* _DL21_PROOF_H */

/* proof.h ends here */
