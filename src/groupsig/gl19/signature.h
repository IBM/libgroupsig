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

#ifndef _GL19_SIGNATURE_H
#define _GL19_SIGNATURE_H

#include <stdint.h>
#include "include/signature.h"
#include "gl19.h"
#include "crypto/spk.h"

/**
 * @struct gl19_signature_t
 * @brief Defines the structure of a GL19 signature.
 */
typedef struct {
  uint8_t scheme; /**< Metainformation: the gs scheme this key belongs to. */
  pbcext_element_G1_t *AA;
  pbcext_element_G1_t *A_;
  pbcext_element_G1_t *d;
  spk_rep_t *pi;
  pbcext_element_G1_t *nym1;
  pbcext_element_G1_t *nym2;
  pbcext_element_G1_t *ehy1;
  pbcext_element_G1_t *ehy2;
  uint64_t expiration; /**< Expiration date. This is metainformation actually 
			  pertaining to the signer's credential. The verify 
			  process checks that the signature was produced by a
			  signer controlling a credential with the corresponding
			  expiration date. */
} gl19_signature_t;

/** 
 * @fn groupsig_signature_t* gl19_signature_init()
 * @brief Initializes the fields of a GL19 signature.
 * 
 * @return A pointer to the allocated signature, or NULL if error.
 */
groupsig_signature_t* gl19_signature_init();

/** 
 * @fn int gl19_signature_free(groupsig_signature_t *sig)
 * @brief Frees the alloc'ed fields of the given GL19 signature.
 *
 * @param[in,out] sig The signature to free.
 * 
 * @return IOK or IERROR
 */
int gl19_signature_free(groupsig_signature_t *sig);

/** 
 * @fn int gl19_signature_copy(groupsig_signature_t *dst, 
 *                             groupsig_signature_t *src)
 * @brief Copies the given source signature into the destination signature.
 *
 * @param[in,out] dst The destination signature. Initialized by the caller.
 * @param[in] src The signature to copy. 
 * 
 * @return IOK or IERROR.
 */
int gl19_signature_copy(groupsig_signature_t *dst, groupsig_signature_t *src);

/** 
 * @fn int gl19_signature_to_string(groupsig_signature_t *sig)
 * @brief Returns a printable string representing the current signature.
 *
 * @param[in] sig The signature o convert.
 * 
 * @return A pointer to the created string or NULL if error.
 */
char* gl19_signature_to_string(groupsig_signature_t *sig);

/** 
 * @fn int gl19_signature_get_size_in_format(groupsig_signature_t *sig)
 * Returns the size of the signature as an array of bytes.
 *
 * @param[in] sig The signature.
 * 
 * @return -1 if error; else, the number of bytes needed to represent the given
 *  signature.
 */
int gl19_signature_get_size(groupsig_signature_t *sig);

/** 
 * @fn int gl19_signature_export(byte_t **bytes,
 *                               uint32_t *size,
 *                               groupsig_signature_t *signature)
 * @brief Exports the specified signature to as an array of bytes, as follows:
 * 
 *    | GL19_CODE | sizeof(AA) | AA | sizeof(A_) | A_ | sizeof(d) | d | 
 *      sizeof(spk) | spk | sizeof(nym1) | nym1 | sizeof(nym2) | nym2 |
 *      expiration (uint64_t) |
 *
 * @param[in,out] bytes A pointer to the array of bytes. If <i>*bytes</i> is NULL,
 *  memory is internally allocated.
 * @param[in,out] size Will be set to the number of bytes written into <i>*bytes</i>.
 * @param[in] signature The group signature to export.
 * 
 * @return IOK or IERROR
 */
int gl19_signature_export(byte_t **bytes,
			  uint32_t *size,
			  groupsig_signature_t *signature);

/** 
 * @fn groupsig_signature_t* gl19_signature_import(byte_t *source,
 *                                                 uint32_t size)
 * @brief Imports a signature according to the specified format.
 *
 * @param[in] source The array of bytes to parse.
 * @param[in] size The number of bytes in <i>source</i>.
 * 
 * @return A pointer to the imported signature, or NULL if error.
 */
groupsig_signature_t* gl19_signature_import(byte_t *source,
					    uint32_t size);

/**
 * @var gl19_signature_handle
 * @brief Set of functions for managing GL19 signatures.
 */
static const groupsig_signature_handle_t gl19_signature_handle = {
  .scheme = GROUPSIG_GL19_CODE, /**< The scheme code. */
  .init = &gl19_signature_init,  /**< Initializes signatures. */
  .free = &gl19_signature_free, /**< Frees signatures. */
  .copy = &gl19_signature_copy, /**< Copies signatures. */
  .get_size = &gl19_signature_get_size, /**< Gets the size in bytes of a signature. */
  .gexport = &gl19_signature_export, /**< Exports signatures. */
  .gimport = &gl19_signature_import, /**< Imports signatures. */
  .to_string = &gl19_signature_to_string, /**< Converts signatures to printable strings. */
};

#endif

/* signature.h ends here */
