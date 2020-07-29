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

#ifndef _GL19_BLINDSIG_H
#define _GL19_BLINDSIG_H

#include <stdint.h>
#include "include/blindsig.h"
#include "bigz.h"
#include "gl19.h"
#include "shim/pbc_ext.h"

/**
 * @struct gl19_blindsig_t
 * @brief Defines the structure of a blinded GL19 signature.
 * Defineme.
 */
typedef struct {
  uint8_t scheme; /**< Metainformation: the gs scheme this key belongs to. */
  pbcext_element_G1_t *nym1;
  pbcext_element_G1_t *nym2;
  pbcext_element_G1_t *nym3;
  pbcext_element_G1_t *c1;
  pbcext_element_G1_t *c2;
} gl19_blindsig_t;

/** 
 * @fn groupsig_blindsig_t* gl19_signature_init()
 * @brief Initializes the fields of a GL19 signature.
 * 
 * @return A pointer to the allocated signature, or NULL if error.
 */
groupsig_blindsig_t* gl19_blindsig_init();

/** 
 * @fn int gl19_blindsig_free(groupsig_blindsig_t *sig)
 * @brief Frees the alloc'ed fields of the given GL19 signature.
 *
 * @param[in,out] sig The signature to free.
 * 
 * @return IOK or IERROR
 */
int gl19_blindsig_free(groupsig_blindsig_t *sig);

/** 
 * @fn int gl19_blindsig_copy(groupsig_blindsig_t *dst, 
 *                              groupsig_blindsig_t *src)
 * @brief Copies the given source signature into the destination signature.
 *
 * @param[in,out] dst The destination signature. Initialized by the caller.
 * @param[in] src The signature to copy. 
 * 
 * @return IOK or IERROR.
 */
int gl19_blindsig_copy(groupsig_blindsig_t *dst, groupsig_blindsig_t *src);

/** 
 * @fn int gl19_blindsig_to_string(groupsig_blindsig_t *sig)
 * @brief Returns a printable string representing the current signature.
 *
 * @param[in] sig The signature o convert.
 * 
 * @return A pointer to the created string or NULL if error.
 */
char* gl19_blindsig_to_string(groupsig_blindsig_t *sig);

/** 
 * @fn int gl19_blindsig_get_size(groupsig_blindsig_t *sig)
 * Returns the size of the signature, in bytes.
 *
 * @param[in] sig The signature.
 * 
 * @return -1 if error, else the size that this signature need to be
 * exported as an array of bytes.
 */
int gl19_blindsig_get_size(groupsig_blindsig_t *sig);

/** 
 * @fn int gl19_blindsig_export(byte_t **bytes,
 *			        uint32_t *size,
 *		       	        groupsig_blindsig_t *sig)
 * @brief Exports the specified signature into an array of bytes.
 * The format will be:
 *
 *    | GL19_CODE | sizeof(nym1) | nym1 | sizeof(nym2) | nym2 | sizeof(nym3) | nym3 | 
 *      sizeof(c1) | c1 | sizeof(c2) | c2 |
 *
 * @param[in,out] bytes A pointer to the array of bytes. If <i>*bytes</i> is NULL,
 *  memory is internally allocated.
 * @param[in,out] size Will be set to the number of bytes written into <i>*bytes</i>.
 * @param[in] signature The blinded group signature to export.
 * 
 * @return IOK or IERROR
 */
int gl19_blindsig_export(byte_t **bytes,
			 uint32_t *size,
			 groupsig_blindsig_t *sig);

/** 
 * @fn groupsig_blindsig_t* gl19_blindsig_import(byte_t *source, uint32_t size)
 * @brief Imports a blinded signature from an array of bytes.
 *
 * @param[in] source The signature to be imported.
 * @param[in] size The number of bytes in <i>source</i>.
 * 
 * @return A pointer to the imported signature, or NUL if error.
 */
groupsig_blindsig_t* gl19_blindsig_import(byte_t *source, uint32_t size);

/**
 * @var gl19_blindsig_handle
 * @brief Set of functions for managing GL19 signatures.
 */
static const groupsig_blindsig_handle_t gl19_blindsig_handle = {
  .scheme = GROUPSIG_GL19_CODE, /**< The scheme code. */
  .init = &gl19_blindsig_init,  /**< Initializes signatures. */
  .free = &gl19_blindsig_free, /**< Frees signatures. */
  .copy = &gl19_blindsig_copy, /**< Copies signatures. */
  .get_size = &gl19_blindsig_get_size, /**< Gets the size in bytes of a signature. */
  .gexport = &gl19_blindsig_export, /**< Exports signatures. */
  .gimport = &gl19_blindsig_import, /**< Imports signatures. */
  .to_string = &gl19_blindsig_to_string, /**< Converts signatures to printable strings. */
};

#endif

/* blindsig.h ends here */
