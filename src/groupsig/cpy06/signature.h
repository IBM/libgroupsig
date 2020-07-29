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

#ifndef _CPY06_SIGNATURE_H
#define _CPY06_SIGNATURE_H

#include <stdint.h>
#include <pbc/pbc.h>
#include "include/signature.h"
#include "bigz.h"
#include "cpy06.h"

/**
 * @def CPY06_SUPPORTED_SIG_FORMATS_N
 * @brief Number of supported signature formats in CPY06.
 */
#define CPY06_SUPPORTED_SIG_FORMATS_N 6

/**
 * @var CPY06_SUPPORTED_SIG_FORMATS
 * @brief List of supported signature formats in CPY06.
 */
static const int CPY06_SUPPORTED_SIG_FORMATS[CPY06_SUPPORTED_SIG_FORMATS_N] = { 
  GROUPSIG_SIGNATURE_FORMAT_FILE_NULL,
  GROUPSIG_SIGNATURE_FORMAT_FILE_NULL_B64,
  GROUPSIG_SIGNATURE_FORMAT_BYTEARRAY,
  GROUPSIG_SIGNATURE_FORMAT_STRING_NULL_B64,
  GROUPSIG_SIGNATURE_FORMAT_MESSAGE_NULL,
  GROUPSIG_SIGNATURE_FORMAT_MESSAGE_NULL_B64,
};

/**
 * @struct cpy06_signature_t
 * @brief Defines the structure of a CPY06 signature.
 */
typedef struct {
  uint8_t scheme; /**< Metainformation: the gs scheme this key belongs to. */
  /* pbc_param_t param; /\**< PBC parameters. *\/ */
  /* pairing_t pairing; /\**< PBC pairing data. *\/ */
  element_t T1;
  element_t T2;
  element_t T3;
  element_t T4;
  element_t T5;
  element_t c;
  element_t sr1;
  element_t sr2;
  element_t sd1;
  element_t sd2;
  element_t sx;
  element_t st;
} cpy06_signature_t;

/** 
 * @fn groupsig_signature_t* cpy06_signature_init()
 * @brief Initializes the fields of a CPY06 signature.
 * 
 * @return A pointer to the allocated signature, or NULL if error.
 */
groupsig_signature_t* cpy06_signature_init();

/** 
 * @fn int cpy06_signature_free(groupsig_signature_t *sig)
 * @brief Frees the alloc'ed fields of the given CPY06 signature.
 *
 * @param[in,out] sig The signature to free.
 * 
 * @return IOK or IERROR
 */
int cpy06_signature_free(groupsig_signature_t *sig);

/** 
 * @fn int cpy06_signature_copy(groupsig_signature_t *dst, 
 *                              groupsig_signature_t *src)
 * @brief Copies the given source signature into the destination signature.
 *
 * @param[in,out] dst The destination signature. Initialized by the caller.
 * @param[in] src The signature to copy. 
 * 
 * @return IOK or IERROR.
 */
int cpy06_signature_copy(groupsig_signature_t *dst, groupsig_signature_t *src);

/** 
 * @fn int cpy06_signature_to_string(groupsig_signature_t *sig)
 * @brief Returns a printable string representing the current signature.
 *
 * @param[in] sig The signature o convert.
 * 
 * @return A pointer to the created string or NULL if error.
 */
char* cpy06_signature_to_string(groupsig_signature_t *sig);

/** 
 * @fn int cpy06_signature_get_size_in_format(groupsig_signature_t *sig, 
 *   groupsig_signature_format_t format)
 * Returns the size of the signature in the specified format. Useful when you have
 * to export the signature and pre-allocate the destination.
 *
 * @param[in] sig The signature.
 * @param[in] format The format.
 * 
 * @return -1 if error, the size that this signature would have in case of
 *  being exported to the specified format.
 */
int cpy06_signature_get_size_in_format(groupsig_signature_t *sig, 
				       groupsig_signature_format_t format);

/** 
 * @fn int cpy06_signature_export(groupsig_signature *signature,
 *                                groupsig_signature_format_t format,
 *                                void *dst)
 * @brief Exports the specified signature to the given destination using
 *  the specified format..
 *
 * @param[in] signature The signature to export.
 * @param[in] format The format to use.
 * @param[in,out] dst Details about the destination. Will depend on the
 *  specified parameter.
 * 
 * @return IOK or IERROR
 */
int cpy06_signature_export(groupsig_signature_t *signature, 
			   groupsig_signature_format_t format, 
			   void *dst);

/** 
 * @fn groupsig_signature_t* cpy06_signature_import(cpy06_groupsig_signature_format_t format, 
 *                                            void *source)
 * @brief Imports a signature according to the specified format.
 *
 * @param[in] format The format of the signature to import.
 * @param[in] source The signature to be imported.
 * 
 * @return A pointer to the imported signature.
 */
groupsig_signature_t* cpy06_signature_import(groupsig_signature_format_t format, void *source);

/**
 * @var cpy06_signature_handle
 * @brief Set of functions for managing CPY06 signatures.
 */
static const groupsig_signature_handle_t cpy06_signature_handle = {
  GROUPSIG_CPY06_CODE, /**< The scheme code. */
  &cpy06_signature_init,  /**< Initializes signatures. */
  &cpy06_signature_free, /**< Frees signatures. */
  &cpy06_signature_copy, /**< Copies signatures. */
  &cpy06_signature_get_size_in_format, /**< Gets the size in bytes of a signature
					  in a specific format. */
  &cpy06_signature_export, /**< Exports signatures. */
  &cpy06_signature_import, /**< Imports signatures. */
  &cpy06_signature_to_string, /**< Converts signatures to printable strings. */
};

#endif

/* signature.h ends here */
