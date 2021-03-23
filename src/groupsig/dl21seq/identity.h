/*                               -*- Mode: C -*- 
 *
 *	libgroupsig Group Signatures library
 *	Copyright (C) 2012-2013 Jesus Diaz Vico
 *
 *		
 *
 *	This file is part of the libgroupsig Group Signatures library.
 *
 *
 *  The libgroupsig library is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License as 
 *  defined by the Free Software Foundation, either version 3 of the License, 
 *  or any later version.
 *
 *  The libroupsig library is distributed WITHOUT ANY WARRANTY; without even 
 *  the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
 *  See the GNU Lesser General Public License for more details.
 *
 *
 *  You should have received a copy of the GNU Lesser General Public License 
 *  along with Group Signature Crypto Library.  If not, see <http://www.gnu.org/
 *  licenses/>
 *
 * @file: identity.h
 * @brief: DL21SEQ identities.
 * @author: jesus
 * Maintainer: jesus
 * @date: jue ene 17 11:16:11 2013 (+0100)
 * @version: 0.1
 * Last-Updated: lun ago  5 11:55:32 2013 (+0200)
 *           By: jesus
 *     Update #: 2
 * URL: bitbucket.org/jdiazvico/libgroupsig
 * @todo Identities should be made independent of group signature schemes, in 
 * order to allow different schemes to share the same identity implementation.
 */

#ifndef _DL21SEQ_IDENTITY_H
#define _DL21SEQ_IDENTITY_H

#include "include/identity.h"
#include "dl21seq.h"
#include "shim/pbc_ext.h"

/**
 * BBS+ signatures used by DL21SEQ
 * They are membership credentials, which can be seen as a kind of identity.
 * Hence, I define them here.
 */
typedef struct _dl21seq_cred_t {
  pbcext_element_G1_t *A; /* A component of the credential */
  pbcext_element_Fr_t *x; /* x component of the credential */
  pbcext_element_Fr_t *s; /* s component of the credential */
} dl21seq_cred_t;

/**
 * DL21SEQ identities.
 */
typedef pbcext_element_G1_t dl21seq_identity_t;

/** 
 * @fn void* dl21seq_identity_init()
 * @brief Allocates memory for a DL21SEQ identity and sets its values to defaults.
 * 
 * @return A pointer to the allocated memory or NULL if error.
 */
identity_t* dl21seq_identity_init();

/** 
 * @fn int dl21seq_identity_free(void *id)
 * @brief Frees the memory allocated for a DL21SEQ identity.
 *
 * @param[in,out] id The identity to free.
 * 
 * @return IOK.
 */
int dl21seq_identity_free(identity_t *id);

/** 
 * @fn int dl21seq_identity_copy(identity_t *dst, identity_t *src)
 * @brief Copies the source identity into the destination identity.
 *
 * @param[in,out] dst The destination identity. Initialized by the caller.
 * @param[in] src The source identity.
 * 
 * @return IOK or IERROR.
 */
int dl21seq_identity_copy(identity_t *dst, identity_t *src);

/** 
 * @fn uint8_t dl21seq_identity_cmp(identity_t *id1, identity_t *id2);
 * @brief Returns 0 if both ids are the same, != 0 otherwise.
 *
 * @param[in] id1 The first id to compare. 
 * @param[in] id2 The second id to compare.
 * 
 * @return 0 if both ids are the same, != otherwise. In case of error,
 *  errno is set consequently.
 */
uint8_t dl21seq_identity_cmp(identity_t *id1, identity_t *id2);

/** 
 * @fn char* dl21seq_identity_to_string(identity_t *id)
 * @brief Converts the given DL21SEQ id into a printable string.
 *
 * @param[in] id The ID to convert.
 * 
 * @return A pointer to the produced string or NULL if error.
 */
char* dl21seq_identity_to_string(identity_t *id);

/** 
 * @fn identity_t* dl21seq_identity_from_string(char *sid)
 * @brief Parses the given string as  DL21SEQ identity.
 *
 * @param[in] sid The string containing the DL21SEQ identity.
 * 
 * @return A pointer to the retrieved DL21SEQ identity or NULL if error.
 */
identity_t* dl21seq_identity_from_string(char *sid);

/**
 * @var dl21seq_identity_handle
 * @brief Set of functions to manage DL21SEQ identities.
 */
static const identity_handle_t dl21seq_identity_handle = {
  GROUPSIG_DL21SEQ_CODE, /**< Scheme code. */
  &dl21seq_identity_init, /**< Identity initialization. */
  &dl21seq_identity_free, /**< Identity free.*/
  &dl21seq_identity_copy, /**< Copies identities. */
  &dl21seq_identity_cmp, /**< Compares identities. */
  &dl21seq_identity_to_string, /**< Converts identities to printable strings. */
  &dl21seq_identity_from_string /**< Imports identities from strings. */
};

#endif /* _DL21SEQ_IDENTITY_H */

/* identity.h ends here */
