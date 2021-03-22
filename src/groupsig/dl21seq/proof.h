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
 * @file: proof.h
 * @brief: DL21SEQ proofs.
 * @author: jesus
 * Maintainer: jesus
 * @date: lun dic 10 21:24:30 2012 (-0500)
 * @version: 0.1
 * Last-Updated: lun ago  5 11:56:12 2013 (+0200)
 *           By: jesus
 *     Update #: 2
 * URL: bitbucket.org/jdiazvico/libgroupsig
 */

#ifndef _DL21SEQ_PROOF_H
#define _DL21SEQ_PROOF_H

#include <stdint.h>
#include "include/proof.h"
#include "crypto/spk.h"
#include "dl21seq.h"

/**
 * @struct dl21seq_proof_t
 * @brief General NIZK proofs of knowledge for DL21SEQ.
 */
typedef struct {
  spk_dlog_t *spk; /**< Linking proof. */
  byte_t **x; /**< Sequence proof. */
  uint64_t *xlen; /* Length, in bytes, per element of x. */
  uint64_t n; /**< Number of elements in x and xlen. */
} dl21seq_proof_t;

/** 
 * @fn struct groupsig_proof_t* dl21seq_proof_init()
 * @brief Initializes the fields of a DL21SEQ proof.
 *
 * @return A pointer to the allocated proof or NULL if error.
 */
groupsig_proof_t* dl21seq_proof_init();

/** 
 * @fn int dl21seq_proof_free(groupsig_proof_t *proof)
 * @brief Frees the alloc'ed fields of the given DL21SEQ proof.
 *
 * @param[in,out] proof The proof to free.
 * 
 * @return IOK or IERROR
 */
int dl21seq_proof_free(groupsig_proof_t *proof);

/** 
 * @fn int dl21seq_proof_to_string
 * @brief Returns a printable string representing the current proof.
 *
 * @param[in] proof The proof to print.
 * 
 * @return IOK or IERROR
 */
char* dl21seq_proof_to_string(groupsig_proof_t *proof);

/** 
 * @fn int dl21seq_proof_get_size_in_format(groupsig_proof_t *proof)
 * @brief Returns the size of the proof as an array of bytes.
 *
 * @param[in] proof The proof.
 * 
 * @return -1 if error, the size that this proof would have in case of
 *  being exported to an array of bytes.
 */
int dl21seq_proof_get_size(groupsig_proof_t *proof);

/** 
 * @fn int dl21seq_proof_export(byte_t **bytes, uint32_t *size, groupsig_proof_t *proof);
 * @brief Writes a bytearray representation of the given signature, with format
 *  | DL21SEQCODE | size_spk | spk | n (uint64_t) | size_x1 | x1 | ... | 
 *    size_xn | xn |
 *
 * @param[in,out] bytes A pointer to the array that will contain the exported 
 *  proof. If <i>*bytes</i> is NULL, memory will be internally allocated.
 * @param[in,out] size Will be set to the number of bytes written in <i>*bytes</i>.
 * @param[in] proof The proof to export.
 * 
 * @return IOK or IERROR with errno updated.
 */
int dl21seq_proof_export(byte_t **bytes, uint32_t *size, groupsig_proof_t *proof);
  
/** 
 * @fn int dl21seq_proof_import(byte_t *source, uint32_t size)
 * @brief Imports a DL21SEQ link proof.
 *
 * Imports a DL21SEQ open proof from the specified array of bytes.
 *
 * @param[in] source The array of bytes containing the proof to import.
 * @param[in] size The number of bytes in <i>source</i>.
 * 
 * @return A pointer to the imported proof, or NULL if error.
 */
groupsig_proof_t* dl21seq_proof_import(byte_t *source, uint32_t size);

/**
 * @var dl21seq_proof_handle
 * @brief Set of functions to manage DL21SEQ proofs.
 */
static const groupsig_proof_handle_t dl21seq_proof_handle = {
  .scheme = GROUPSIG_DL21SEQ_CODE, /**< The scheme code. */
  .init = &dl21seq_proof_init, /**< Initalizes proofs. */
  .free = &dl21seq_proof_free, /**< Frees proofs. */
  .get_size = &dl21seq_proof_get_size, /**< Gets the size of a proof in bytes. */
  .gexport = &dl21seq_proof_export, /**< Exports proofs. */
  .gimport = &dl21seq_proof_import, /**< Imports proofs. */
  .to_string = &dl21seq_proof_to_string /**< Gets printable representations of proofs. */
};

#endif /* _DL21SEQ_PROOF_H */

/* proof.h ends here */
