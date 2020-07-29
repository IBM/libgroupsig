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

#ifndef _CPY06_H
#define _CPY06_H

#include <pbc/pbc.h>

#include "key.h"
#include "gml.h"
#include "crl.h"
#include "signature.h"
#include "proof.h"
#include "grp_key.h"
#include "mgr_key.h"
#include "mem_key.h"
#include "groupsig.h"
#include "bigz.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @def GROUPSIG_CPY06_CODE
 * @brief CPY06 scheme code.
 */
#define GROUPSIG_CPY06_CODE 2

/**
 * @def GROUPSIG_CPY06_NAME
 * @brief CPY06 scheme name.
 */
#define GROUPSIG_CPY06_NAME "CPY06"

/**
 * @def CPY06_D_MAX
 * @brief Maximum discriminant for pairing generation.
 */
#define CPY06_D_MAX 1000000000

/* @todo Why are CPY06_SUPPORTED_KEY_FORMATS in the main header file
   but CPY06_SUPPORTED_SIG_FORMATS in the signature.h file!? 
   (key applies to all key types!)
*/

/** 
 * @def CPY06_SUPPORTED_KEY_FORMATS_N
 * @brief Number of supported key formats supported by CPY06.
 */
#define CPY06_SUPPORTED_KEY_FORMATS_N 6

/**
 * @var CPY06_SUPPORTED_KEY_FORMATS
 * @brief Codes of the key formats supported by CPY06.
 */
static const int CPY06_SUPPORTED_KEY_FORMATS[CPY06_SUPPORTED_KEY_FORMATS_N] = { 
  GROUPSIG_KEY_FORMAT_FILE_NULL,
  GROUPSIG_KEY_FORMAT_FILE_NULL_B64,
  GROUPSIG_KEY_FORMAT_BYTEARRAY,
  GROUPSIG_KEY_FORMAT_STRING_NULL_B64,
  GROUPSIG_KEY_FORMAT_MESSAGE_NULL,
  GROUPSIG_KEY_FORMAT_MESSAGE_NULL_B64,
};

/**
 * @var cpy06_description
 * @brief CPY06's description.
 */
static const groupsig_description_t cpy06_description = {
  GROUPSIG_CPY06_CODE, /**< CPY06's scheme code. */
  GROUPSIG_CPY06_NAME /**< CPY06's scheme name. */
};

/**
 * @struct cpy06_genparam_t
 * @brief Structure used for generation of CPY06 pairings.
 */
typedef struct {
  size_t bitlimit; /**< The produced groups will be of order at most 2^bitlimit-1. */
  pbc_param_t param; /**< PBC parameters. */
  bigz_t r; /**< The characteristic of the generated field. */
} cpy06_genparam_t;

/** 
 * @struct cpy06_config_t
 * @brief The configuration information for the CPY06 scheme.
 */
typedef struct {
  unsigned int bitlimit; /**< The order of the created group will be of at 
			    most bitlimit bits. */
} cpy06_config_t;

/* Metadata for the join protocol */

/* 0 means the first message is sent by the manager, 1 means the first message
   is sent by the member */
#define CPY06_JOIN_START 1

/* Number of exchanged messages */
#define CPY06_JOIN_SEQ 1


#define CPY06_DEFAULT_BITLIMIT 160

#define CPY06_CONFIG_SET_DEFAULTS(cfg)		\
  ((cpy06_config_t *) cfg)->bitlimit = CPY06_DEFAULT_BITLIMIT;

/**
 * @struct cpy06_sysenv_t
 * @brief Global information specific to the CPY06 scheme, useful for saving
 *  communications and/or computation costs.
 */
typedef struct {
  pbc_param_t param; /**< The pairing parameters. */
  pairing_t pairing; /**< The pairing. */
} cpy06_sysenv_t;

/** 
 * @fn groupsig_config_t* cpy06_config_init(void)
 * @brief Allocates memory for a CPY06 config structure.
 * 
 * @return A pointer to the allocated structure or NULL if error.
 */
groupsig_config_t* cpy06_config_init(void);

/** 
 * @fn int cpy06_config_free(groupsig_config_t *cfg)
 * @brief Frees the memory of a CPY06 config structure.
 * 
 * @param cfg The structure to free.
 *
 * @return A pointer to the allocated structure or NULL if error.
 */
int cpy06_config_free(groupsig_config_t *cfg);


/** 
 * @fn int cpy06_sysenv_update(void *data)
 * @brief Sets the CPY06 internal environment data, i.e., the PBC params and pairings.
 *
 * @param data A cpy06_sysenv_t structure containing the PBC params and pairings.
 * 
 * @return IOK or IERROR.
 */
int cpy06_sysenv_update(void *data);

/** 
 * @fn void* cpy06_sysenv_get(void)
 * @brief Returns the CPY06 specific environment data.
 * 
 * @return A pointer to the CPY06 specific environment data or NULL if error.
 */
void* cpy06_sysenv_get(void);

/** 
 * @fn int cpy06_sysenv_free(void)
 * @brief Frees the CPY06 internal environment.
 * 
 * @return IOK or IERROR.
 */
int cpy06_sysenv_free(void);

/** 
 * @fn int cpy06_setup(groupsig_key_t *grpkey, groupsig_key_t *mgrkey, 
 *                     gml_t *gml, groupsig_config_t *config)
 * @brief The setup function for the CPY06 scheme.
 *
 * @param[in,out] grpkey An initialized group key, will be updated with the newly
 *   created group's group key.
 * @param[in,out] mgrkey An initialized manager key, will be updated with the
 *   newly created group's manager key.
 * @param[in,out] gml An initialized GML, will be set to an empty GML.
 * @param[in] config A CPY06 configuration structure.
 * 
 * @return IOK or IERROR.
 */
int cpy06_setup(groupsig_key_t *grpkey, groupsig_key_t *mgrkey, gml_t *gml, groupsig_config_t *config);

/**
 * @fn int cpy06_get_joinseq(uint8_t *seq)
 * @brief Returns the number of messages to be exchanged in the join protocol.
 * 
 * @param seq A pointer to store the number of messages to exchange.
 *
 * @return IOK or IERROR.
 */ 
int cpy06_get_joinseq(uint8_t *seq);

/**
 * @fn int cpy06_get_joinstart(uint8_t *start)
 * @brief Returns who sends the first message in the join protocol.
 * 
 * @param start A pointer to store the who starts the join protocol. 0 means
 *  the Manager starts the protocol, 1 means the Member starts the protocol.
 *
 * @return IOK or IERROR.
 */ 
int cpy06_get_joinstart(uint8_t *start);

/** 
 * @fn int cpy06_join_mem(void **mout, groupsig_key_t *memkey,
 *			      int seq, void *min, groupsig_key_t *grpkey)
 * @brief Executes the member-side join of the CPY06 scheme.
 *
 * @param[in,out] mout Message to be produced by the current step of the
 *  join/issue protocol.
 * @param[in,out] memkey An initialized group member key. Must have been
 *  initialized by the caller. Will be set to the final member key once
 *  the join/issue protocol is completed.
 * @param[in] seq The step to run of the join/issue protocol.
 * @param[in] min Input message received from the manager for the current step
 *  of the join/issue protocol.
 * @param[in] grpkey The group key.
 * 
 * @return IOK or IERROR.
 */
int cpy06_join_mem(void **mout, groupsig_key_t *memkey,
		   int seq, void *min, groupsig_key_t *grpkey);

/** 
 * @fn int cpy06_join_mgr(void **mout, gml_t *gml,
 *                            groupsig_key_t *mgrkey,
 *                            int seq, void *min, 
 *			      groupsig_key_t *grpkey)
 * @brief Executes the manager-side join of the join procedure.
 *
 * @param[in,out] mout Message to be produced by the current step of the join/
 *  issue protocol.
 * @param[in,out] gml The group membership list that may be updated with
 *  information related to the new member.
// * @param[in,out] memkey The partial member key to be completed by the group
* @param[in] seq The step to run of the join/issue protocol.
 *  manager.
 * @param[in] min Input message received from the member for the current step of
 *  the join/issue protocol.
 * @param[in] mgrkey The group manager key.
 * @param[in] grpkey The group key.
 * 
 * @return IOK or IERROR.
 */
int cpy06_join_mgr(void **mout, gml_t *gml,
		   groupsig_key_t *mgrkey,
		   int seq, void *min,
		   groupsig_key_t *grpkey);

/** 
 * @fn int cpy06_sign(groupsig_signature_t *sig, message_t *msg, groupsig_key_t *memkey, 
 *	              groupsig_key_t *grpkey, unsigned int seed)
 * @brief Issues CPY06 group signatures.
 *
 * Using the specified member and group keys, issues a signature for the specified
 * message.
 *
 * @param[in,out] sig An initialized CPY06 group signature. Will be updated with
 *  the generated signature data.
 * @param[in] msg The message to sign.
 * @param[in] memkey The member key to use for signing.
 * @param[in] grpkey The group key.
 * @param[in] seed The seed. If it is set to UINT_MAX, the current system PRNG
 *  will be used normally. Otherwise, it will be reseeded with the specified
 *  seed before issuing the signature. 
 * 
 * @return IOK or IERROR.
 */
int cpy06_sign(groupsig_signature_t *sig, message_t *msg, groupsig_key_t *memkey, 
	       groupsig_key_t *grpkey, unsigned int seed);

/** 
 * @fn int cpy06_verify(uint8_t *ok, groupsig_signature_t *sig, message_t *msg, 
 *		        groupsig_key_t *grpkey);
 * @brief Verifies a CPY06 group signature.
 *
 * @param[in,out] ok Will be set to 1 if the verification succeeds, to 0 if
 *  it fails.
 * @param[in] sig The signature to verify.
 * @param[in] msg The corresponding message.
 * @param[in] grpkey The group key.
 * 
 * @return IOK or IERROR.
 */
int cpy06_verify(uint8_t *ok, groupsig_signature_t *sig, message_t *msg, 
		 groupsig_key_t *grpkey);

/** 
 * @fn int cpy06_open(identity_t *id, groupsig_proof_t *proof, 
 *                    crl_t *crl, groupsig_signature_t *sig, 
 *	              groupsig_key_t *grpkey, groupsig_key_t *mgrkey, gml_t *gml)
 * @brief Opens a CPY06 group signature.
 * 
 * Opens the specified group signature, obtaining the signer's identity.
 *
 * @param[in,out] id An initialized identity. Will be updated with the signer's
 *  real identity.
 * @param[in,out] proof CPY06 ignores this parameter.
 * @param[in,out] crl Optional. If not NULL, must be an initialized CRL, and will
 *  be updated with a new entry corresponding to the obtained trapdoor.
 * @param[in] sig The signature to open.
 * @param[in] grpkey The group key.
 * @param[in] mgrkey The manager's key.
 * @param[in] gml The GML.
 *
 * @return IOK if it was possible to open the signature. IFAIL if the open
 *  trapdoor was not found, IERROR otherwise.
 */
int cpy06_open(identity_t *id, groupsig_proof_t *proof, crl_t *crl, 
	       groupsig_signature_t *sig, groupsig_key_t *grpkey, 
	       groupsig_key_t *mgrkey, gml_t *gml);

/** 
 * @fn int cpy06_reveal(trapdoor_t *trap, crl_t *crl, gml_t *gml, uint64_t index)
 * @brief Reveals the tracing trapdoor of the GML entry with the specified index.
 *
 * Reveals the tracing trapdoor of the GML entry with the specified index. If
 * a CRL is also specified, a new entry corresponding to the retrieved trapdoor
 * will be added. 
 *
 * @param[in,out] trap An initialized trapdoor. Will be updated with the trapdoor
 *  associated to the group member with the given index within the GML.
 * @param[in,out] crl Optional. If not NULL, must be an initialized CRL, and will
 *  be updated with a new entry corresponding to the obtained trapdoor.
 * @param[in] gml The GML.
 * @param[in] index The index of the GML from which the trapdoor is to be obtained.
 *  In CPY06, this matches the real identity of the group members.
 * 
 * @return IOK or IERROR.
 */
int cpy06_reveal(trapdoor_t *trap, crl_t *crl, gml_t *gml, uint64_t index);

/** 
 * @fn int cpy06_trace(uint8_t *ok, groupsig_signature_t *sig, 
 *                     groupsig_key_t *grpkey, crl_t *crl,
 *                     groupsig_key_t *mgrkey, gml_t *gml)
 * @brief Determines whether or not the given signature has been issued by a 
 *  (unlinkability) revoked member.
 *
 * If the specified signature has been issued by a group member whose tracing
 * trapdoor is included in the CRL, ok will be set to 1. Otherwise, it will
 * be set to 0.
 *
 * @param[in,out] ok Will be set to 1 if the signature has been issued by a 
 *  group member with revoked unlinkability. To 0 otherwise.
 * @param[in] sig The signature to use for tracing.
 * @param[in] grpkey The group key.
 * @param[in] crl The CRL.
 * @param[in] mgrkey The manager key.
 * @param[in] gml The GML.
 * 
 * @return IOK or IERROR.
 */
int cpy06_trace(uint8_t *ok, groupsig_signature_t *sig, groupsig_key_t *grpkey, 
		crl_t *crl, groupsig_key_t *mgrkey, gml_t *gml);

/** 
 * @fn int cpy06_claim(groupsig_proof_t *proof, groupsig_key_t *memkey, 
 *		       groupsig_key_t *grpkey, groupsig_signature_t *sig)
 * @brief Issues a proof demonstrating that the member with the specified key is
 *  the issuer of the specified signature.
 * 
 * @param[in,out] proof An initialized CPY06 proof. Will be updated with the
 *  contents of the proof.
 * @param[in] memkey The member key of the issuer of the <i>sig</i> parameter.
 * @param[in] grpkey The group key.
 * @param[in] sig The signature.
 * 
 * @return IOK or IERROR.
 */
int cpy06_claim(groupsig_proof_t *proof, groupsig_key_t *memkey, 
		groupsig_key_t *grpkey, groupsig_signature_t *sig);

/** 
 * @fn int cpy06_claim_verify(uint8_t *ok, groupsig_proof_t *proof, 
 *		              groupsig_signature_t *sig, groupsig_key_t *grpkey)
 * @brief Verifies a claim produced by the function <i>cpy06_claim</i>.
 *
 * @param[in,out] ok Will be set to 1 if the proof is correct, to 0 otherwise.
 * @param[in] proof The proof to verify.
 * @param[in] sig The signature associated to the proof.
 * @param[in] grpkey The group key.
 * 
 * @return IOK or IERROR.
 */
int cpy06_claim_verify(uint8_t *ok, groupsig_proof_t *proof, 
		       groupsig_signature_t *sig, groupsig_key_t *grpkey);

/** 
 * @fn int cpy06_prove_equality(groupsig_proof_t *proof, groupsig_key_t *memkey, 
 *			        groupsig_key_t *grpkey, groupsig_signature_t **sigs, 
 *                              uint16_t n_sigs)
 * @brief Creates a proof demonstrating that the given set of group signatures
 *  have all been issued by the same member.
 *
 * @param[in,out] proof An initialized proof. Will be updated with the produced
 *  proof.
 * @param[in] memkey The member key of the issuer of the given set of signatures.
 * @param[in] grpkey The group key.
 * @param[in] sigs The set of signatures, issued by the member with key <i>memkey</i>
 *  to be used for proof generation.
 * @param[in] n_sigs The number of signatures in <i>sigs</i> 
 * 
 * @return IOK or IERROR.
 */
int cpy06_prove_equality(groupsig_proof_t *proof, groupsig_key_t *memkey, 
			 groupsig_key_t *grpkey, groupsig_signature_t **sigs, uint16_t n_sigs);

/** 
 * @fn int cpy06_prove_equality_verify(uint8_t *ok, groupsig_proof_t *proof, 
 *                                     groupsig_key_t *grpkey,
 * 				       groupsig_signature_t **sigs, uint16_t n_sigs)
 * @brief Verifies the received proof, demonstrating that the given set of 
 *  signatures have been issued by the same group member.
 *
 * @param[in,out] ok Will be set to 1 if the proof is correct, to 0 otherwise.
 * @param[in] proof The proof to verify.
 * @param[in] grpkey The group key.
 * @param[in] sigs The signatures that have allegedly been issued by the same member.
 * @param[in] n_sigs The number of signatures in <i>sigs</i>.
 * 
 * @return IOK or IERROR.
 */
int cpy06_prove_equality_verify(uint8_t *ok, groupsig_proof_t *proof, groupsig_key_t *grpkey,
				groupsig_signature_t **sigs, uint16_t n_sigs);

/**
 * @var cpy06_groupsig_bundle
 * @brief The set of functions to manage CPY06 groups.
 */
static const groupsig_t cpy06_groupsig_bundle = {
  &cpy06_description, /**< Contains the CPY06 scheme description. */
  &cpy06_config_init, /**< Initializes a CPY06 config structure. */
  &cpy06_config_free, /**< Frees a CPY06 config structure. */
  &cpy06_sysenv_update, /**< Sets the PBC params and pairing. */
  &cpy06_sysenv_get, /**< Returns the CPY06 specific environment data. */
  &cpy06_sysenv_free, /**<  Frees the PBC params and pairing. */
  &cpy06_setup, /**< Sets up CPY06 groups. */
  &cpy06_get_joinseq, /**< Returns the number of messages in the join 
			    protocol. */
  &cpy06_get_joinstart, /**< Returns who begins the join protocol. */
  &cpy06_join_mem, /**< Executes member-side joins. */
  &cpy06_join_mgr, /**< Executes maanger-side joins. */
  &cpy06_sign, /**< Issues CPY06 signatures. */
  &cpy06_verify, /**< Verifies CPY06 signatures. */
  &cpy06_open, /**< Opens CPY06 signatures. */
  NULL, /**< CPY06 does not create proofs of opening. */
  &cpy06_reveal, /**< Reveals the tracing trapdoor from CPY06 signatures. */
  &cpy06_trace, /**< Traces the issuer of a signature. */ 
  &cpy06_claim, /**< Claims, in ZK, "ownership" of a signature. */
  &cpy06_claim_verify, /**< Verifies claims. */
  &cpy06_prove_equality, /**< Issues "same issuer" ZK proofs for several signatures. */
  &cpy06_prove_equality_verify, /**< Verifies "same issuer" ZK proofs. */
  NULL, /**< CPY06 does not provide blinding. */
  NULL, /**< CPY06 does not provide conversion. */
  NULL, /**< CPY06 does not provide unblinding. */
};

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif
  
#endif /* _CPY06_H */

/* cpy06.h ends here */
