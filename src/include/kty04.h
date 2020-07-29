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

#ifndef _KTY04_H
#define _KTY04_H

#include "key.h"
#include "gml.h"
#include "crl.h"
#include "signature.h"
#include "proof.h"
#include "grp_key.h"
#include "mgr_key.h"
#include "mem_key.h"
#include "groupsig.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @def GROUPSIG_KTY04_CODE
 * @brief KTY04 scheme code.
 */
#define GROUPSIG_KTY04_CODE 0

/**
 * @def GROUPSIG_KTY04_NAME
 * @brief KTY04 scheme name.
 */
#define GROUPSIG_KTY04_NAME "KTY04"

/** 
 * @def KTY04_SUPPORTED_KEY_FORMATS_N
 * @brief Number of supported key formats supported by KTY04.
 */
#define KTY04_SUPPORTED_KEY_FORMATS_N 6

/**
 * @var KTY04_SUPPORTED_KEY_FORMATS
 * @brief Codes of the key formats supported by KTY04.
 */
static const int KTY04_SUPPORTED_KEY_FORMATS[KTY04_SUPPORTED_KEY_FORMATS_N] = { 
  GROUPSIG_KEY_FORMAT_FILE_NULL,
  GROUPSIG_KEY_FORMAT_FILE_NULL_B64,
  GROUPSIG_KEY_FORMAT_BYTEARRAY,
  GROUPSIG_KEY_FORMAT_STRING_NULL_B64,
  GROUPSIG_KEY_FORMAT_MESSAGE_NULL,
  GROUPSIG_KEY_FORMAT_MESSAGE_NULL_B64,
};

/**
 * @var kty04_description
 * @brief KTY04's description.
 */
static const groupsig_description_t kty04_description = {
  GROUPSIG_KTY04_CODE, /**< KTY04's scheme code. */
  GROUPSIG_KTY04_NAME /**< KTY04's scheme name. */
};

/** 
 * @struct kty04_config_t
 * @brief The configuration information for the KTY04 scheme.
 */
typedef struct {
  uint64_t security; /**< Security parameter. */
  uint64_t primesize; /**< Size of the Sophie Germain primes to be generated. */
  double epsilon; /**< Epsilon parameter. Controls de statistical indistinguishability
		     of the generated proofs. */
} kty04_config_t;

/* Metadata for the join protocol */

/* 0 means the first message is sent by the manager, 1 means the first message
   is sent by the member */
#define KTY04_JOIN_START 1

/* Number of exchanged messages */
#define KTY04_JOIN_SEQ 1

#define KTY04_DEFAULT_SECURITY 10
#define KTY04_DEFAULT_PRIMESIZE 256 // Actually, we set primesize/4
#define KTY04_DEFAULT_EPSILON 2

#define KTY04_CONFIG_SET_DEFAULTS(cfg)		\
  ((kty04_config_t *) cfg)->security = KTY04_DEFAULT_SECURITY;	\
  ((kty04_config_t *) cfg)->primesize = KTY04_DEFAULT_PRIMESIZE;\
  ((kty04_config_t *) cfg)->epsilon = KTY04_DEFAULT_EPSILON;

/** 
 * @fn groupsig_config_t* kty04_config_init(void)
 * @brief Allocates memory for a KTY04 config structure.
 * 
 * @return A pointer to the allocated structure or NULL if error.
 */
groupsig_config_t* kty04_config_init(void);

/** 
 * @fn int kty04_config_free(groupsig_config_t *cfg)
 * @brief Frees the memory of a KTY04 config structure.
 * 
 * @param cfg The structure to free.
 *
 * @return A pointer to the allocated structure or NULL if error.
 */
int kty04_config_free(groupsig_config_t *cfg);

/** 
 * @fn int kty04_setup(groupsig_key_t *grpkey, groupsig_key_t *mgrkey, 
 *                     gml_t *gml, groupsig_config_t *config)
 * @brief The setup function for the KTY04 scheme.
 *
 * @param[in,out] grpkey An initialized group key, will be updated with the newly
 *   created group's group key.
 * @param[in,out] mgrkey An initialized manager key, will be updated with the
 *   newly created group's manager key.
 * @param[in,out] gml An initialized GML, will be set to an empty GML.
 * @param[in] config A KTY04 configuration structure.
 * 
 * @return IOK or IERROR.
 */
int kty04_setup(groupsig_key_t *grpkey, groupsig_key_t *mgrkey, gml_t *gml, groupsig_config_t *config);

/**
 * @fn int kty04_get_joinseq(uint8_t *seq)
 * @brief Returns the number of messages to be exchanged in the join protocol.
 * 
 * @param seq A pointer to store the number of messages to exchange.
 *
 * @return IOK or IERROR.
 */ 
int kty04_get_joinseq(uint8_t *seq);

/**
 * @fn int kty04_get_joinstart(uint8_t *start)
 * @brief Returns who sends the first message in the join protocol.
 * 
 * @param start A pointer to store the who starts the join protocol. 0 means
 *  the Manager starts the protocol, 1 means the Member starts the protocol.
 *
 * @return IOK or IERROR.
 */ 
int kty04_get_joinstart(uint8_t *start);

/** 
 * @fn int kty04_join_mem(void **mout, groupsig_key_t *memkey,
 *			      int seq, void *min, groupsig_key_t *grpkey)
 * @brief Executes the member-side join of the KTY04 scheme.
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
int kty04_join_mem(void **mout, groupsig_key_t *memkey,
		   int seq, void *min, groupsig_key_t *grpkey);

/** 
 * @fn int kty04_join_mgr(void **mout, gml_t *gml,
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
int kty04_join_mgr(void **mout, gml_t *gml,
		   groupsig_key_t *mgrkey,
		   int seq, void *min,
		   groupsig_key_t *grpkey);

/** 
 * @fn int kty04_sign(groupsig_signature_t *sig, message_t *msg, groupsig_key_t *memkey, 
 *	              groupsig_key_t *grpkey, unsigned int seed)
 * @brief Issues KTY04 group signatures.
 *
 * Using the specified member and group keys, issues a signature for the specified
 * message.
 *
 * @param[in,out] sig An initialized KTY04 group signature. Will be updated with
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
int kty04_sign(groupsig_signature_t *sig, message_t *msg, groupsig_key_t *memkey, 
	       groupsig_key_t *grpkey, unsigned int seed);

/** 
 * @fn int kty04_verify(uint8_t *ok, groupsig_signature_t *sig, message_t *msg, 
 *		        groupsig_key_t *grpkey);
 * @brief Verifies a KTY04 group signature.
 *
 * @param[in,out] ok Will be set to 1 if the verification succeeds, to 0 if
 *  it fails.
 * @param[in] sig The signature to verify.
 * @param[in] msg The corresponding message.
 * @param[in] grpkey The group key.
 * 
 * @return IOK or IERROR.
 */
int kty04_verify(uint8_t *ok, groupsig_signature_t *sig, message_t *msg, 
		 groupsig_key_t *grpkey);

/** 
 * @fn int kty04_open(identity_t *id, groupsig_proof_t *proof, crl_t *crl, groupsig_signature_t *sig,  
 *	              groupsig_key_t *grpkey, groupsig_key_t *mgrkey, gml_t *gml)
 * @brief Opens a KTY04 group signature.
 * 
 * Opens the specified group signature, obtaining the signer's identity.
 *
 * @param[in,out] id An initialized identity. Will be updated with the signer's
 *  real identity.
 * @param[in,out] proof KTY04 ignores this parameter.
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
int kty04_open(identity_t *id, groupsig_proof_t *proof, crl_t *crl, 
	       groupsig_signature_t *sig, groupsig_key_t *grpkey, 
	       groupsig_key_t *mgrkey, gml_t *gml);

/** 
 * @fn int kty04_reveal(trapdoor_t *trap, crl_t *crl, gml_t *gml, uint64_t index)
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
 *  In KTY04, this matches the real identity of the group members.
 * 
 * @return IOK or IERROR.
 */
int kty04_reveal(trapdoor_t *trap, crl_t *crl, gml_t *gml, uint64_t index);

/** 
 * @fn int kty04_trace(uint8_t *ok, groupsig_signature_t *sig, 
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
 * @param[in] mgrkey Ignored.
 * @param[in] gml Ignored.
 * 
 * @return IOK or IERROR.
 */
int kty04_trace(uint8_t *ok, groupsig_signature_t *sig, groupsig_key_t *grpkey, 
		crl_t *crl, groupsig_key_t *mgrkey, gml_t *gml);

/** 
 * @fn int kty04_claim(groupsig_proof_t *proof, groupsig_key_t *memkey, 
 *		       groupsig_key_t *grpkey, groupsig_signature_t *sig)
 * @brief Issues a proof demonstrating that the member with the specified key is
 *  the issuer of the specified signature.
 * 
 * @param[in,out] proof An initialized KTY04 proof. Will be updated with the
 *  contents of the proof.
 * @param[in] memkey The member key of the issuer of the <i>sig</i> parameter.
 * @param[in] grpkey The group key.
 * @param[in] sig The signature.
 * 
 * @return IOK or IERROR.
 */
int kty04_claim(groupsig_proof_t *proof, groupsig_key_t *memkey, 
		groupsig_key_t *grpkey, groupsig_signature_t *sig);

/** 
 * @fn int kty04_claim_verify(uint8_t *ok, groupsig_proof_t *proof, 
 *		              groupsig_signature_t *sig, groupsig_key_t *grpkey)
 * @brief Verifies a claim produced by the function <i>kty04_claim</i>.
 *
 * @param[in,out] ok Will be set to 1 if the proof is correct, to 0 otherwise.
 * @param[in] proof The proof to verify.
 * @param[in] sig The signature associated to the proof.
 * @param[in] grpkey The group key.
 * 
 * @return IOK or IERROR.
 */
int kty04_claim_verify(uint8_t *ok, groupsig_proof_t *proof, 
		       groupsig_signature_t *sig, groupsig_key_t *grpkey);

/** 
 * @fn int kty04_prove_equality(groupsig_proof_t *proof, groupsig_key_t *memkey, 
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
int kty04_prove_equality(groupsig_proof_t *proof, groupsig_key_t *memkey, 
			 groupsig_key_t *grpkey, groupsig_signature_t **sigs, uint16_t n_sigs);

/** 
 * @fn int kty04_prove_equality_verify(uint8_t *ok, groupsig_proof_t *proof, 
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
int kty04_prove_equality_verify(uint8_t *ok, groupsig_proof_t *proof, groupsig_key_t *grpkey,
				groupsig_signature_t **sigs, uint16_t n_sigs);

/**
 * @var kty04_groupsig_bundle
 * @brief The set of functions to manage KTY04 groups.
 */
static const groupsig_t kty04_groupsig_bundle = {
  &kty04_description, /**< Contains the KTY04 scheme description. */
  &kty04_config_init, /**< Initializes a KTY04 config structure. */
  &kty04_config_free, /**< Frees a KTY04 config structure. */
  NULL, /**< KYT04 does not have (yet) specific environment info. */
  NULL, /**< KYT04 does not have (yet) specific environment info. */
  NULL, /**< KYT04 does not have (yet) specific environment info. */
  &kty04_setup, /**< Sets up KTY04 groups. */
  &kty04_get_joinseq, /**< Returns the number of messages in the join 
			    protocol. */
  &kty04_get_joinstart, /**< Returns who begins the join protocol. */
  &kty04_join_mem, /**< Executes member-side joins. */
  &kty04_join_mgr, /**< Executes manager-side joins. */
  &kty04_sign, /**< Issues KTY04 signatures. */
  &kty04_verify, /**< Verifies KTY04 signatures. */
  &kty04_open, /**< Opens KTY04 signatures. */
  NULL, /**< KTY04 does not create proofs of opening. */
  &kty04_reveal, /**< Reveals the tracing trapdoor from KTY04 signatures. */
  &kty04_trace, /**< Traces the issuer of a signature. */ 
  &kty04_claim, /**< Claims, in ZK, "ownership" of a signature. */
  &kty04_claim_verify, /**< Verifies claims. */
  &kty04_prove_equality, /**< Issues "same issuer" ZK proofs for several signatures. */
  &kty04_prove_equality_verify, /**< Verifies "same issuer" ZK proofs. */
  NULL, /**< KTY04 does not provide blinding. */
  NULL, /**< KTY04 does not provide conversion. */
  NULL, /**< KTY04 does not provide unblinding. */
};

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif
  
#endif /* _KTY04_H */

/* kty04.h ends here */
