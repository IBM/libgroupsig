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

#ifndef _PS16_H
#define _PS16_H

#include "key.h"
#include "gml.h"
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
 * @def GROUPSIG_PS16_CODE
 * @brief PS16 scheme code.
 */
#define GROUPSIG_PS16_CODE 4

/**
 * @def GROUPSIG_PS16_NAME
 * @brief PS16 scheme name.
 */
#define GROUPSIG_PS16_NAME "PS16"

/**
 * @var ps16_description
 * @brief PS16's description.
 */
static const groupsig_description_t ps16_description = {
  GROUPSIG_PS16_CODE, /**< PS16's scheme code. */
  GROUPSIG_PS16_NAME, /**< PS16's scheme name. */
  1, /**< PS16 has a GML. */
  0, /**< PS16 does not have a CRL. */
  1, /**< PS16 uses PBC. */
  1, /**< PS16 has verifiable openings. */
  1, /**< PS16's issuer key is the first manager key. */
  0 /**< PS16 relies only on GML for opening. */
};

/* Metadata for the join protocol */

/* 0 means the first message is sent by the manager, 1 means the first message
   is sent by the member */
#define PS16_JOIN_START 0

/* Number of exchanged messages */
#define PS16_JOIN_SEQ 3

/** 
 * @fn int ps16_init()
 * @brief Initializes the internal variables needed by PS16. In this case,
 *  it only sets up the pairing module.
 *
 * @return IOK or IERROR.
 */  
int ps16_init();

/** 
 * @fn int ps16_clear()
 * @brief Frees the memory initialized by ps16_init.
 *
 * @return IOK or IERROR.
 */   
int ps16_clear();

/** 
 * @fn int ps16_setup(groupsig_key_t *grpkey, 
 *                    groupsig_key_t *mgrkey, 
 *                    gml_t *gml)
 * @brief The setup function for the PS16 scheme.
 *
 * @param[in,out] grpkey An initialized group key, will be updated with the newly
 *   created group's group key.
 * @param[in,out] mgrkey An initialized manager key, will be updated with the
 *   newly created group's manager key.
 * @param[in,out] gml An initialized GML, will be set to an empty GML.
 * 
 * @return IOK or IERROR.
 */
int ps16_setup(groupsig_key_t *grpkey,
	       groupsig_key_t *mgrkey,
	       gml_t *gml);

/**
 * @fn int ps16_get_joinseq(uint8_t *seq)
 * @brief Returns the number of messages to be exchanged in the join protocol.
 * 
 * @param seq A pointer to store the number of messages to exchange.
 *
 * @return IOK or IERROR.
 */ 
int ps16_get_joinseq(uint8_t *seq);

/**
 * @fn int ps16_get_joinstart(uint8_t *start)
 * @brief Returns who sends the first message in the join protocol.
 * 
 * @param start A pointer to store the who starts the join protocol. 0 means
 *  the Manager starts the protocol, 1 means the Member starts the protocol.
 *
 * @return IOK or IERROR.
 */ 
int ps16_get_joinstart(uint8_t *start);

/** 
 * @fn int ps16_join_mem(message_t **mout, 
 *                       groupsig_key_t *memkey,
 *			 int seq, 
 *                       message_t *min, 
 *                       groupsig_key_t *grpkey)
 * @brief Executes the member-side join of the PS16 scheme.
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
int ps16_join_mem(message_t **mout,
		  groupsig_key_t *memkey,
		   int seq,
		  message_t *min,
		  groupsig_key_t *grpkey);

/** 
 * @fn int ps16_join_mgr(message_t **mout, 
 *                       gml_t *gml,
 *                       groupsig_key_t *mgrkey,
 *                       int seq, 
 *                       message_t *min, 
 *			 groupsig_key_t *grpkey)
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
int ps16_join_mgr(message_t **mout,
		  gml_t *gml,
		  groupsig_key_t *mgrkey,
		  int seq,
		  message_t *min,
		  groupsig_key_t *grpkey);

/** 
 * @fn int ps16_sign(groupsig_signature_t *sig,
 *                   message_t *msg, 
 *                   groupsig_key_t *memkey, 
 *	             groupsig_key_t *grpkey, 
 *                   unsigned int seed)
 * @brief Issues PS16 group signatures.
 *
 * Using the specified member and group keys, issues a signature for the specified
 * message.
 *
 * @param[in,out] sig An initialized PS16 group signature. Will be updated with
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
int ps16_sign(groupsig_signature_t *sig,
	      message_t *msg,
	      groupsig_key_t *memkey, 
	      groupsig_key_t *grpkey,
	      unsigned int seed);

/** 
 * @fn int ps16_verify(uint8_t *ok, 
 *                     groupsig_signature_t *sig, 
 *                     message_t *msg, 
 *		       groupsig_key_t *grpkey);
 * @brief Verifies a PS16 group signature.
 *
 * @param[in,out] ok Will be set to 1 if the verification succeeds, to 0 if
 *  it fails.
 * @param[in] sig The signature to verify.
 * @param[in] msg The corresponding message.
 * @param[in] grpkey The group key.
 * 
 * @return IOK or IERROR.
 */
int ps16_verify(uint8_t *ok,
		groupsig_signature_t *sig,
		message_t *msg, 
		groupsig_key_t *grpkey);

/** 
 * @fn int ps16_open(uint64_t *index, groupsig_proof_t *proof, crl_t *crl, 
 *                    groupsig_signature_t *sig, groupsig_key_t *grpkey, 
 *	              groupsig_key_t *mgrkey, gml_t *gml)
 * @brief Opens a PS16 group signature.
 * 
 * Opens the specified group signature, obtaining the signer's identity.
 *
 * @param[in,out] index Will be updated with the signer's index in the GML.
 * @param[in,out] proof PS16 ignores this parameter.
 * @param[in,out] crl Unused. Ignore.
 * @param[in] sig The signature to open.
 * @param[in] grpkey The group key.
 * @param[in] mgrkey The manager's key.
 * @param[in] gml The GML.
 * 
 * @return IOK if it was possible to open the signature. IFAIL if the open
 *  trapdoor was not found, IERROR otherwise.
 */
int ps16_open(uint64_t *index,
	      groupsig_proof_t *proof,
	      crl_t *crl,
	      groupsig_signature_t *sig,
	      groupsig_key_t *grpkey,
	      groupsig_key_t *mgrkey,
	      gml_t *gml);

/** 
 * @fn int ps16_open_verify(uint8_t *ok,
 *                          groupsig_proof_t *proof, 
 *                          groupsig_signature_t *sig,
 *                          groupsig_key_t *grpkey)
 * 
 * @param[in,out] ok Will be set to 1 if the proof is correct, to 0 otherwise.
 *  signature.
 * @param[in] id The identity produced by the open algorithm. Unused. Can be NULL.
 * @param[in] proof The proof of opening.
 * @param[in] sig The group signature associated to the proof.
 * @param[in] grpkey The group key.
 * 
 * @return IOK or IERROR
 */
int ps16_open_verify(uint8_t *ok,
		     groupsig_proof_t *proof, 
		     groupsig_signature_t *sig,
		     groupsig_key_t *grpkey);
  
/**
 * @var ps16_groupsig_bundle
 * @brief The set of functions to manage PS16 groups.
 */
static const groupsig_t ps16_groupsig_bundle = {
 desc: &ps16_description, /**< Contains the PS16 scheme description. */
 init: &ps16_init, /**< Initializes the variables needed by PS16. */
 clear: &ps16_clear, /**< Frees the varaibles needed by PS16. */
 setup: &ps16_setup, /**< Sets up PS16 groups. */
 get_joinseq: &ps16_get_joinseq, /**< Returns the number of messages in the join 
				     protocol. */
 get_joinstart: &ps16_get_joinstart, /**< Returns who begins the join protocol. */
 join_mem: &ps16_join_mem, /**< Executes member-side joins. */
 join_mgr: &ps16_join_mgr, /**< Executes manager-side joins. */
 sign: &ps16_sign, /**< Issues PS16 signatures. */
 verify: &ps16_verify, /**< Verifies PS16 signatures. */
 verify_batch: NULL,
 open: &ps16_open, /**< Opens PS16 signatures. */
 open_verify: &ps16_open_verify, /**< Verifies proofs of opening. */
 reveal: NULL,
 trace: NULL,
 claim: NULL,
 claim_verify: NULL,
 prove_equality: NULL,
 prove_equality_verify: NULL,
 blind: NULL,
 convert: NULL,
 unblind: NULL,
 identify: NULL,
 link: NULL,
 verify_link: NULL,
 seqlink: NULL,
 verify_seqlink: NULL
};

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _PS16_H */

/* ps16.h ends here */
