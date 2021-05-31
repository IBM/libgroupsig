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

#ifndef _KLAP20_H
#define _KLAP20_H

#include <stdlib.h>

#include "key.h"
#include "gml.h"
#include "crl.h"
#include "signature.h"
#include "proof.h"
#include "bld_key.h"
#include "grp_key.h"
#include "mgr_key.h"
#include "mem_key.h"
#include "groupsig.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @def GROUPSIG_KLAP20_CODE
 * @brief KLAP20 scheme code.
 */
#define GROUPSIG_KLAP20_CODE 5

/**
 * @def GROUPSIG_KLAP20_NAME
 * @brief KLAP20 scheme name.
 */
#define GROUPSIG_KLAP20_NAME "KLAP20"

/**
 * @var klap20_description
 * @brief KLAP20's description.
 */
static const groupsig_description_t klap20_description = {
  GROUPSIG_KLAP20_CODE, /**< KLAP20's scheme code. */
  GROUPSIG_KLAP20_NAME, /**< KLAP20's scheme name. */
  1, /**< KLAP20 has a GML. */
  0, /**< KLAP20 does not have a CRL. */
  1, /**< KLAP20 uses PBC. */
  1,  /**< KLAP20 has verifiable openings. */
  1, /**< KLAP20's issuer key is the first manager key. */
  2 /**< KLAP20's inspector (opener) key is the second manager key. */
};

/* Metadata for the join protocol */

/* 0 means the first message is sent by the manager, 1 means the first message
   is sent by the member */
#define KLAP20_JOIN_START 0

/* Number of exchanged messages */
#define KLAP20_JOIN_SEQ 3

/** 
 * @fn int klap20_init()
 * @brief Initializes the internal variables needed by KLAP20. In this case,
 *  it only sets up the pairing module.
 *
 * @return IOK or IERROR.
 */  
int klap20_init();

/** 
 * @fn int klap20_clear()
 * @brief Frees the memory initialized by klap20_init.
 *
 * @return IOK or IERROR.
 */   
int klap20_clear();  

/** 
 * @fn int klap20_setup(groupsig_key_t *grpkey, 
 *                      groupsig_key_t *mgrkey, 
 *                      gml_t *gml)
 * @brief The setup function for the KLAP20 scheme. Used to generate group public
 *  key and the managers keys.
 * 
 *  In KLAP20, we have two central entities (managers in libgroupsig jargon): the 
 *  Issuer, and the Opener. Both managers have public-private keypairs, their
 *  public parts being a part of the overall group public key. In order to 
 *  properly create the group public key and the manager's keys, we need to call
 *  setup twice. The first time it is called, a partial group public key will be
 *  generated, along with the Issuer's private key (i.e., the Issuer is expected
 *  to initiate this process.) The second call must receive as input the partial
 *  group public key obtained in the first call, and a new manager key. As a
 *  result of the second call, the group public key is completely set up, and the
 *  Opener's private key is also generated. Therefore, this second call is 
 *  expected to be made by the Opener.
 *
 *  To be precise, whenever an empty group public key (i.e., an initialized KLAP20
 *  groupsig_key_t struct, with all fields in the key sub-struct set to NULL), 
 *  is received, the function assumes that this is a first call.
 *
 * @param[in,out] grpkey An initialized group key. In the first call, a partial
 *  group public key will be returned.
 * @param[in,out] mgrkey An initialized manager key. In the first call, it will
 *  be set to the Issuer's private key. In the second call, it will be set to 
 *  the converter's private key..
 * @param[in] gml Ignored.
 * 
 * @return IOK or IERROR.
 */
int klap20_setup(groupsig_key_t *grpkey,
		 groupsig_key_t *mgrkey,
		 gml_t *gml);

/**
 * @fn int klap20_get_joinseq(uint8_t *seq)
 * @brief Returns the number of messages to be exchanged in the join protocol.
 * 
 * @param seq A pointer to store the number of messages to exchange.
 *
 * @return IOK or IERROR.
 */ 
int klap20_get_joinseq(uint8_t *seq);

/**
 * @fn int klap20_get_joinstart(uint8_t *start)
 * @brief Returns who sends the first message in the join protocol.
 * 
 * @param start A pointer to store the who starts the join protocol. 0 means
 *  the Manager starts the protocol, 1 means the Member starts the protocol.
 *
 * @return IOK or IERROR.
 */ 
int klap20_get_joinstart(uint8_t *start);

/** 
* @fn int klap20_join_mem(message_t **mout, groupsig_key_t *memkey,
 *			      int seq, message_t *min, groupsig_key_t *grpkey)
 * @brief Executes the member-side join of the KLAP20 scheme.
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
int klap20_join_mem(message_t **mout,
		    groupsig_key_t *memkey,
		    int seq,
		    message_t *min,
		    groupsig_key_t *grpkey);

/** 
 * @fn int klap20_join_mgr(message_t **mout, 
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
int klap20_join_mgr(message_t **mout,
		  gml_t *gml,
		  groupsig_key_t *mgrkey,
		  int seq,
		  message_t *min,
		  groupsig_key_t *grpkey);

/** 
 * @fn int klap20_sign(groupsig_signature_t *sig, 
 *                   message_t *msg, 
 *                   groupsig_key_t *memkey, 
 *	             groupsig_key_t *grpkey, 
 *                   unsigned int seed)
 * @brief Issues KLAP20 group signatures.
 *
 * Using the specified member and group keys, issues a signature for the specified
 * message.
 *
 * @param[in,out] sig An initialized KLAP20 group signature. Will be updated with
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
int klap20_sign(groupsig_signature_t *sig,
	      message_t *msg,
	      groupsig_key_t *memkey, 
	      groupsig_key_t *grpkey,
	      unsigned int seed);

/** 
 * @fn int klap20_verify(uint8_t *ok, 
 *                     groupsig_signature_t *sig, 
 *                     message_t *msg, 
 *		       groupsig_key_t *grpkey);
 * @brief Verifies a KLAP20 group signature.
 *
 * @param[in,out] ok Will be set to 1 if the verification succeeds, to 0 if
 *  it fails.
 * @param[in] sig The signature to verify.
 * @param[in] msg The corresponding message.
 * @param[in] grpkey The group key.
 * 
 * @return IOK or IERROR.
 */
int klap20_verify(uint8_t *ok,
		groupsig_signature_t *sig,
		message_t *msg, 
		groupsig_key_t *grpkey);

/** 
 * @fn int klap20_verify_batch(uint8_t *ok, 
 *                             groupsig_signature_t **sigs, 
 *                             message_t **msgs, 
 *                             uint32_t n,
 *		               groupsig_key_t *grpkey);
 * @brief Verifies a KLAP20 group signature.
 *
 * @param[in,out] ok Will be set to 1 if the verification succeeds, to 0 if
 *  it fails.
 * @param[in] sigs The signatures to verify.
 * @param[in] msgs The corresponding messagse.
 * @param[in] n The size of the sigs and msgs array.
 * @param[in] grpkey The group key.
 * 
 * @return IOK or IERROR.
 */
int klap20_verify_batch(uint8_t *ok,
			groupsig_signature_t **sigs,
			message_t **msgs,
			uint32_t n,
			groupsig_key_t *grpkey);  

/** 
 * @fn int klap20_open(uint64_t *index, groupsig_proof_t *proof, crl_t *crl, 
 *                    groupsig_signature_t *sig, groupsig_key_t *grpkey, 
 *	              groupsig_key_t *mgrkey, gml_t *gml)
 * @brief Opens a KLAP20 group signature.
 * 
 * Opens the specified group signature, obtaining the signer's identity.
 *
 * @param[in,out] index Will be updated with the signer's index in the GML.
 * @param[in,out] proof KLAP20 ignores this parameter.
 * @param[in,out] crl Unused. Ignore.
 * @param[in] sig The signature to open.
 * @param[in] grpkey The group key.
 * @param[in] mgrkey The manager's key.
 * @param[in] gml The GML.
 * 
 * @return IOK if it was possible to open the signature. IFAIL if the open
 *  trapdoor was not found, IERROR otherwise.
 */
int klap20_open(uint64_t *index,
		groupsig_proof_t *proof,
		crl_t *crl,
		groupsig_signature_t *sig,
		groupsig_key_t *grpkey,
		groupsig_key_t *mgrkey,
		gml_t *gml);

/** 
 * @fn int klap20_open_verify(uint8_t *ok,
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
int klap20_open_verify(uint8_t *ok,
		       groupsig_proof_t *proof, 
		       groupsig_signature_t *sig,
		       groupsig_key_t *grpkey);  
  
/**
 * @var klap20_groupsig_bundle
 * @brief The set of functions to manage KLAP20 groups.
 */
static const groupsig_t klap20_groupsig_bundle = {
 desc: &klap20_description, /**< Contains the KLAP20 scheme description. */
 init: &klap20_init, /**< Initializes the variables needed by KLAP20. */
 clear: &klap20_clear, /**< Frees the varaibles needed by KLAP20. */  
 setup: &klap20_setup, /**< Sets up KLAP20 groups. */
 get_joinseq: &klap20_get_joinseq, /**< Returns the number of messages in the join 
			protocol. */
 get_joinstart: &klap20_get_joinstart, /**< Returns who begins the join protocol. */
 join_mem: &klap20_join_mem, /**< Executes member-side joins. */
 join_mgr: &klap20_join_mgr, /**< Executes manager-side joins. */
 sign: &klap20_sign, /**< Issues KLAP20 signatures. */
 verify: &klap20_verify, /**< Verifies KLAP20 signatures. */
 verify_batch: &klap20_verify_batch, /**< Verifies batches of KLAP20 signatures. */
 open: &klap20_open, /**< Opens KLAP20 signatures. */
 open_verify: &klap20_open_verify, /**< KLAP20 does not create proofs of opening. */
 reveal: NULL, // &klap20_reveal, /**< Reveals the tracing trapdoor from KLAP20 signatures. */
 trace: NULL, // &klap20_trace, /**< Traces the issuer of a signature. */ 
 claim: NULL, // &klap20_claim, /**< Claims, in ZK, "ownership" of a signature. */
 claim_verify: NULL, // &klap20_claim_verify, /**< Verifies claims. */
 prove_equality: NULL, // &klap20_prove_equality, /**< Issues "same issuer" ZK proofs for several signatures. */
 prove_equality_verify: NULL, // &klap20_prove_equality_verify, /**< Verifies "same issuer" ZK proofs. */
 blind: NULL, /**< Blinds group signatures. */
 convert: NULL, /**< Converts blinded group signatures. */
 unblind: NULL, /**< Unblinds converted group signatures. */
 identify: NULL, // &identify, /**< Determines whether a signature has been issued by a member. */
 link: NULL, // &link, 
 verify_link: NULL, // &link_verify
 seqlink: NULL, // &seqlink, 
 verify_seqlink: NULL, // &seqlink_verify
};

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif
  
#endif /* _KLAP20_H */

/* klap20.h ends here */
