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

#ifndef _BBS04_H
#define _BBS04_H

#include "key.h"
#include "gml.h"
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
 * @def GROUPSIG_BBS04_CODE
 * @brief BBS04 scheme code.
 */
#define GROUPSIG_BBS04_CODE 1

/**
 * @def GROUPSIG_BBS04_NAME
 * @brief BBS04 scheme name.
 */
#define GROUPSIG_BBS04_NAME "BBS04"

/**
 * @var bbs04_description
 * @brief BBS04's description.
 */
static const groupsig_description_t bbs04_description = {
  GROUPSIG_BBS04_CODE, /**< BBS04's scheme code. */
  GROUPSIG_BBS04_NAME, /**< BBS04's scheme name. */
  1, /**< BBS04 has a GML. */
  0, /**< BBS04 does not have a CRL. */
  1, /**< BBS04 uses PBC. */
  0, /**< BBS04 does not have verifiable openings. */
  1, /**< BBS04's issuer key is the first manager key. */
  1 /**< BBS04's inspector (opener) key is the first manager key. */  
};

/* Metadata for the join protocol */

/* 0 means the first message is sent by the manager, 1 means the first message
   is sent by the member */
#define BBS04_JOIN_START 0

/* Number of exchanged messages */
#define BBS04_JOIN_SEQ 1

/** 
 * @fn int bbs04_init()
 * @brief Initializes the internal variables needed by BBS04. In this case,
 *  it only sets up the pairing module.
 *
 * @return IOK or IERROR.
 */  
int bbs04_init();

/** 
 * @fn int bbs04_clear()
 * @brief Frees the memory initialized by bbs04_init.
 *
 * @return IOK or IERROR.
 */   
int bbs04_clear();
  
/** 
 * @fn int bbs04_setup(groupsig_key_t *grpkey,
 *                     groupsig_key_t *mgrkey, 
 *                     gml_t *gml)
 * @brief The setup function for the BBS04 scheme.
 *
 * @param[in,out] grpkey An initialized group key, will be updated with the newly
 *   created group's group key.
 * @param[in,out] mgrkey An initialized manager key, will be updated with the
 *   newly created group's manager key.
 * @param[in,out] gml An initialized GML, will be set to an empty GML.
 * 
 * @return IOK or IERROR.
 */
int bbs04_setup(groupsig_key_t *grpkey,
		groupsig_key_t *mgrkey,
		gml_t *gml);

/**
 * @fn int bbs04_get_joinseq(uint8_t *seq)
 * @brief Returns the number of messages to be exchanged in the join protocol.
 * 
 * @param seq A pointer to store the number of messages to exchange.
 *
 * @return IOK or IERROR.
 */ 
int bbs04_get_joinseq(uint8_t *seq);

/**
 * @fn int bbs04_get_joinstart(uint8_t *start)
 * @brief Returns who sends the first message in the join protocol.
 * 
 * @param start A pointer to store the who starts the join protocol. 0 means
 *  the Manager starts the protocol, 1 means the Member starts the protocol.
 *
 * @return IOK or IERROR.
 */ 
int bbs04_get_joinstart(uint8_t *start);

/** 
 * @fn int bbs04_join_mem(message_t **mout,
 *                        groupsig_key_t *memkey,
 *			  int seq, message_t *min,
 *                        groupsig_key_t *grpkey)
 * @brief Executes the member-side join of the BBS04 scheme.
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
int bbs04_join_mem(message_t **mout,
		   groupsig_key_t *memkey,
		   int seq,
		   message_t *min,
		   groupsig_key_t *grpkey);

/** 
 * @fn int bbs04_join_mgr(message_t **mout, 
 *                        gml_t *gml,
 *                        groupsig_key_t *mgrkey,
 *                        int seq, 
 *                        message_t *min, 
 *			  groupsig_key_t *grpkey)
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
int bbs04_join_mgr(message_t **mout,
		   gml_t *gml,
		   groupsig_key_t *mgrkey,
		   int seq,
		   message_t *min,
		   groupsig_key_t *grpkey);

/** 
 * @fn int bbs04_sign(groupsig_signature_t *sig, 
 *                    message_t *msg, 
 *                    groupsig_key_t *memkey, 
 *	              groupsig_key_t *grpkey, 
 *                    unsigned int seed)
 * @brief Issues BBS04 group signatures.
 *
 * Using the specified member and group keys, issues a signature for the specified
 * message.
 *
 * @param[in,out] sig An initialized BBS04 group signature. Will be updated with
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
int bbs04_sign(groupsig_signature_t *sig,
	       message_t *msg,
	       groupsig_key_t *memkey, 
	       groupsig_key_t *grpkey,
	       unsigned int seed);

/** 
 * @fn int bbs04_verify(uint8_t *ok, 
 *                      groupsig_signature_t *sig, 
 *                      message_t *msg, 
 *		        groupsig_key_t *grpkey);
 * @brief Verifies a BBS04 group signature.
 *
 * @param[in,out] ok Will be set to 1 if the verification succeeds, to 0 if
 *  it fails.
 * @param[in] sig The signature to verify.
 * @param[in] msg The corresponding message.
 * @param[in] grpkey The group key.
 * 
 * @return IOK or IERROR.
 */
int bbs04_verify(uint8_t *ok,
		 groupsig_signature_t *sig,
		 message_t *msg, 
		 groupsig_key_t *grpkey);

/** 
 * @fn int bbs04_open(uint64_t *index, 
 *                    groupsig_proof_t *proof, 
 *                    crl_t *crl, 
 *                    groupsig_signature_t *sig, 
 *                    groupsig_key_t *grpkey, 
 *	              groupsig_key_t *mgrkey, 
 *                    gml_t *gml)
 * @brief Opens a BBS04 group signature.
 * 
 * Opens the specified group signature, obtaining the signer's identity.
 *
 * @param[in,out] id An initialized identity. Will be updated with the signer's
 *  real identity.
 * @param[in,out] proof BBS04 ignores this parameter.
 * @param[in,out] crl Unused. Ignore.
 * @param[in] sig The signature to open.
 * @param[in] grpkey The group key.
 * @param[in] mgrkey The manager's key.
 * @param[in] gml The GML.
 * 
 * @return IOK if it was possible to open the signature. IFAIL if the open
 *  trapdoor was not found, IERROR otherwise.
 */
int bbs04_open(uint64_t *index,
	       groupsig_proof_t *proof,
	       crl_t *crl,
	       groupsig_signature_t *sig, 
	       groupsig_key_t *grpkey,
	       groupsig_key_t *mgrkey,
	       gml_t *gml);

/**
 * @var bbs04_groupsig_bundle
 * @brief The set of functions to manage BBS04 groups.
 */
static const groupsig_t bbs04_groupsig_bundle = {
 desc: &bbs04_description, /**< Contains the BBS04 scheme description. */
 init: &bbs04_init, /**< Initializes the variables needed by BBS04. */
 clear: &bbs04_clear, /**< Frees the varaibles needed by BBS04. */ 
 setup: &bbs04_setup, /**< Sets up BBS04 groups. */
 get_joinseq: &bbs04_get_joinseq, /**< Returns the number of messages in the join 
				     protocol. */
 get_joinstart: &bbs04_get_joinstart, /**< Returns who begins the join protocol. */
 join_mem: &bbs04_join_mem, /**< Executes member-side joins. */
 join_mgr: &bbs04_join_mgr, /**< Executes maanger-side joins. */
 sign: &bbs04_sign, /**< Issues BBS04 signatures. */
 verify: &bbs04_verify, /**< Verifies BBS04 signatures. */
 verify_batch: NULL,
 open: &bbs04_open, /**< Opens BBS04 signatures. */
 open_verify: NULL,
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

#endif /* _BBS04_H */

/* bbs04.h ends here */
