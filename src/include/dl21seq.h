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

#ifndef _DL21SEQ_H
#define _DL21SEQ_H

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
   * @def GROUPSIG_DL21SEQ_CODE
   * @brief DL21SEQ scheme code.
   */
#define GROUPSIG_DL21SEQ_CODE 7

  /**
   * @def GROUPSIG_DL21SEQ_NAME
   * @brief DL21SEQ scheme name.
   */
#define GROUPSIG_DL21SEQ_NAME "DL21SEQ"

  /* Metadata for the join protocol */

  /* 0 means the first message is sent by the manager, 1 means the first message
     is sent by the member */
#define DL21SEQ_JOIN_START 0

  /* Number of exchanged messages */
#define DL21SEQ_JOIN_SEQ 3

  /**
   * @var dl21_description
   * @brief DL21's description.
   */
  static const groupsig_description_t dl21seq_description = {
    GROUPSIG_DL21SEQ_CODE, /**< DL21SEQ's scheme code. */
    GROUPSIG_DL21SEQ_NAME, /**< DL21SEQ's scheme name. */
    0, /**< DL21SEQ does not have a GML. */
    0, /**< DL21SEQ does not have a CRL. */
    1, /**< DL21SEQ uses PBC. */
    0, /**< DL21SEQ does not have verifiable openings. */
    1, /**< DL21SEQ's issuer key is the first manager key. */
    0 /**< DL21SEQ's does not have inspector key. */    
  };
  
  /** 
   * @fn int dl21seq_init()
   * @brief Initializes the internal variables needed by DL21SEQ. In this case,
   *  it only sets up the pairing module.
   *
   * @return IOK or IERROR.
   */  
  int dl21seq_init();

  /** 
   * @fn int dl21seq_clear()
   * @brief Frees the memory initialized by dl21seq_init.
   *
   * @return IOK or IERROR.
   */   
  int dl21seq_clear();  
  
  /** 
   * @fn int dl21seq_setup(groupsig_key_t *grpkey, 
   *                       groupsig_key_t *mgrkey, 
   *                       gml_t *gml)
   * @brief The setup function for the DL21SEQ scheme.
   *
   * @param[in,out] grpkey An initialized group key, will be updated with the newly
   *   created group's group key.
   * @param[in,out] mgrkey An initialized manager key, will be updated with the
   *   newly created group's manager key.
   * @param[in,out] gml An initialized GML, will be set to an empty GML.
   * @param[in] config A DL21SEQ configuration structure.
   * 
   * @return IOK or IERROR.
   */
  int dl21seq_setup(groupsig_key_t *grpkey, groupsig_key_t *mgrkey, gml_t *gml);

  /**
   * @fn int dl21seq_get_joinseq(uint8_t *seq)
   * @brief Returns the number of messages to be exchanged in the join protocol.
   * 
   * @param seq A pointer to store the number of messages to exchange.
   *
   * @return IOK or IERROR.
   */ 
  int dl21seq_get_joinseq(uint8_t *seq);

  /**
   * @fn int dl21seq_get_joinstart(uint8_t *start)
   * @brief Returns who sends the first message in the join protocol.
   * 
   * @param start A pointer to store the who starts the join protocol. 0 means
   *  the Manager starts the protocol, 1 means the Member starts the protocol.
   *
   * @return IOK or IERROR.
   */ 
  int dl21seq_get_joinstart(uint8_t *start);

  /** 
   * @fn int dl21seq_join_mem(message_t **mout, 
   *                          groupsig_key_t *memkey,
   *			    int seq, 
   *                          message_t *min,
   *                          groupsig_key_t *grpkey)
   * @brief Executes the member-side join of the DL21SEQ scheme.
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
  int dl21seq_join_mem(message_t **mout,
		       groupsig_key_t *memkey,
		       int seq,
		       message_t *min,
		       groupsig_key_t *grpkey);

  /** 
   * @fn int dl21seq_join_mgr(message_t **mout, 
   *                          gml_t *gml,
   *                          groupsig_key_t *mgrkey,
   *                          int seq, 
   *                          message_t *min, 
   *			    groupsig_key_t *grpkey)
   * @brief Executes the manager-side join of the join procedure.
   *
   * @param[in,out] mout Message to be produced by the current step of the join/
   *  issue protocol.
   * @param[in,out] gml The group membership list that may be updated with
   *  information related to the new member.
   * @param[in] mgrkey The group manager key.
   * @param[in] seq The step to run of the join/issue protocol.
   *  manager.
   * @param[in] min Input message received from the member for the current step of
   *  the join/issue protocol.
   * @param[in] grpkey The group key.
   * 
   * @return IOK or IERROR.
   */
  int dl21seq_join_mgr(message_t **mout,
		       gml_t *gml,
		       groupsig_key_t *mgrkey,
		       int seq,
		       message_t *min,
		       groupsig_key_t *grpkey);

  /** 
   * @fn int dl21seq_sign(groupsig_signature_t *sig, message_t *msg, groupsig_key_t *memkey, 
   *	              groupsig_key_t *grpkey, unsigned int seed)
   * @brief Issues DL21SEQ group signatures.
   *
   * Using the specified member and group keys, issues a signature for the specified
   * message.
   *
   * @param[in,out] sig An initialized DL21SEQ group signature. Will be updated with
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
  int dl21seq_sign(groupsig_signature_t *sig, message_t *msg, groupsig_key_t *memkey, 
		   groupsig_key_t *grpkey, unsigned int seed);

  /** 
   * @fn int dl21seq_verify(uint8_t *ok, groupsig_signature_t *sig, message_t *msg, 
   *		        groupsig_key_t *grpkey);
   * @brief Verifies a DL21SEQ group signature.
   *
   * @param[in,out] ok Will be set to 1 if the verification succeeds, to 0 if
   *  it fails.
   * @param[in] sig The signature to verify.
   * @param[in] msg The corresponding message.
   * @param[in] grpkey The group key.
   * 
   * @return IOK or IERROR.
   */
  int dl21seq_verify(uint8_t *ok, groupsig_signature_t *sig, message_t *msg, 
		     groupsig_key_t *grpkey);

  /** 
   * @fn int dl21seq_identify(uint8_t *ok,
   *                           groupsig_proof_t **proof,
   *                           groupsig_key_t *grpkey, 
   *                           groupsig_key_t *memkey,
   *                           groupsig_signature_t *sig,
   *                           message_t *msg)
   * @brief Enables a member to determine whether a specific DL21SEQ signature has 
   *  been issued by him/herself or not.
   *
   * @param[in,out] ok Will be set to 1 (signature issued by member) or 0 (not 
   *  issued by member.)
   * @param[in,out] proof If not null, and the algorithm supports it, will be
   * set to contain a proof of having issued the given signature. 
   * @param[in] grpkey The group key.
   * @param[in] memkey The key used for issuing the signature.
   * @param[in] sigs The signature.
   * @param[in] msg The signed message.
   * 
   * @return IOK or IERROR.
   */
  int dl21seq_identify(uint8_t *ok,
		       groupsig_proof_t **proof,
		       groupsig_key_t *grpkey,
		       groupsig_key_t *memkey,
		       groupsig_signature_t *sig,
		       message_t *msg);

  /** 
   * @typedef int dl21seq_link(groupsig_proof_t **proof,
   *                        groupsig_key_t *grpkey, 
   *                        groupsig_key_t *memkey,
   *                        message_t *msg,
   *                        groupsig_signature_t **sigs,
   *                        message_t **msgs,
   *                        uint32_t n)
   * @brief Issues a proof of several DL21SEQ signatures being 
   *        linked (issued by the same member.)
   *
   * @param[in,out] proof The proof to be issued.
   * @param[in] grpkey The group key.
   * @param[in] memkey The key used for issuing the individual signatures.
   * @param[in] msg The message to add to the created proof (prevents replays.)
   * @param[in] sigs The signatures to link.
   * @param[in] msgs The signed messages.
   * @param[in] n The size of the sig and msg arrays.
   * 
   * @return IOK or IERROR.
   */
  int dl21seq_link(groupsig_proof_t **proof,
		   groupsig_key_t *grpkey,
		   groupsig_key_t *memkey,
		   message_t *msg,
		   groupsig_signature_t **sigs,
		   message_t **msgs,
		   uint32_t n);

  /** 
   * @fn int groupsig_verify_link(uint8_t *ok,
   *                              groupsig_key_t *grpkey,
   *                              groupsig_proof_t *proof, 
   *                              message_t *msg,
   *                              groupsig_signature_t **sigs,
   *                              message_t **msgs,
   *                              uint32_t n)
   * @brief Verifies proofs of several DL21SEQ signatures being linked.
   *
   * @param[in,out] ok Will be set to 1 (proof valid) or 0 (proof invalid).
   * @param[in] proof The proof to be verified.
   * @param[in] grpkey The group key.
   * @param[in] msg The message to add to the created proof (prevents replays.)
   * @param[in] sigs The signatures.
   * @param[in] msgs The signed messages. 
   * @param[in] n The size of the sig and msg arrays.
   * 
   * @return IOK or IERROR.
   */
  int dl21seq_verify_link(uint8_t *ok,
			  groupsig_key_t *grpkey,
			  groupsig_proof_t *proof,
			  message_t *msg,
			  groupsig_signature_t **sigs,
			  message_t **msgs,
			  uint32_t n);
  

  /** 
   * @typedef int dl21seq_seqlink(groupsig_proof_t **proof,
   *                              groupsig_key_t *grpkey, 
   *                              groupsig_key_t *memkey,
   *                              message_t *msg,
   *                              groupsig_signature_t **sigs,
   *                              message_t **msgs,
   *                              uint32_t n)
   * @brief Issues a proof of several DL21SEQ signatures being 
   *        sequentially linked (issued by the same member.)
   *
   * @param[in,out] proof The proof to be issued.
   * @param[in] grpkey The group key.
   * @param[in] memkey The key used for issuing the individual signatures.
   * @param[in] msg The message to add to the created proof (prevents replays.)
   * @param[in] sigs The signatures to link.
   * @param[in] msgs The signed messages.
   * @param[in] n The size of the sig and msg arrays.
   * 
   * @return IOK or IERROR.
   */
  int dl21seq_seqlink(groupsig_proof_t **proof,
		      groupsig_key_t *grpkey,
		      groupsig_key_t *memkey,
		      message_t *msg,
		      groupsig_signature_t **sigs,
		      message_t **msgs,
		      uint32_t n);

  /** 
   * @fn int groupsig_verify_seqlink(uint8_t *ok,
   *                              groupsig_key_t *grpkey,
   *                              groupsig_proof_t *proof, 
   *                              message_t *msg,
   *                              groupsig_signature_t **sigs,
   *                              message_t **msgs,
   *                              uint32_t n)
   * @brief Verifies proofs of several DL21SEQ signatures being sequentially 
   *  linked.
   *
   * @param[in,out] ok Will be set to 1 (proof valid) or 0 (proof invalid).
   * @param[in] proof The proof to be verified.
   * @param[in] grpkey The group key.
   * @param[in] msg The message to add to the created proof (prevents replays.)
   * @param[in] sigs The signatures.
   * @param[in] msgs The signed messages. 
   * @param[in] n The size of the sig and msg arrays.
   * 
   * @return IOK or IERROR.
   */
  int dl21seq_verify_seqlink(uint8_t *ok,
			     groupsig_key_t *grpkey,
			     groupsig_proof_t *proof,
			     message_t *msg,
			     groupsig_signature_t **sigs,
			     message_t **msgs,
			     uint32_t n);
  
  
  /**
   * @var dl21seq_groupsig_bundle
   * @brief The set of functions to manage DL21SEQ groups.
   */
  static const groupsig_t dl21seq_groupsig_bundle = {
  desc: &dl21seq_description, /**< Contains the DL21SEQ scheme description. */
  init: &dl21seq_init, /**< Initializes the variables needed by DL21SEQ. */
  clear: &dl21seq_clear, /**< Frees the variables needed by DL21SEQ. */
  setup: &dl21seq_setup, /**< Sets up DL21SEQ groups. */
  get_joinseq: &dl21seq_get_joinseq, /**< Returns the number of messages in the join 
					protocol. */
  get_joinstart: &dl21seq_get_joinstart, /**< Returns who begins the join protocol. */
  join_mem: &dl21seq_join_mem, /**< Executes member-side joins. */
  join_mgr: &dl21seq_join_mgr, /**< Executes manager-side joins. */
  sign: &dl21seq_sign, /**< Issues DL21SEQ signatures. */
  verify: &dl21seq_verify, /**< Verifies DL21SEQ signatures. */
  open: NULL, 
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
  identify: &dl21seq_identify, /**< Determines whether a signature has been 
				  issued by a member. */
  link: &dl21seq_link, /**< Links a set of DL21SEQ signatures. */
  verify_link: &dl21seq_verify_link, /**< Verifies a proof of link. */
  seqlink: &dl21seq_seqlink, /**< Sequentially links a set of DL21SEQ sigs. */
  verify_seqlink: &dl21seq_verify_seqlink, /**< Verifies a proof of sequential 
					      link. */
  };

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif
  
#endif /* _DL21SEQ_H */

/* dl21seq.h ends here */
