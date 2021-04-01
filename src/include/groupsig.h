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

#ifndef _GROUPSIG_H
#define _GROUPSIG_H

#include <stdint.h>

#include "types.h"
#include "key.h"
#include "signature.h"
#include "blindsig.h"
#include "gml.h"
#include "crl.h"
#include "grp_key.h"
#include "mgr_key.h"
#include "mem_key.h"
#include "proof.h"
#include "identity.h"
#include "trapdoor.h"
#include "message.h"
#include "sysenv.h"

#ifdef __cplusplus
extern "C" {
#endif

  /**
   * @struct groupsig_description_t
   * @brief Stores the basic description of a group signature scheme. Useful
   *  metadata for simplifying internal processes. 
   */
  typedef struct {
    uint8_t code; /**< The scheme's code. Each code uniquely identifies a group
		     signature scheme. The registered group signature schemes are
		     linked in the file registered_groupsigs.h, and their
		     corresponding unique codes are defined in the therein
		     included files. */
    char name[10]; /**< The scheme's name. */
    uint8_t has_gml; /**< Whether the scheme requires a GML (1) or not (0). */
    uint8_t has_crl; /**< Whether the scheme requires a CRL (1) or not (0). */
    uint8_t has_pbc; /**< Whether the scheme requires PBC (1) or not (0). */
    uint8_t has_open_proof; /**< Whether the scheme supports verifiable openings. */
    uint8_t issuer_key; /**< "Index" of the issuer key. Starts in 1, 0 means no key. */
    uint8_t inspector_key; /**< "Index" of the opener key. Starts in 1, 0 means no key. */
  } groupsig_description_t;

  /**
   * @typedef int (*init_f)(void);
   * @brief Initializes internal data structures used by the schemes.
   *
   * @return IOK or IERROR.
   */
  typedef int (*init_f)(void);
  
  /**
   * @typedef int (*clear_f)(void);
   * @brief Clears the internal data structures initialized by init_f functions.
   *
   * @return IOK or IERROR.
   */
  typedef int (*clear_f)(void);  

  /**
   * @typedef int (*setup_f)(groupsig_key_t *grpkey, 
   *                         groupsig_key_t *mgrkey, 
   *                         gml_t *gml)
   * @brief Type for setup functions.
   *
   * All schemes' setup functions must follow this scheme. Functions following 
   * this prototype will create a specific scheme instance, setting the group 
   * and manager keys, and the GML.
   *
   * @param[in,out] grpkey An initialized group key, will be updated with the
   *  generated group key.
   * @param[in,out] mgrkey An initialized manager key, will be updated with the
   *  generated manager key.
   * @param[in,out] gml An initialized GML, will be updated with the generated
   *  GML.
   * @return IOK or IERROR.
   */
  typedef int (*setup_f)(groupsig_key_t *grpkey,
			 groupsig_key_t *mgrkey,
			 gml_t *gml);

  /**
   * @typedef int (*get_joinseq_f)(uint8_t *seq)
   * @brief Functions returning the number of messages to be exchanged in the 
   *  join protocol.
   * 
   * @param seq A pointer to store the number of messages to exchange.
   *
   * @return IOK or IERROR.
   */ 
  typedef int (*get_joinseq_f)(uint8_t *seq);

  /**
   * @typedef int (*get_joinstart)(uint8_t *start)
   * @brief Functions returning who sends the first message in the join protocol.
   * 
   * @param start A pointer to store the who starts the join protocol. 0 means
   *  the Manager starts the protocol, 1 means the Member starts the protocol.
   *
   * @return IOK or IERROR.
   */
  typedef int (*get_joinstart_f)(uint8_t *start);

  /** 
   * @typedef int (*join_mem_f)(message_t **mout, groupsig_key_t *memkey,
   *			      int seq, message_t *min, groupsig_key_t *grpkey)
   * @brief Type for functions implementing the member join functionality.
   *
   * Functions of this type are executed by entities who want to be included in a
   * group. They run in coordination with the equivalent functions run by 
   * managers (join_mgr).
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
  typedef int (*join_mem_f)(message_t **mout,
			    groupsig_key_t *memkey,
			    int seq,
			    message_t *min,
			    groupsig_key_t *grpkey);

  /** 
   * @typedef int (*join_mgr_f)(message_t **mout, gml_t *gml,
   *                            groupsig_key_t *mgrkey,
   *                            int seq, message_t *min, 
   *			      groupsig_key_t *grpkey)
   * @brief Type for functions implementing the manager join functionality.
   *
   * Functions of this type are executed by group managers. From a partial member
   * key, as produced by the corresponding join_mem_f function, these functions
   * create a complete member key, adding the new member to any necessary component
   * (e.g. GMLs).
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
  typedef int (*join_mgr_f)(message_t **mout,
			    gml_t *gml,
			    groupsig_key_t *mgrkey,
			    int seq,
			    message_t *min,
			    groupsig_key_t *grpkey);

  /** 
   * @typedef int (*sign_f)(groupsig_signature_t *sig, message_t *msg, groupsig_key_t *memkey, 
   *		      groupsig_key_t *grpkey, unsigned int seed)
   * @brief Type of functions for signing messages.
   *
   * @param[in,out] sig An initialized group signature structure. Will be set to the
   *  produced signature.
   * @param[in] msg The message to sign.
   * @param[in] memkey The member key for signing.
   * @param[in] grpkey The group key.
   * @param[in] seed When set to a value different to UINT_MAX, the system's pseudo
   *  random number generator will be reseeded with the specified value (allowing to
   *  re-generate signatures). Otherwise, the random number generator state will not
   *  be modified. In any case, the random generator will be randomly reseeded after
   *  signing.
   * 
   * @return IOK or IERROR.
   */
  typedef int (*sign_f)(groupsig_signature_t *sig,
			message_t *msg,
			groupsig_key_t *memkey, 
			groupsig_key_t *grpkey,
			unsigned int seed);

  /** 
   * @typedef int (*verify_f)(uint8_t *ok, groupsig_signature_t *sig, message_t *msg, 
   *			groupsig_key_t *grpkey)
   * @brief Type of functions for verifying group signatures. 
   * 
   * @param[in,out] Will be set to 1 if the signature is valid, to 0 otherwise.
   * @param[in] sig The signature to be verified.
   * @param[in] msg The message associated to <i>sig</i>.
   * @param[in] grpkey The group key.
   * 
   * @return IOK or IERROR.
   */
  typedef int (*verify_f)(uint8_t *ok,
			  groupsig_signature_t *sig,
			  message_t *msg, 
			  groupsig_key_t *grpkey);

  /** 
   * @typedef int (*verify_batch_f)(uint8_t *ok, 
   *                                groupsig_signature_t **sig, 
   *                                message_t **msg, 
   *                                uint32_t n,
   *                                groupsig_key_t *grpkey)
   * @brief Type of functions for verifying batches of signatures.
   *
   * @param[in,out] ok Will be set to 1 if all the signatures are correct.
   *  To 0 otherwise.
   * @param[in] sigs The signatures to verify.
   * @param[in] msgs The messages related to the signatures.
   * @param[in] n The size of the sigs and msgs arrays.
   * @param[in] grpkey The group key.
   * 
   * @return IOK or IERROR.
   */    
  typedef int (*verify_batch_f)(uint8_t *ok,
				groupsig_signature_t **sigs,
				message_t **msgs,
				uint32_t n,
				groupsig_key_t *grpkey);
    
  /** 
   * @typedef int (*reveal_f)(trapdoor_t *trap, crl_t *crl, gml_t *gml, uint64_t index)
   * @brief Type of functions for revealing the tracing trapdoor of group members.7
   *
   * Functions of this type return the tracing trapdoor of the member at the position
   * <i>index</i> within the given GML. If the received CRL is not NULL, a new 
   * entry will be updated to it, corresponding to the member with the specified index.
   *
   * @param[in,out] trap Will be set to the retrieved trapdoor. Must have been
   *  initialized by the caller.
   * @param[in] crl If not NULL, a new entry will be added to the CRL, associated
   *  to the member with the given index.
   * @param[in] gml The Group Membership List.
   * @param[in] index The index of the member whose trapdoor is to be revealed.
   * 
   * @return IOK or IERROR.
   *
   * @todo Using <i>index</i>es to refer to specific members may not be general
   *  enough (e.g. for dynamic acccumulator based schemes).
   */
  typedef int (*reveal_f)(trapdoor_t *trap,
			  crl_t *crl,
			  gml_t *gml,
			  uint64_t index);

  /** 
   * @typedef int (*open_f)(uint64_t *id, groupsig_proof_t *proof, crl_t *crl, 
   *                        groupsig_signature_t *sig, groupsig_key_t *grpkey, 
   *		          groupsig_key_t *mgrkey, gml_t *gml)
   * @brief Type of functions for opening group signatures, revealing the identity
   *  of the issuer of the given signature.
   *
   * @param[in,out] index Will be set to the index of the member who issued the
   *  signature.
   * @param[in,out] proof If opening proofs are produced, this parameter will be set
   *  to a proof of correctness of the opening.
   * @param[in] crl If not NULL, a new entry will be added to the CRL, associated
   *  to the member with the given index.
   * @param[in] sig The group signature to be opened.
   * @param[in] grpkey The group key.
   * @param[in] mgrkey The group manager key.
   * @param[in] gml The group membership list.
   * 
   * @return IOK if it was possible to open the signature. IFAIL if the open
   *  trapdoor was not found, IERROR otherwise.
   */
  typedef int (*open_f)(uint64_t *index,
			groupsig_proof_t *proof,
			crl_t *crl, 
			groupsig_signature_t *sig,
			groupsig_key_t *grpkey, 
			groupsig_key_t *mgrkey,
			gml_t *gml);

  /** 
   * @typedef typedef int (*open_verify_f)(uint8_t *ok, 
   *                                       groupsig_proof_t *proof, 
   *                                       groupsig_signature_t *sig, 
   *                                       groupsig_key_t *grpkey)
   * 
   * @param[in,out] ok Will be set to 1 if the proof is correct, to 0 otherwise.
   *  signature.
   * @param[in] proof The proof of opening.
   * @param[in] sig The group signature associated to the proof.
   * @param[in] grpkey The group key.
   * 
   * @return IOK or IERROR
   */
  typedef int (*open_verify_f)(uint8_t *ok,
			       groupsig_proof_t *proof, 
			       groupsig_signature_t *sig,
			       groupsig_key_t *grpkey);

  /** 
   * @typedef int (*trace_f)(uint8_t *ok, groupsig_signature_t *sig, groupsig_key_t *grpkey, 
   *		           crl_t *crl, groupsig_key_t *mgrkey, gml_t *gml)
   * @brief Type of functions for tracing group signatures.
   * 
   * Functions of this type set <i>ok</i> to 1 if the given group signature has been
   * issued by any of the group members in the specified CRL (otherwise, <i>ok</i> is
   * set to 0).
   * 
   * @param[in,out] ok Will be set to 1 if the group signature has been issued by
   *  a member in the CRL, to 0 otherwise.
   * @param[in] The group signature to be traced.
   * @param[in] grpkey The group key.
   * @param[in] CRL the Certificate Revocation List to use for tracing.
   * @param[in] mgrkey Schemes that do not include native support for tracing may
   *  "emulate" it by opening group signatures. Hence, they will need the manager
   *  key. In traceable schemes, this parameter may be ignored.
   * @param[in] gml Schemes that do not include native support for tracing may
   *  "emulate" it by opening group signatures. Hence, they will need the GML.
   *  In traceable schemes, this parameter may be ignored.
   * 
   * @return IOK or IERROR.
   */
  typedef int (*trace_f)(uint8_t *ok,
			 groupsig_signature_t *sig,
			 groupsig_key_t *grpkey, 
			 crl_t *crl,
			 groupsig_key_t *mgrkey,
			 gml_t *gml);

  /** 
   * @typedef int (*claim_f)(groupsig_proof_t *proof, groupsig_key_t *memkey, 
   *		           groupsig_key_t *grpkey, groupsig_signature_t *sig)
   * @brief Type of functions for issuing (Zero Knowledge) proofs for claiming 
   *  authorship of a signature.
   *
   * @param[in,out] proof The proof to be created. Must have been initialized by
   *  the caller.
   * @param[in] memkey The member key of the issuer of the signature.
   * @param[in] grpkey The group key.
   * @param[in] sig The group signature.
   * 
   * @return IOK or IERROR.
   */
  typedef int (*claim_f)(groupsig_proof_t *proof,
			 groupsig_key_t *memkey, 
			 groupsig_key_t *grpkey,
			 groupsig_signature_t *sig);

  /** 
   * @typedef int (*claim_verify_f)(uint8_t *ok, groupsig_proof_t *proof, 
   *			          groupsig_signature_t *sig, groupsig_key_t *grpkey)
   * @brief Type of functions for verifying claim proofs. 
   *
   * @param[in,out] ok Will be set to 1 if the proof is correct, to 0 otherwise.
   * @param[in] proof The proof to verify.
   * @param[in] sig The signature that the proof claims ownership of.
   * @param[in] grpkey The group key.
   * 
   * @return IOK or IERROR.
   */
  typedef int (*claim_verify_f)(uint8_t *ok,
				groupsig_proof_t *proof, 
				groupsig_signature_t *sig,
				groupsig_key_t *grpkey);

  /** 
   * @typedef int (*prove_equality_f)(groupsig_proof_t *proof, groupsig_key_t *memkey, 
   *				    groupsig_key_t *grpkey, groupsig_signature_t **sigs, 
   *				    uint16_t n_sigs)
   * @brief Type of functions for proving that all the signatures in <i>sigs</i> have
   *  been issued by the owner of <i>memkey</i>.
   * 
   * @param[in,out] proof Will be set to the generated proof. Must have been
   *  initialized by the caller.
   * @param[in] memkey The group member key. Must be the issuer of all the signatures.
   * @param[in] grpkey The group key.
   * @param[in] sigs The signatures to be proved.
   * @param[in] n_sigs The number of signatures in <i>sigs</i>.
   * 
   * @return IOK or IERROR.
   */
  typedef int (*prove_equality_f)(groupsig_proof_t *proof,
				  groupsig_key_t *memkey, 
				  groupsig_key_t *grpkey,
				  groupsig_signature_t **sigs, 
				  uint16_t n_sigs);

  /** 
   * @typedef int (*prove_equality_verify_f)(uint8_t *ok, groupsig_proof_t *proof, 
   *				           groupsig_key_t *grpkey,
   *			                   groupsig_signature_t **sigs, uint16_t n_sigs)
   * @brief Type of functions for verifying equality proofs.
   *
   * @param[in,out] ok Will be set to 1 if the proof is correct. To 0 otherwise.
   * @param[in] proof The proof to verify.
   * @param[in] grpkey The group key.
   * @param[in] sigs The group signatures related to the proof.
   * @param[in] n_sigs The number of signatures in <i>n_sigs</i>.
   * 
   * @return IOK or IERROR.
   */
  typedef int (*prove_equality_verify_f)(uint8_t *ok,
					 groupsig_proof_t *proof, 
					 groupsig_key_t *grpkey,
					 groupsig_signature_t **sigs,
					 uint16_t n_sigs);

  /** 
   * @typedef int (*blind_f)(groupsig_blindsig_t *bsig, groupsig_key_t **bldkey, 
   *			   groupsig_signature_t *sig, message_t *msg, 
   *                         groupsig_key_t *grpkey)
   * @brief Type of functions for blinding group signatures.
   *
   * @param[in,out] bsig The produced blinded group signature.
   *  Must be allocated by the caller.
   * @param[in,out] bldkey The key used for blinding. If NULL, a fresh one
   *  is created.
   * @param[in] grpkey The group key.
   * @param[in] sig The group signature to blind.
   * @param[in] msg The signed message.
   * 
   * @return IOK or IERROR.
   */
  typedef int (*blind_f)(groupsig_blindsig_t *bsig,
			 groupsig_key_t **bldkey,
			 groupsig_key_t *grpkey,
			 groupsig_signature_t *sig,
			 message_t *msg);

  /** 
   * @typedef int (*convert_f)(groupsig_blindsig_t **csig,
   *                           groupsig_blindsig_t **bsig, uint32_t n_bsigs,
   *			     groupsig_key_t *grpkey, groupsig_key_t *mgrkey,
   *                           groupsig_key_t *bldkey, message_t *msg)
   * @brief Type of functions for converting blinded group signatures.
   *
   * @param[in,out] csig Array of blinded signatures to store the result of the 
   *  conversion.
   * @param[in] bsig The blinded signatures to be converted.
   * @param[in] n_bsigs The size of the previous array.
   * @param[in] grpkey The group public key.
   * @param[in] mgrkey The 'manager' key (containing at least 
   *  the converting key).
   * @param[in] bldkey The public blinding key.
   * @param[in] msg The signed messages. Optional.
   * 
   * @return IOK or IERROR.
   */
  typedef int (*convert_f)(groupsig_blindsig_t **csig,
			   groupsig_blindsig_t **bsig,
			   uint32_t n_bsigs,
			   groupsig_key_t *grpkey,
			   groupsig_key_t *mgrkey,
			   groupsig_key_t *bldkey,
			   message_t *msg);

  /** 
   * @typedef int (*unblind_f)(identity_t *nym, groupsig_signature_t *sig,
   *                               groupsig_blindsig_t *bsig,
   *                               groupsig_key_t *grpkey, groupsig_key_t *bldkey,
   *                               message_t *msg)
   * @brief Type of functions for unblinding nyms in encrypt-then-sign group signatures.
   *
   * @param[in,out] nym The unblinded nym (might be ignored).
   * @param[in,out] sig The unblinded signature (might be ignored).
   * @param[in] bsig The blinded signature.
   * @param[in] grpkey The group key.
   * @param[in] bldkey The key used for blinding. If NULL, a fresh one
   *  is created.
   * @param[in,out] msg The signed message. Optional.
   * 
   * @return IOK or IERROR.
   */
  typedef int (*unblind_f)(identity_t *nym,
			   groupsig_signature_t *sig,
			   groupsig_blindsig_t *bsig,
			   groupsig_key_t *grpkey,
			   groupsig_key_t *bldkey,
			   message_t *msg);
  
  /** 
   * @typedef int (*identify_f)(uint8_t *ok,
   *                            groupsig_proof_t **proof,
   *                            groupsig_key_t *grpkey, 
   *                            groupsig_key_t *memkey,
   *                            groupsig_signature_t *sig,
   *                            message_t *msg)
   * @brief Type of functions enabling a member to determine whether a specific
   *  signature has been issued by him/herself or not.
   *
   * @param[in,out] ok Will be set to 1 (signature issued by member) or 0 (not 
   *  issued by member.)
   * @param[in,out] proof If not null, and the algorithm supports it, will be
   * set to contain a proof of having issued the given signature. 
   *   @TODO: This should be merged with claim/claim_verify.
   * @param[in] grpkey The group key.
   * @param[in] memkey The key used for issuing the signature.
   * @param[in] sig The signature.
   * @param[in] msg The signed message.
   * 
   * @return IOK or IERROR.
   */
  typedef int (*identify_f)(uint8_t *ok,
			    groupsig_proof_t **proof,
			    groupsig_key_t *grpkey,
			    groupsig_key_t *memkey,
			    groupsig_signature_t *sig,
			    message_t *msg);

  /** 
   * @typedef int (*link_f)(groupsig_proof_t **proof,
   *                        groupsig_key_t *grpkey, 
   *                        groupsig_key_t *memkey,
   *                        message_t *msg,
   *                        groupsig_signature_t **sigs,
   *                        message_t **msgs,
   *                        uint32_t n)
   * @brief Type of functions for issuing proofs of several signatures being 
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
   * @return IOK if link was produced correctly; IFAIL if the signatures
   * do not verify correctly or identify to the user. IERROR if something
   * misbehaved.
   */
  typedef int (*link_f)(groupsig_proof_t **proof,
			groupsig_key_t *grpkey,
			groupsig_key_t *memkey,
			message_t *msg,
			groupsig_signature_t **sigs,
			message_t **msgs,
			uint32_t n);

  /** 
   * @typedef int (*verify_link_f)(uint8_t *ok,
   *                        groupsig_key_t *grpkey,
   *                        groupsig_proof_t *proof, 
   *                        message_t *msg,
   *                        groupsig_signature_t **sigs,
   *                        message_t **msgs,
   *                        uint32_t n)
   * @brief Type of functions for verifying proofs of several signatures being 
   *        linked.
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
  typedef int (*verify_link_f)(uint8_t *ok,
			       groupsig_key_t *grpkey,
			       groupsig_proof_t *proof,
			       message_t *msg,
			       groupsig_signature_t **sigs,
			       message_t **msgs,
			       uint32_t n);

  /** 
   * @typedef int (*seqlink_f)(groupsig_proof_t **proof,
   *                           groupsig_key_t *grpkey, 
   *                           groupsig_key_t *memkey,
   *                           message_t *msg,
   *                           groupsig_signature_t **sigs,
   *                           message_t **msgs,
   *                           uint32_t n)
   * @brief Type of functions for issuing proofs of several signatures being 
   *        sequentially linked (the *sigs array must be correctly ordered!)
   *
   * @param[in,out] proof The proof to be issued.
   * @param[in] grpkey The group key.
   * @param[in] memkey The key used for issuing the individual signatures.
   * @param[in] msg The message to add to the created proof (prevents replays.)
   * @param[in] sigs The signatures to sequentially link.
   * @param[in] msgs The signed messages.
   * @param[in] n The size of the sig and msg arrays.
   * 
   * @return IOK if link was produced correctly; IFAIL if the signatures
   * do not verify correctly or identify to the user. IERROR if something
   * misbehaved.
   */
  typedef int (*seqlink_f)(groupsig_proof_t **proof,
			   groupsig_key_t *grpkey,
			   groupsig_key_t *memkey,
			   message_t *msg,
			   groupsig_signature_t **sigs,
			   message_t **msgs,
			   uint32_t n);

  /** 
   * @typedef int (*verify_seqlink_f)(uint8_t *ok,
   *                        groupsig_key_t *grpkey,
   *                        groupsig_proof_t *proof,
   *                        message_t *msg,
   *                        groupsig_signature_t **sigs, 
   *                        message_t **msgs,
   *                        uint32_t n)
   * @brief Type of functions for verifying proofs of several signatures being 
   *        sequentially linked (the *sigs array must be correctly ordered!)
   *
   * @param[in,out] ok Will be set to 1 (proof valid) or 0 (proof invalid).
   * @param[in] grpkey The group key.
   * @param[in] proof The proof.
   * @param[in] msg The message to add to the created proof (prevents replays.)
   * @param[in] sigs The signatures to link.
   * @param[in] msgs The signed messages. 
   * @param[in] n The size of the sig and msg arrays.
   * 
   * @return IOK or IERROR.
   */
  typedef int (*verify_seqlink_f)(uint8_t *ok,
				  groupsig_key_t *grpkey,
				  groupsig_proof_t *proof,
				  message_t *msg,
				  groupsig_signature_t **sigs,
				  message_t **msgs,
				  uint32_t n);

  /** 
   * @struct groupsig_t
   * @brief Defines the structure for group signature scheme handles.
   */
  typedef struct {
    const groupsig_description_t *desc; /**< The scheme's description. */
    init_f init; /**< Initializes internal data structures used by the schemes. */
    clear_f clear; /**< Frees the internal data structures used by the schemes. */
    setup_f setup; /**< The schemes setup function. */
    get_joinseq_f get_joinseq; /**< Returns the number of messages in the 
				  join protocol. */
    get_joinstart_f get_joinstart; /**< Returns who begins the join protocol. */
    join_mem_f join_mem; /**< The member side join function. */
    join_mgr_f join_mgr; /**< The manager side join function. */
    sign_f sign; /**< Signs messages. */
    verify_f verify; /**< Verifies group signatures. */
    verify_batch_f verify_batch; /**< Verifies batches of group signatures. */
    open_f open; /**< Opens group signatures. */
    open_verify_f open_verify; /**< Verifies proofs of opening. */
    reveal_f reveal; /**< Reveals tracing trapdoors. */
    trace_f trace; /**< Traces signers. */
    claim_f claim; /**< Issues proofs of ownership. */
    claim_verify_f claim_verify; /**< Verifies proofs of ownership. */
    prove_equality_f prove_equality; /**< Proves that several signatures have
					been issued by the same member. */
    prove_equality_verify_f prove_equality_verify; /**< Verifies proofs demonstrating
						      "prove_equalities". */
    blind_f blind; /**< Creates a blinded version of a group signature. */
    convert_f convert; /**< Converts a group signature so that in can be processed
			  (traced). */
    unblind_f unblind; /**< Unblinds the nym inside a blinded group signature. */
    identify_f identify; /**< Invoked by a member, determines whether or not a given
			  signature was issued by this member. */
    link_f link; /**< Creates a proof of a set of signatures being linked. */
    verify_link_f verify_link; /**< Verifies a proof of link. */
    seqlink_f seqlink; /**< Creates a proof of a set of signatures being 
			  sequentially linked. */
    verify_seqlink_f verify_seqlink; /* Verifies a proof of sequential link. */
  } groupsig_t;

  /* Function implementations */


  /** 
   * @fn int groupsig_hello_world(void)
   * @brief Hello world function. For testing mainly.
   * 
   * Prints "Hello, World!\n" in stdout.
   *
   * @return 0
   */
  int groupsig_hello_world(void);

  /** 
   * @fn uint8_t groupsig_is_supported_scheme(uint8_t code)
   * @brief Returns 1 if a group signature scheme with the given code is supported. 
   * Returns 0 otherwise.
   *
   * @param[in] code The code to check.
   * 
   * @return 1 or 0
   */
  uint8_t groupsig_is_supported_scheme(uint8_t code);

  /** 
   * @fn const groupsig_t* groupsig_get_groupsig_from_str(char *str, groupsig_t *gs)
   * @brief Returns the bundle associated to the given groupsig name.
   *
   * @param[in] str The groupsig name.
   * 
   * @return The associated groupsig bundle or NULL.
   */
  const groupsig_t* groupsig_get_groupsig_from_str(char *str);

  /** 
   * @fn const groupsig_t* groupsig_get_groupsig_from_code(uint8_t code)
   * @brief Returns the bundle associated to the given groupsig code.
   *
   * @param[in] code The groupsig code.
   * 
   * @return The associated groupsig bundle or NULL.
   */
  const groupsig_t* groupsig_get_groupsig_from_code(uint8_t code);

  /*
   * @fn const char* groupsig_get_name_from_code(uint8_t code)
   * @brief Returns the name associated to the given scheme code.
   *
   * @param[in] code The groupsig code.
   * 
   * @return The associated groupsig bundle or NULL.
   */
  const char* groupsig_get_name_from_code(uint8_t code); 

  /** 
   * @fn int groupsig_init(uint8_t code, unsigned int seed)
   * @brief Initializes the group signature environment (random number generators, 
   *  etc.).
   *
   * @param[in] code The scheme's code.
   * @param[in] seed The seed to use for the [P]RNG.
   * 
   * @return IOK or IERROR.
   */
  int groupsig_init(uint8_t code, unsigned int seed);


  /** 
   * @fn groupsig_clear(uint8_t code)
   * @brief Frees all the memory allocated for a group signature scheme environment.
   * 
   * @param[in] code The groupsig code.
   *
   * @return IOK or IERROR.
   */
  int groupsig_clear(uint8_t code);

  /** 
   * @fn int groupsig_setup(uint8_t code, groupsig_key_t *grpkey, groupsig_key_t *mgrkey, 
   *		          gml_t *gml)
   * @brief Executes the setup function of the scheme with the specified code. 
   *
   *  Executes the setup function of the scheme with the specified code, filling
   *  the group key, manager key and GML.
   *
   * @param[in] code The group signature scheme code.
   * @param[in,out] grpkey An initialized group key. Will be set to the final group
   *  key.
   * @param[in,out] mgrkey An initialized group manager key. Will be set to the final
   *  group manager key.
   * @param[in,out] gml An initialized GML. Will be set to the created GML.
   * 
   * @return IOK or IERROR.
   * 
   */
  int groupsig_setup(uint8_t code,
		     groupsig_key_t *grpkey,
		     groupsig_key_t *mgrkey, 
		     gml_t *gml);

  /**
   * @fn int groupsig_get_joinseq(uint8_t code, uint8_t *seq)
   * @brief Returns the number of messages to be exchanged in the join protocol.
   * 
   * @param[in] code The scheme's code.
   * @param[in,out] seq A pointer to store the number of messages to exchange.
   *
   * @return IOK or IERROR.
   */ 
  int groupsig_get_joinseq(uint8_t code, uint8_t *seq);

  /**
   * @fn int groupsig_get_joinstart(uint8_t code, uint8_t *start)
   * @brief Returns who sends the first message in the join protocol.
   * 
   * @param[in] code The scheme's code.
   * @param[in,out] start A pointer to store the who starts the join protocol. 0 
   *  means the Manager starts the protocol, 1 means the Member starts the 
   *  protocol.
   *
   * @return IOK or IERROR.
   */
  int groupsig_get_joinstart(uint8_t code, uint8_t *start);

  /** 
   * @fn int groupsig_join_mem(void **mout, groupsig_key_t *memkey, 
   *                           int seq, message_t *min, groupsig_key_t *grpkey)
   * @brief Executes the join member action of the scheme associated to the
   *  received tokens.
   *
   * The member key will be updated to the member-side generated key information.
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
   *
   */
  int groupsig_join_mem(message_t **mout,
			groupsig_key_t *memkey,
			int seq,
			message_t *min,
			groupsig_key_t *grpkey);

  /** 
   * @fn int groupsig_join_mgr(message_t *mout, gml_t *gml, groupsig_key_t *mgrkey,
   *		             int seq, message_t *min, groupsig_key_t *grpkey)
   * @brief Runs the manager side join of the specified group signature scheme.
   *
   * Runs the manager side join of the specified group signature scheme. As a result,
   * the received member key is completed, and a new entry related to the new member
   * is added to the GML.
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
   * 
   * @return IOK or IERROR.
   *
   */
  int groupsig_join_mgr(message_t **mout,
			gml_t *gml,
			groupsig_key_t *mgrkey,
			int seq,
			message_t *min,
			groupsig_key_t *grpkey);

  /** 
   * @fn int groupsig_sign(groupsig_signature_t *sig, message_t *msg, 
   *		  groupsig_key_t *memkey, 
   *		  groupsig_key_t *grpkey, unsigned int seed)
   * @brief Runs the signing algorithm of the scheme associated with the received
   *        tokens.
   *
   * @param[in,out] sig The group signature structure to be filled. Must be initialized
   *  by the caller.
   * @param[in] msg The message to sign.
   * @param[in] memkey The member key to use for signing.
   * @param[in] grpkey The group key.
   * @param[in] seed When different to UINT_MAX, the specified seed will be sued
   *  for reseeding the PRNG. If UINT_MAX, the current state of the random number
   *  generator will be used.
   * 
   * @return IOK or IERROR.
   *
   */
  int groupsig_sign(groupsig_signature_t *sig,
		    message_t *msg, 
		    groupsig_key_t *memkey, 
		    groupsig_key_t *grpkey,
		    unsigned int seed);

  /** 
   * @fn int groupsig_verify(uint8_t *ok, groupsig_signature_t *sig, 
   *                  message_t *msg, groupsig_key_t *grpkey)
   * @brief Verifies group signatures of the given scheme.
   *
   * @param[in,out] ok Will be set to 1 if the signature is correct. To 0 otherwise.
   * @param[in] sig The signature to verify.
   * @param[in] msg The message related to the signature.
   * @param[in] grpkey The group key.
   * 
   * @return IOK or IERROR.
   */
  int groupsig_verify(uint8_t *ok,
		      groupsig_signature_t *sig,
		      message_t *msg, 
		      groupsig_key_t *grpkey);

  /** 
   * @fn int groupsig_verify_batch(uint8_t *ok, 
   *                               groupsig_signature_t **sig, 
   *                               message_t **msg, 
   *                               uint32_t n,
   *                               groupsig_key_t *grpkey)
   * @brief Verifies batches of signatures.
   *
   * @param[in,out] ok Will be set to 1 if all the signatures are correct.
   *  To 0 otherwise.
   * @param[in] sigs The signatures to verify.
   * @param[in] msgs The messages related to the signatures.
   * @param[in] n The size of the sigs and msgs arrays.
   * @param[in] grpkey The group key.
   * 
   * @return IOK or IERROR.
   */  
  int groupsig_verify_batch(uint8_t *ok,
			    groupsig_signature_t **sigs,
			    message_t **msgs,
			    uint32_t n,
			    groupsig_key_t *grpkey);
    
  /** 
   * @fn int groupsig_reveal(trapdoor_t *trap, crl_t *crl, gml_t *gml, uint64_t index)
   * @brief Reveals the tracing trapdoor of the member in position <i>index</i> within 
   *  the given GML.
   * 
   *  Reveals the tracing trapdoor of the member in position <i>index</i> within 
   *  the given GML. If a CRL is provided, a new entry with the retrieved trapdoor
   *  is added to it.
   *
   * @param[in,out] trap An initialized trapdoor. Will be updated with the trapdoor
   *  of the member with <i>index</i> index.
   * @param[in,out] crl When not NULL, a new entry will be added corresponding to the
   *  member with the specified index.
   * @param[in] gml The GML.
   * @param[in] index The position within the GML of the member to be revealed.
   * 
   * @return IOK or IERROR.
   *
   */
  int groupsig_reveal(trapdoor_t *trap,
		      crl_t *crl,
		      gml_t *gml,
		      uint64_t index);

  /** 
   * @fn int groupsig_open(uint64_t *index, groupsig_proof_t *proof, 
   *                       crl_t *crl, groupsig_signature_t *sig,  
   *		           groupsig_key_t *grpkey, groupsig_key_t *mgrkey, 
   *                       gml_t *gml)
   * @brief Returns the real identity of the issuer of the given signature. 
   *
   * Returns the real identity of the issuer of the given signature. Currently, the
   * identity is the index within the given GML.
   *
   * @param[in,out] index Will be set to the index of the user who created
   *  the given signature.
   * @param[in,out] proof An initialized proof of opening, or NULL if the called 
   *  scheme does not produce proofs of opening.
   * @param[in] crl If not NULL, a new entry will be added to the CRL, associated
   *  to the member with the given index.
   * @param[in] sig The signature to open.
   * @param[in] grpkey The group key.
   * @param[in] mgrkey The manager key.
   * @param[in] gml The GML.
   * 
   * @return IOK if it was possible to open the signature. IFAIL if the open
   *  trapdoor was not found, IERROR otherwise.
   */
  int groupsig_open(uint64_t *index,
		    groupsig_proof_t *proof,
		    crl_t *crl, 
		    groupsig_signature_t *sig,
		    groupsig_key_t *grpkey, 
		    groupsig_key_t *mgrkey,
		    gml_t *gml);

  /** 
   * @fn int open_verify(uint8_t *ok, groupsig_proof_t *proof, 
   *                     groupsig_signature_t *sig, groupsig_key_t *grpkey)
   * 
   * @param[in,out] ok Will be set to 1 if the proof is correct, to 0 otherwise.
   *  signature.
   * @param[in] proof The proof of opening.
   * @param[in] sig The group signature associated to the proof.
   * @param[in] grpkey The group key.
   * 
   * @return IOK or IERROR
   */
  int groupsig_open_verify(uint8_t *ok, 
			   groupsig_proof_t *proof, 
			   groupsig_signature_t *sig, 
			   groupsig_key_t *grpkey);

  /** 
   * @fn int groupsig_trace(uint8_t *ok, groupsig_signature_t *sig, 
   *		   groupsig_key_t *grpkey, crl_t *crl)
   * @brief Determines whether or not the issuer of the specified signature has
   *  been revoked according to the given CRL.
   *
   * @param[in,out] ok Will be set to 1 if the signer of <i>sig</i> is revoked,
   *  to 0 otherwise.
   * @param[in] sig The group signature to trace.
   * @param[in] grpkey The group key.
   * @param[in] crl The CRL.
   * @param[in] mgrkey Schemes that do not include native support for tracing may
   *  "emulate" it by opening group signatures. Hence, they will need the manager
   *  key. In traceable schemes, this parameter may be ignored.
   * @param[in] gml Schemes that do not include native support for tracing may
   *  "emulate" it by opening group signatures. Hence, they will need the GML.
   *  In traceable schemes, this parameter may be ignored.
   * 
   * @return IOK or IERROR.
   */
  int groupsig_trace(uint8_t *ok,
		     groupsig_signature_t *sig,
		     groupsig_key_t *grpkey,
		     crl_t *crl,
		     groupsig_key_t *mgrkey,
		     gml_t *gml);

  /** 
   * @fn int groupsig_claim(groupsig_proof_t *proof, groupsig_key_t *memkey, 
   *                 groupsig_key_t *grpkey, groupsig_signature_t *sig)
   * @brief Issues a proof claiming having issued the specified signature.
   *
   * The proofs generated with this function are ZKP.
   *
   * @param[in,out] proof An initialized proof. Will be updated to contain the 
   *  generated proof.
   * @param[in] memkey The group member key.
   * @param[in] grpkey The group key.
   * @param[in] sig The signature to prove.
   * 
   * @return IOK or IERROR.
   *
   */
  int groupsig_claim(groupsig_proof_t *proof,
		     groupsig_key_t *memkey,
		     groupsig_key_t *grpkey, 
		     groupsig_signature_t *sig);

  /** 
   * @fn int groupsig_claim_verify(uint8_t *ok, 
   *                               groupsig_proof_t *proof, 
   *                               groupsig_signature_t *sig, 
   *			           groupsig_key_t *grpkey)
   * @brief Verifies a "claim" proof.
   *
   * @param[in,out] ok Will be set to 1 if the proof is correct, to 0 otherwise.
   * @param[in] proof The proof to verify.
   * @param[in] sig The signature related to the proof.
   * @param[in] grpkey The group key.
   * 
   * @return IOK or IERROR.
   *
   */
  int groupsig_claim_verify(uint8_t *ok,
			    groupsig_proof_t *proof,
			    groupsig_signature_t *sig, 
			    groupsig_key_t *grpkey);

  /** 
   * @fn int groupsig_prove_equality(groupsig_proof_t *proof, groupsig_key_t *memkey, 
   *			    groupsig_key_t *grpkey, groupsig_signature_t **sigs, uint16_t n_sigs)
   * @brief Issues a proof demonstrating that all the signatures in <i>sigs</i> have
   *  been issued using <i>memkey</i>.
   *
   *  The proofs generated using this function are ZKP.
   *
   * @param[in,out] proof An initialized proof. Will be updated with the generated
   * proof.
   * @param[in] memkey The member key used for generating the proof. Must be the same
   *  that was used for issuing <i>sigs</i>.
   * @param[in] grpkey The group key.
   * @param[in] sigs The signatures to prove.
   * @param[in] n_sigs The number of signatures in <i>sigs</i>.
   * 
   * @return IOK or IERROR.
   */
  int groupsig_prove_equality(groupsig_proof_t *proof,
			      groupsig_key_t *memkey, 
			      groupsig_key_t *grpkey,
			      groupsig_signature_t **sigs,
			      uint16_t n_sigs);

  /** 
   * @fn int groupsig_prove_equality_verify(uint8_t *ok, groupsig_proof_t *proof, 
   *				   groupsig_key_t *grpkey, groupsig_signature_t **sigs, 
   *				   uint16_t n_sigs)
   * @brief Verifies "proofs of equality".
   *
   * @param[in,out] ok Will be set to 1 if the proof is correct, to 0 otherwise.
   * @param[in] proof The proof to verify.
   * @param[in] grpkey The group key.
   * @param[in] sigs The signatures related to the proof.
   * @param[in] n_sigs The number of signatures in <i>sigs</i>.
   * 
   * @return IOK or IERROR.
   */
  int groupsig_prove_equality_verify(uint8_t *ok,
				     groupsig_proof_t *proof, 
				     groupsig_key_t *grpkey,
				     groupsig_signature_t **sigs, 
				     uint16_t n_sigs);

  /** 
   * @fn int groupsig_blind(groupsig_blindsig_t *bsig, groupsig_key_t **bldkey, 
   *                        groupsig_key_t *grpkey, groupsig_signature_t *sig,
   *                        message_t *msg)
   * @brief Blinding of group signatures.
   *
   * @param[in,out] bsig The produced blinded group signature.
   *  Must be allocated by the caller.
   * @param[in,out] bldkey The key used for blinding. If NULL, a fresh one
   *  is created.
   * @param[in] grpkey The group key.
   * @param[in] sig The group signature to blind.
   * @param[in] msg The signed message.
   * 
   * @return IOK or IERROR.
   */
  int groupsig_blind(groupsig_blindsig_t *bsig,
		     groupsig_key_t **bldkey,
		     groupsig_key_t *grpkey,
		     groupsig_signature_t *sig,
		     message_t *msg);

  /** 
   * @fn int groupsig_convert(groupsig_blindsig_t **csig,
   *                          groupsig_blindsig_t **bsig, uint32_t n_bsigs,
   *			      groupsig_key_t *grpkey, groupsig_key_t *mgrkey,
   *                          groupsig_key_t *bldkey, message_t *msg)
   * @brief Converts blinded group signatures.
   *
   * @param[in,out] csig Array to store the converted signatures.
   * @param[in] bsig The blinded signatures to be converted.
   * @param[in] n_bsigs The size of the previous array.
   * @param[in] grpkey The group public key.
   * @param[in] mgrkey The 'manager' key (containing at least 
   *  the converting key).
   * @param[in] bldkey The public blinding key.
   * @param[in] msg The signed messages. Optional.
   * 
   * @return IOK or IERROR.
   */
  int groupsig_convert(groupsig_blindsig_t **csig,
		       groupsig_blindsig_t **bsig,
		       uint32_t n_bsigs,
		       groupsig_key_t *grpkey,
		       groupsig_key_t *mgrkey,
		       groupsig_key_t *bldkey,
		       message_t *msg);

  /**
   * @fn int groupsig_unblind(identity_t *nym, groupsig_signature_t *sig,
   *                          groupsig_blindsig_t *bsig,
   *                          groupsig_key_t *grpkey, groupsig_key_t *bldkey,
   *                          message_t *msg)
   * @brief Unblinds group signatures.
   *
   * @param[in,out] nym The unblinded nym (might be ignored).
   * @param[in,out] sig The unblinded signature (might be ignored).
   * @param[in] bsig The blinded signature.
   * @param[in] grpkey The group key.
   * @param[in] bldkey The key used for blinding. If NULL, a fresh one
   *  is created.
   * @param[in,out] msg The signed message. Optional.
   * 
   * @return IOK or IERROR.
   */
  int groupsig_unblind(identity_t *nym,
		       groupsig_signature_t *sig,
		       groupsig_blindsig_t *bsig,
		       groupsig_key_t *grpkey,
		       groupsig_key_t *bldkey,
		       message_t *msg);


  /** 
   * @fn int groupsig_identify(uint8_t *ok,
   *                           groupsig_proof_t **proof,
   *                           groupsig_key_t *grpkey, 
   *                           groupsig_key_t *memkey,
   *                           groupsig_signature_t *sig,
   *                           message_t *msg)
   * @brief Enables a member to determine whether a specific signature has been 
   *  issued by him/herself or not.
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
  int groupsig_identify(uint8_t *ok,
			groupsig_proof_t **proof,
			groupsig_key_t *grpkey,
			groupsig_key_t *memkey,
			groupsig_signature_t *sig,
			message_t *msg);
  
  /** 
   * @fn int groupsig_link(groupsig_proof_t **proof,
   *                       groupsig_key_t *grpkey, 
   *                       groupsig_key_t *memkey,
   *                       message_t *msg,
   *                       groupsig_signature_t **sigs,
   *                       message_t **msgs,
   *                       uint32_t n)
   * @brief Issues proofs of several signatures being linked (issued by the
   *  same member.)
   *
   * @param[in,out] proof The proof to be issued.
   * @param[in] grpkey The group key.
   * @param[in] memkey The key used for issuing the individual signatures.
   * @param[in] msg The message to add to the created proof (prevents replays.)
   * @param[in] sigs The signatures to link.
   * @param[in] msgs The signed messages.
   * @param[in] n The size of the sigs and msgs arrays.
   * 
   * @return IOK if link was produced correctly; IFAIL if the signatures
   * do not verify correctly or identify to the user. IERROR if something
   * misbehaved.
   */
  int groupsig_link(groupsig_proof_t **proof,
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
   * @brief Verifies proofs of several signatures being linked.
   *
   * @param[in,out] ok Will be set to 1 (proof valid) or 0 (proof invalid).
   * @param[in] grpkey The group key.
   * @param[in] proof The proof.
   * @param[in] msg The message to add to the created proof (prevents replays.)
   * @param[in] sigs The signatures to link.
   * @param[in] msgs The signed messages. 
   * @param[in] n The size of the sig and msg arrays.
   * 
   * @return IOK or IERROR.
   */
  int groupsig_verify_link(uint8_t *ok,
			   groupsig_key_t *grpkey,
			   groupsig_proof_t *proof,
			   message_t *msg,
			   groupsig_signature_t **sig,
			   message_t **msgs,
			   uint32_t n);
  
  /** 
   * @fn int groupsig_seqlink(groupsig_proof_t **proof,
   *                          groupsig_key_t *grpkey, 
   *                          groupsig_key_t *memkey,
   *                          message_t *msg,
   *                          groupsig_signature_t **sigs,
   *                          message_t **msgs,
   *                          uint32_t n)
   * @brief Issues proofs of several signatures being sequentially linked 
   * (the *sigs array must be correctly ordered!)
   *
   * @param[in,out] proof The proof to be issued.
   * @param[in] grpkey The group key.
   * @param[in] memkey The key used for issuing the individual signatures.
   * @param[in] msg The message to add to the created proof (prevents replays.)
   * @param[in] sigs The signatures to sequentially link.
   * @param[in] msgs The signed messages.
   * @param[in] n The size of the sig and msg arrays.
   * 
   * @return IOK if link was produced correctly; IFAIL if the signatures
   * do not verify correctly or identify to the user. IERROR if something
   * misbehaved.
   */
  int groupsig_seqlink(groupsig_proof_t **proof,
		       groupsig_key_t *grpkey,
		       groupsig_key_t *memkey,
		       message_t *msg,
		       groupsig_signature_t **sigs,
		       message_t **msgs,
		       uint32_t n);
  
  /** 
   * @fn int groupsig_verify_seqlink(uint8_t *ok,
   *                                 groupsig_key_t *grpkey,
   *                                 groupsig_proof_t *proof, 
   *                                 message_t *msg,
   *                                 groupsig_signature_t **sigs,
   *                                 message_t **msgs,
   *                                 uint32_t n)
   * @brief Verifies proofs of several signatures being sequentially linked 
   *  (the *sigs array must be correctly ordered!)
   *
   * @param[in,out] ok Will be set to 1 (proof valid) or 0 (proof invalid).
   * @param[in] grpkey The group key.
   * @param[in] proof The proof.
   * @param[in] msg The message to add to the created proof (prevents replays.)
   * @param[in] sigs The signatures to link.
   * @param[in] msgs The signed messages. 
   * @param[in] n The size of the sig and msg arrays.
   * 
   * @return IOK or IERROR.
   */
  int groupsig_verify_seqlink(uint8_t *ok,
			      groupsig_key_t *grpkey,
			      groupsig_proof_t *proof,
			      message_t *msg,
			      groupsig_signature_t **sigs,
			      message_t **msgs,
			      uint32_t n);

  /** 
   * @fn int groupsig_get_code_from_str(uint8_t *code, char *name)
   * @brief Sets <i>groupsig</i> to the code associated to the given groupsig name.
   *
   * @param[in,out] code The groupsig code.
   * @param[in] name The groupsig name.
   * 
   * @return IOK with code set to the groupsig code. IFAIL if the name does not
   *  correspond to any groupsig name, or IERROR if error.
   */
  int groupsig_get_code_from_str(uint8_t *code, char *name);

  /* Include here all known group signature schemes */
#include "registered_groupsigs.h"
  
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _GROUPSIG_H */
/* groupsig.h ends here */
