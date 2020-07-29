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

#ifndef _GL19_H
#define _GL19_H

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
 * @def GROUPSIG_GL19_CODE
 * @brief GL19 scheme code.
 */
#define GROUPSIG_GL19_CODE 3

/**
 * @def GROUPSIG_GL19_NAME
 * @brief GL19 scheme name.
 */
#define GROUPSIG_GL19_NAME "GL19"

/**
 * @var gl19_description
 * @brief GL19's description.
 */
static const groupsig_description_t gl19_description = {
  GROUPSIG_GL19_CODE, /**< GL19's scheme code. */
  GROUPSIG_GL19_NAME /**< GL19's scheme name. */
};

/* Metadata for the join protocol */

/* 0 means the first message is sent by the manager, 1 means the first message
   is sent by the member */
#define GL19_JOIN_START 0

/* Number of exchanged messages */
#define GL19_JOIN_SEQ 3

/*
 * @def GL19_CONFIG_SET_DEFAULTS
 * @brief Sets the configuration structure to the default values for
 *  GL19.
 */
#define GL19_CONFIG_SET_DEFAULTS(cfg) \
  ((groupsig_config_t *) cfg)->scheme = GROUPSIG_GL19_CODE;	\
  ((groupsig_config_t *) cfg)->has_gml = 0;			\
  ((groupsig_config_t *) cfg)->has_crl = 0;			\
  ((groupsig_config_t *) cfg)->has_pbc = 1;

/** 
 * @fn groupsig_config_t* gl19_config_init(void)
 * @brief Allocates memory for a GL19 config structure.
 * 
 * @return A pointer to the allocated structure or NULL if error.
 */
groupsig_config_t* gl19_config_init(void);

/** 
 * @fn int gl19_config_free(groupsig_config_t *cfg)
 * @brief Frees the memory of a GL19 config structure.
 * 
 * @param cfg The structure to free.
 *
 * @return A pointer to the allocated structure or NULL if error.
 */
int gl19_config_free(groupsig_config_t *cfg);

/** 
 * @fn int gl19_sysenv_update(void *data)
 * @brief Sets the GL19 internal environment data, i.e., the PBC params and pairings.
 *
 * @param data A gl19_sysenv_t structure containing the PBC params and pairings.
 * 
 * @return IOK or IERROR.
 */
int gl19_sysenv_update(void *data);

/** 
 * @fn void* gl19_sysenv_get(void)
 * @brief Returns the GL19 specific environment data.
 * 
 * @return A pointer to the GL19 specific environment data or NULL if error.
 */
void* gl19_sysenv_get(void);

/** 
 * @fn int gl19_sysenv_free(void)
 * @brief Frees the GL19 internal environment.
 * 
 * @return IOK or IERROR.
 */
int gl19_sysenv_free(void);

/** 
 * @fn int gl19_setup(groupsig_key_t *grpkey, groupsig_key_t *mgrkey, 
 *                     gml_t *gml, groupsig_config_t *config)
 * @brief The setup function for the GL19 scheme. Used to generate group public
 *  key and the managers keys.
 * 
 *  In GL19, we have two central entities (managers in libgroupsig jargon): the 
 *  Issuer, and the Converter. Both managers have public-private keypairs, their
 *  public parts being a part of the overall group public key. In order to 
 *  properly create the group public key and the manager's keys, we need to call
 *  setup twice. The first time it is called, a partial group public key will be
 *  generated, along with the Issuer's private key (i.e., the Issuer is expected
 *  to initiate this process.) The second call must receive as input the partial
 *  group public key obtained in the first call, and a new manager key. As a
 *  result of the second call, the group public key is completely set up, and the
 *  Converter's private key is also generated. Therefore, this second call is 
 *  expected to be made by the Converter.
 *
 *  To be precise, whenever an empty group public key (i.e., an initialized GL19
 *  groupsig_key_t struct, with all fields in the key sub-struct set to NULL), 
 *  with is assumed, the function assumes that this is a first call.
 *
 * @param[in,out] grpkey An initialized group key. In the first call, a partial
 *  group public key will be returned.
 * @param[in,out] mgrkey An initialized manager key. In the first call, it will
 *  be set to the Issuer's private key. In the second call, it will be set to 
 *  the converter's private key..
 * @param[in] gml Ignored.
 * @param[in] config Ignored.
 * 
 * @return IOK or IERROR.
 */
int gl19_setup(groupsig_key_t *grpkey, groupsig_key_t *mgrkey, gml_t *gml, groupsig_config_t *config);

/**
 * @fn int gl19_get_joinseq(uint8_t *seq)
 * @brief Returns the number of messages to be exchanged in the join protocol.
 * 
 * @param seq A pointer to store the number of messages to exchange.
 *
 * @return IOK or IERROR.
 */ 
int gl19_get_joinseq(uint8_t *seq);

/**
 * @fn int gl19_get_joinstart(uint8_t *start)
 * @brief Returns who sends the first message in the join protocol.
 * 
 * @param start A pointer to store the who starts the join protocol. 0 means
 *  the Manager starts the protocol, 1 means the Member starts the protocol.
 *
 * @return IOK or IERROR.
 */ 
int gl19_get_joinstart(uint8_t *start);

/** 
* @fn int gl19_join_mem(message_t **mout, groupsig_key_t *memkey,
 *			      int seq, message_t *min, groupsig_key_t *grpkey)
 * @brief Executes the member-side join of the GL19 scheme.
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
int gl19_join_mem(message_t **mout, groupsig_key_t *memkey,
		  int seq, message_t *min, groupsig_key_t *grpkey);

/** 
 * @fn int gl19_join_mgr(message_t **mout, gml_t *gml,
 *                            groupsig_key_t *mgrkey,
 *                            int seq, message_t *min, 
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
int gl19_join_mgr(message_t **mout, gml_t *gml,
		  groupsig_key_t *mgrkey,
		  int seq, message_t *min, groupsig_key_t *grpkey);

/** 
 * @fn int gl19_sign(groupsig_signature_t *sig, message_t *msg, groupsig_key_t *memkey, 
 *	              groupsig_key_t *grpkey, unsigned int seed)
 * @brief Issues GL19 group signatures.
 *
 * Using the specified member and group keys, issues a signature for the specified
 * message.
 *
 * @param[in,out] sig An initialized GL19 group signature. Will be updated with
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
int gl19_sign(groupsig_signature_t *sig, message_t *msg, groupsig_key_t *memkey, 
	       groupsig_key_t *grpkey, unsigned int seed);

/** 
 * @fn int gl19_verify(uint8_t *ok, groupsig_signature_t *sig, message_t *msg, 
 *		        groupsig_key_t *grpkey);
 * @brief Verifies a GL19 group signature.
 *
 * @param[in,out] ok Will be set to 1 if the verification succeeds, to 0 if
 *  it fails.
 * @param[in] sig The signature to verify.
 * @param[in] msg The corresponding message.
 * @param[in] grpkey The group key.
 * 
 * @return IOK or IERROR.
 */
int gl19_verify(uint8_t *ok, groupsig_signature_t *sig, message_t *msg, 
		 groupsig_key_t *grpkey);

/** 
 * @fn int gl19_blind(groupsig_blindsig_t *bsig, groupsig_key_t *bldkey, 
 *                    groupsig_key_t *grpkey, message_t *msg, 
 *                    groupsig_signature_t *sig)
 * @brief Blinding of group signatures.
 *
 * @param[in,out] bsig The produced blinded group signature.
 * @param[in,out] bldkey The key used for blinding. If NULL, a fresh one
 *  is created.
 * @param[in] grpkey The group key.
 * @param[in] sig The group signature to blind.
 * @param[in] msg The signed message.
 * 
 * @return IOK or IERROR.
 */
int gl19_blind(groupsig_blindsig_t *bsig, groupsig_key_t **bldkey,
	       groupsig_key_t *grpkey, groupsig_signature_t *sig,
	       message_t *msg);


/** 
 * @fn int gl19_convert(groupsig_blindsig_t **csig,
 *                      groupsig_blindsig_t **bsig, uint32_t n_bsigs,
 *	                groupsig_key_t *grpkey, groupsig_key_t *mgrkey,
 *                      groupsig_key_t *bldkey, message_t *msg)
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
int gl19_convert(groupsig_blindsig_t **csig,
		 groupsig_blindsig_t **bsig, uint32_t n_bsigs,
		 groupsig_key_t *grpkey, groupsig_key_t *mgrkey,
		 groupsig_key_t *bldkey, message_t *msg);

/**
 * @fn int gl19_unblind(identity_t *nym, groupsig_signature_t *sig,
 *                      groupsig_blindsig_t *bsig,
 *                      groupsig_key_t *grpkey, groupsig_key_t *bldkey,
 *                      message_t *msg)
 * @brief Unblinds the nym in a GL19 group signature.
 *
 * @param[in,out] nym The unblinded nym.
 * @param[in,out] sig The unblinded signature. Ignored.
 * @param[in] bsig The blinded signature.
 * @param[in] grpkey The group key.
 * @param[in] bldkey The key used for blinding. If NULL, a fresh one
 *  is created.
 * @param[in] msg The signed message. Optional.
 * 
 * @return IOK or IERROR.
 */
int gl19_unblind(identity_t *nym, groupsig_signature_t *sig,
		 groupsig_blindsig_t *bsig,
		 groupsig_key_t *grpkey, groupsig_key_t *bldkey,
		 message_t *msg);

/**
 * @var gl19_groupsig_bundle
 * @brief The set of functions to manage GL19 groups.
 */
static const groupsig_t gl19_groupsig_bundle = {
  &gl19_description, /**< Contains the GL19 scheme description. */
  &gl19_config_init, /**< Initializes a GL19 config structure. */
  &gl19_config_free, /**< Frees a GL19 config structure. */
  &gl19_sysenv_update, /**< Updates GL19's environment data, if any. */
  &gl19_sysenv_get, /**< Gets GL19's environment data, if any. */
  &gl19_sysenv_free, /**< Frees GL19's environment data, if any. */
  &gl19_setup, /**< Sets up GL19 groups. */
  &gl19_get_joinseq, /**< Returns the number of messages in the join 
			protocol. */
  &gl19_get_joinstart, /**< Returns who begins the join protocol. */
  &gl19_join_mem, /**< Executes member-side joins. */
  &gl19_join_mgr, /**< Executes manager-side joins. */
  &gl19_sign, /**< Issues GL19 signatures. */
  &gl19_verify, /**< Verifies GL19 signatures. */
  NULL, // &gl19_open, /**< Opens GL19 signatures. */
  NULL, // &gl19_open_verify_f, /**< GL19 does not create proofs of opening. */
  NULL, // &gl19_reveal, /**< Reveals the tracing trapdoor from GL19 signatures. */
  NULL, // &gl19_trace, /**< Traces the issuer of a signature. */ 
  NULL, // &gl19_claim, /**< Claims, in ZK, "ownership" of a signature. */
  NULL, // &gl19_claim_verify, /**< Verifies claims. */
  NULL, // &gl19_prove_equality, /**< Issues "same issuer" ZK proofs for several signatures. */
  NULL, // &gl19_prove_equality_verify, /**< Verifies "same issuer" ZK proofs. */
  &gl19_blind, /**< Blinds group signatures. */
  &gl19_convert, /**< Converts blinded group signatures. */
  &gl19_unblind, /**< Unblinds converted group signatures. */
  NULL, // &identify, /**< Determines whether a signature has been issued by a member. */
  NULL, // &link, 
  NULL, // &link_verify
  NULL, // &seqlink, 
  NULL, // &seqlink_verify
};

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif
  
#endif /* _GL19_H */

/* gl19.h ends here */
