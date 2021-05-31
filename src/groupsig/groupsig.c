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

#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#include "groupsig.h"
#include "sysenv.h"
#include "sys/mem.h"
#include "registered_groupsigs.h"

#define GROUPSIG_REGISTERED_GROUPSIGS_N 6
static const groupsig_t *GROUPSIG_REGISTERED_GROUPSIGS[GROUPSIG_REGISTERED_GROUPSIGS_N] = {
  /* &kty04_groupsig_bundle, */
  &bbs04_groupsig_bundle,
  /* &cpy06_groupsig_bundle, */
  &gl19_groupsig_bundle,
  &ps16_groupsig_bundle,
  &klap20_groupsig_bundle,
  &dl21_groupsig_bundle,
  &dl21seq_groupsig_bundle,  
};

int groupsig_hello_world(void) {
  fprintf(stdout, "Hello, World!\n");
  return 0;
}

uint8_t groupsig_is_supported_scheme(uint8_t code) {

  int i;

  for(i=0; i<GROUPSIG_REGISTERED_GROUPSIGS_N; i++) {
    if(code == GROUPSIG_REGISTERED_GROUPSIGS[i]->desc->code) return 1;
  }

  return 0;

}

const groupsig_t* groupsig_get_groupsig_from_str(char *str) {

  uint8_t i;

  if(!str) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_get_groupsig_from_str", __LINE__, LOGERROR);
    return NULL;
  }

  for(i=0; i<GROUPSIG_REGISTERED_GROUPSIGS_N; i++) {
    if(!strcasecmp(str, GROUPSIG_REGISTERED_GROUPSIGS[i]->desc->name)) {
      return GROUPSIG_REGISTERED_GROUPSIGS[i];
    }
  }

  return NULL;

}

const groupsig_t* groupsig_get_groupsig_from_code(uint8_t code) {

  uint8_t i;

  for(i=0; i<GROUPSIG_REGISTERED_GROUPSIGS_N; i++) {
    if(code == GROUPSIG_REGISTERED_GROUPSIGS[i]->desc->code) {
      return GROUPSIG_REGISTERED_GROUPSIGS[i];
    }
  }

  return NULL;

}

const char* groupsig_get_name_from_code(uint8_t code) {

  uint8_t i;

  for(i=0; i<GROUPSIG_REGISTERED_GROUPSIGS_N; i++) {
    if(code == GROUPSIG_REGISTERED_GROUPSIGS[i]->desc->code) {
      return GROUPSIG_REGISTERED_GROUPSIGS[i]->desc->name;
    }
  }

  return NULL;
  
}

int groupsig_init(uint8_t code,
		  unsigned int seed) {

  const groupsig_t *gs;
  
  if(!(gs = groupsig_get_groupsig_from_code(code))) {
    return IERROR;
  }

  /* 1) System-wide environment: right now, only seed the PRNGs */
  if(!(sysenv = sysenv_init(seed))) {
    return IERROR;
  }

  /* 2) Scheme-specific variables */
  return gs->init();

}

int groupsig_clear(uint8_t code) {

  const groupsig_t *gs;
  
  if(!(gs = groupsig_get_groupsig_from_code(code))) {
    return IERROR;
  }

  /* 1) System-wide environment: right now, only seed the PRNGs */
  if (sysenv) { sysenv_free(sysenv); sysenv = NULL; }

  /* 2) Scheme-specific data */
  return gs->clear();

}

int groupsig_get_joinseq(uint8_t code,
			 uint8_t *seq) {

  const groupsig_t *gs;
  
  /* Get the group signature scheme from its code */
  if(!(gs = groupsig_get_groupsig_from_code(code))) {
    return IERROR;
  }  
  
  /* Run the JOINSEQ action */
  return gs->get_joinseq(seq);
  
}

int groupsig_get_joinstart(uint8_t code,
			   uint8_t *start) {

  const groupsig_t *gs;
  
  /* Get the group signature scheme from its code */
  if(!(gs = groupsig_get_groupsig_from_code(code))) {
    return IERROR;
  }  
  
  /* Run the JOINSTART action */
  return gs->get_joinstart(start);
  
}

int groupsig_setup(uint8_t code,
		   groupsig_key_t *grpkey, 
		   groupsig_key_t *mgrkey,
		   gml_t *gml) {

  const groupsig_t *gs;

  /* The only mandatory parameters are grpkey and mgrkey; gml and config depend on
     the specific scheme (although they would probably be required too). */
  if(!grpkey || !mgrkey) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_setup", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the group signature scheme from its code */
  if(!(gs = groupsig_get_groupsig_from_code(code))) {
    return IERROR;
  }  

  /* Run the SETUP action */
  return gs->setup(grpkey, mgrkey, gml);

}

int groupsig_join_mem(message_t **mout,
		      groupsig_key_t *memkey,
		      int seq,
		      message_t *min,
		      groupsig_key_t *grpkey) {

  const groupsig_t *gs;

  if(!mout || !memkey || !grpkey ||
     memkey->scheme != grpkey->scheme) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_join_mem", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the group signature scheme from its code */
  if(!(gs = groupsig_get_groupsig_from_code(grpkey->scheme))) {
    return IERROR;
  }  

  /* Run the JOINMEM action */
  return gs->join_mem(mout, memkey, seq, min, grpkey);

}

int groupsig_join_mgr(message_t **mout,
		      gml_t *gml,
		      groupsig_key_t *mgrkey,
		      int seq,
		      message_t *min, groupsig_key_t *grpkey) {

  const groupsig_t *gs;

  /* The mandatory parameters at this point are the manager and group keys; the 
     gml, even though it is an [in,out] parameter, may be omitted in schemes 
     that do not keep a transcript of joins (a.k.a. membership list). */
  if(!mout || !mgrkey || !grpkey ||  mgrkey->scheme != grpkey->scheme) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_join_mgr", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the group signature scheme from its code */
  if(!(gs = groupsig_get_groupsig_from_code(grpkey->scheme))) {
    return IERROR;
  }  

  /* Run the JOINMGR action */
  return gs->join_mgr(mout, gml, mgrkey, seq, min, grpkey);

}

int groupsig_sign(groupsig_signature_t *sig,
		  message_t *msg,
		  groupsig_key_t *memkey, 
		  groupsig_key_t *grpkey,
		  unsigned int seed) {

  const groupsig_t *gs;

  if(!sig || !msg || !memkey || !grpkey ||
     sig->scheme != memkey->scheme || memkey->scheme != grpkey->scheme) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_sign", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the group signature scheme from its code */
  if(!(gs = groupsig_get_groupsig_from_code(grpkey->scheme))) {
    return IERROR;
  }  

  /* Run the SIGN action */
  return gs->sign(sig, msg, memkey, grpkey, seed);

}

int groupsig_verify(uint8_t *ok,
		    groupsig_signature_t *sig,
		    message_t *msg,
		    groupsig_key_t *grpkey) {

  const groupsig_t *gs;

  if(!ok || !sig || !msg || !grpkey ||
     sig->scheme != grpkey->scheme) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_verify", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the group signature scheme from its code */
  if(!(gs = groupsig_get_groupsig_from_code(grpkey->scheme))) {
    return IERROR;
  }  

  /* Run the VERIFY action */
  return gs->verify(ok, sig, msg, grpkey);

}

int groupsig_verify_batch(uint8_t *ok,
			  groupsig_signature_t **sigs,
			  message_t **msgs,
			  uint32_t n,
			  groupsig_key_t *grpkey) {

  const groupsig_t *gs;

  if(!ok || !sigs || !msgs || !n || !grpkey) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_verify_batch", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the group signature scheme from its code */
  if(!(gs = groupsig_get_groupsig_from_code(grpkey->scheme))) {
    return IERROR;
  }  

  /* Run the VERIFY action */
  return gs->verify_batch(ok, sigs, msgs, n, grpkey);

}

int groupsig_open(uint64_t *index,
		  groupsig_proof_t *proof,
		  crl_t *crl, 
		  groupsig_signature_t *sig,
		  groupsig_key_t *grpkey, 
		  groupsig_key_t *mgrkey,
		  gml_t *gml) {

  const groupsig_t *gs;
  
  /* All the parameters are mandatory except the gml, which will depend on the
     specific scheme. Also, the type of ID will probably depend both on the
     scheme and the external application using the library. */
  if(!index || !sig || !grpkey || !mgrkey ||
     sig->scheme != grpkey->scheme || grpkey->scheme != mgrkey->scheme) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_open", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the group signature scheme from its code */
  if(!(gs = groupsig_get_groupsig_from_code(grpkey->scheme))) {
    return IERROR;
  }  

  /* Run the OPEN action */
  return gs->open(index, proof, crl, sig, grpkey, mgrkey, gml);

}

int groupsig_open_verify(uint8_t *ok, 
			 groupsig_proof_t *proof, 
			 groupsig_signature_t *sig, 
			 groupsig_key_t *grpkey) {
  
  const groupsig_t *gs;
  
  /* All the parameters are mandatory. */
  if(!proof || !sig || !grpkey || sig->scheme != grpkey->scheme ||
     proof->scheme != sig->scheme) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_open_verify", __LINE__, LOGERROR);
    return IERROR;
  }
  
  /* Get the group signature scheme from its code */
  if(!(gs = groupsig_get_groupsig_from_code(grpkey->scheme))) {
    return IERROR;
  }  
  
  /* Run the OPEN VERIFY action */
  return gs->open_verify(ok, proof, sig, grpkey);

}

int groupsig_reveal(trapdoor_t *trap,
		    crl_t *crl,
		    gml_t *gml,
		    uint64_t index) {

  const groupsig_t *gs;

  /* All the parameters but the CRL here are mandatory, although the type of 
     trapdoor will depend on the scheme and application. */
  if(!trap || !gml) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_reveal", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the group signature scheme from its code */
  if(!(gs = groupsig_get_groupsig_from_code(trap->scheme))) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_reveal", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Run the REVEAL action */
  return gs->reveal(trap, crl, gml, index);

}

int groupsig_trace(uint8_t *ok,
		   groupsig_signature_t *sig, 
		   groupsig_key_t *grpkey,
		   crl_t *crl,
		   groupsig_key_t *mgrkey,
		   gml_t *gml) {

  const groupsig_t *gs;

  /* Only ok, sig, grpkey, and crl are mandatory */
  if(!ok || !sig || !grpkey || !crl ||
     sig->scheme != grpkey->scheme) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_trace", __LINE__, LOGERROR);
    return IERROR;
  }

  /* If we have a manager  key its scheme needs to match the group key and we
   * must have a gml */
  if(mgrkey && (!gml || grpkey->scheme != mgrkey->scheme)){
    LOG_EINVAL(&logger, __FILE__, "groupsig_trace", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the group signature scheme from its code */
  if(!(gs = groupsig_get_groupsig_from_code(grpkey->scheme))) {
    return IERROR;
  }  

  /* Run the TRACE action */
  return gs->trace(ok, sig, grpkey, crl, mgrkey, gml);

}

int groupsig_claim(groupsig_proof_t *proof,
		   groupsig_key_t *memkey, 
		   groupsig_key_t *grpkey,
		   groupsig_signature_t *sig) {

  const groupsig_t *gs;

  /* All parameters are mandatory here */
  if(!proof || !memkey || !grpkey || !sig ||
     proof->scheme != sig->scheme ||
     memkey->scheme != grpkey->scheme || grpkey->scheme != sig->scheme) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_claim", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the group signature scheme from its code */
  if(!(gs = groupsig_get_groupsig_from_code(grpkey->scheme))) {
    return IERROR;
  }  

  /* Run the CLAIM action */
  return gs->claim(proof, memkey, grpkey, sig);

}

int groupsig_claim_verify(uint8_t *ok,
			  groupsig_proof_t *proof, 
			  groupsig_signature_t *sig,
			  groupsig_key_t *grpkey) {

  const groupsig_t *gs;

  /* All parameters are mandatory */
  if(!ok || !proof || !sig || !grpkey ||
     proof->scheme != sig->scheme || sig->scheme != grpkey->scheme) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_claim_verify", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the group signature scheme from its code */
  if(!(gs = groupsig_get_groupsig_from_code(grpkey->scheme))) {
    return IERROR;
  }  

  /* Run the CLAIMVER action */
  return gs->claim_verify(ok, proof, sig, grpkey);

}

int groupsig_prove_equality(groupsig_proof_t *proof,
			    groupsig_key_t *memkey, 
			    groupsig_key_t *grpkey,
			    groupsig_signature_t **sigs,
			    uint16_t n_sigs) {

  const groupsig_t *gs;

  /* All parameters are mandatory */
  if(!proof || !memkey || !grpkey || !sigs || !n_sigs ||
     proof->scheme != memkey->scheme || memkey->scheme != grpkey->scheme) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_prove_equality", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the group signature scheme from its code */
  if(!(gs = groupsig_get_groupsig_from_code(grpkey->scheme))) {
    return IERROR;
  }  

  /* Run the PROVEQCOMP action */
  return gs->prove_equality(proof, memkey, grpkey, sigs, n_sigs);

}

int groupsig_prove_equality_verify(uint8_t *ok,
				   groupsig_proof_t *proof,
				   groupsig_key_t *grpkey,
				   groupsig_signature_t **sigs,
				   uint16_t n_sigs) {

  const groupsig_t *gs;

  /* All parameters are mandatory */
  if(!ok || !proof || !grpkey || !sigs || !n_sigs ||
     proof->scheme != grpkey->scheme) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_prove_equality_verify",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the group signature scheme from its code */
  if(!(gs = groupsig_get_groupsig_from_code(grpkey->scheme))) {
    return IERROR;
  }  

  /* Run the PROVEQVER action */
  return gs->prove_equality_verify(ok, proof, grpkey, sigs, n_sigs);

}

int groupsig_blind(groupsig_blindsig_t *bsig,
		   groupsig_key_t **bldkey,
		   groupsig_key_t *grpkey,
		   groupsig_signature_t *sig,
		   message_t *msg) {

  const groupsig_t *gs;

  /* All parameters are mandatory except msg */
  if(!bsig || !bldkey || !grpkey || !sig) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_blind", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the group signature scheme from its code */
  if(!(gs = groupsig_get_groupsig_from_code(grpkey->scheme))) {
    return IERROR;
  }  

  /* Run the BLIND action */
  return gs->blind(bsig, bldkey, grpkey, sig, msg);
  
}

int groupsig_convert(groupsig_blindsig_t **csigs,
		     groupsig_blindsig_t **bsigs,
		     uint32_t n_bsigs,
		     groupsig_key_t *grpkey,
		     groupsig_key_t *mgrkey,
		     groupsig_key_t *bldkey,
		     message_t *msg) {

  const groupsig_t *gs;

  /* All parameters are mandatory except msg */
  if(!csigs || !bsigs || n_bsigs <= 0 || !grpkey || !mgrkey || !bldkey) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_convert", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the group signature scheme from its code */
  if(!(gs = groupsig_get_groupsig_from_code(grpkey->scheme))) {
    return IERROR;
  }  

  /* Run the CONVERT action */
  return gs->convert(csigs, bsigs, n_bsigs, grpkey, mgrkey, bldkey, msg);
  
}

int groupsig_unblind(identity_t *nym,
		     groupsig_signature_t *sig,
		     groupsig_blindsig_t *bsig,
		     groupsig_key_t *grpkey,
		     groupsig_key_t *bldkey,
		     message_t *msg) {

  const groupsig_t *gs;

  /* Check for mandatory parameters */
  if((!nym && !sig) || !bsig || !bldkey) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_unblind", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the group signature scheme from its code */
  if(!(gs = groupsig_get_groupsig_from_code(bldkey->scheme))) {
    return IERROR;
  }  

  /* Run the UNBLIND action */
  return gs->unblind(nym, sig, bsig, grpkey, bldkey, msg);
    
}

int groupsig_identify(uint8_t *ok,
		      groupsig_proof_t **proof,
		      groupsig_key_t *grpkey,
		      groupsig_key_t *memkey,
		      groupsig_signature_t *sig,
		      message_t *msg) {

  const groupsig_t *gs;

  /* Check for mandatory parameters */
  if(!ok || !grpkey || !memkey || !sig || !msg) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_unblind", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the group signature scheme from its code */
  if(!(gs = groupsig_get_groupsig_from_code(grpkey->scheme))) {
    return IERROR;
  }  

  /* Run the IDENTIFY action */
  return gs->identify(ok, proof, grpkey, memkey, sig, msg);
  
}

int groupsig_link(groupsig_proof_t **proof,
		  groupsig_key_t *grpkey,
		  groupsig_key_t *memkey,
		  message_t *msg,
		  groupsig_signature_t **sigs,
		  message_t **msgs,
		  uint32_t n) {
  
  const groupsig_t *gs;

  /* Check for mandatory parameters */
  if(!proof || !grpkey || !memkey || !msg || !sigs || !msgs || !n) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_link", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the group signature scheme from its code */
  if(!(gs = groupsig_get_groupsig_from_code(grpkey->scheme))) {
    return IERROR;
  }  
  
  /* Run the LINK action */
  return gs->link(proof, grpkey, memkey, msg, sigs, msgs, n);
  
}

int groupsig_verify_link(uint8_t *ok,
			 groupsig_key_t *grpkey,
			 groupsig_proof_t *proof,
			 message_t *msg,
			 groupsig_signature_t **sigs,
			 message_t **msgs,
			 uint32_t n) {

  const groupsig_t *gs;

  /* Check for mandatory parameters */
  if(!ok || !proof || !grpkey || !msg || !sigs || !msgs || !n) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_verify_link", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the group signature scheme from its code */
  if(!(gs = groupsig_get_groupsig_from_code(grpkey->scheme))) {
    return IERROR;
  }  
  
  /* Run the LINK action */
  return gs->verify_link(ok, grpkey, proof, msg, sigs, msgs, n);
  
}

int groupsig_seqlink(groupsig_proof_t **proof,
		     groupsig_key_t *grpkey,
		     groupsig_key_t *memkey,
		     message_t *msg,
		     groupsig_signature_t **sigs,
		     message_t **msgs,
		     uint32_t n) {

  const groupsig_t *gs;

  /* Check for mandatory parameters */
  if(!proof || !grpkey || !memkey || !msg || !sigs || !msgs || !n) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_seqlink", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the group signature scheme from its code */
  if(!(gs = groupsig_get_groupsig_from_code(grpkey->scheme))) {
    return IERROR;
  }  
  
  /* Run the LINK action */
  return gs->seqlink(proof, grpkey, memkey, msg, sigs, msgs, n);

}

int groupsig_verify_seqlink(uint8_t *ok,
			    groupsig_key_t *grpkey,
			    groupsig_proof_t *proof,
			    message_t *msg,
			    groupsig_signature_t **sigs,
			    message_t **msgs,
			    uint32_t n) {

  const groupsig_t *gs;

  /* Check for mandatory parameters */
  if(!ok || !proof || !grpkey || !msg || !sigs || !msgs || !n) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_verify_seqlink", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the group signature scheme from its code */
  if(!(gs = groupsig_get_groupsig_from_code(grpkey->scheme))) {
    return IERROR;
  }  
  
  /* Run the LINK action */
  return gs->verify_seqlink(ok, grpkey, proof, msg, sigs, msgs, n);
  
}

int groupsig_get_code_from_str(uint8_t *code,
			       char *name) {

  uint8_t i;

  if(!code || !name) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_get_groupsig_from_str", __LINE__, LOGERROR);
    return IERROR;
  }

  for(i=0; i<GROUPSIG_REGISTERED_GROUPSIGS_N; i++) {
    if(!strcasecmp(name, GROUPSIG_REGISTERED_GROUPSIGS[i]->desc->name)) {
      *code = GROUPSIG_REGISTERED_GROUPSIGS[i]->desc->code;
      return IOK;
    }
  }

  return IFAIL;

}

/* groupsig.c ends here */
