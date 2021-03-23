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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "types.h"
#include "sysenv.h"
#include "gl19.h"
#include "logger.h"
#include "bigz.h"
#include "sys/mem.h"
#include "groupsig/gl19/bld_key.h"
#include "groupsig/gl19/grp_key.h"
#include "groupsig/gl19/mgr_key.h"
#include "groupsig/gl19/signature.h"
#include "groupsig/gl19/blindsig.h"
#include "groupsig/gl19/identity.h"
#include "shim/hash.h"

int gl19_blind(groupsig_blindsig_t *bsig, groupsig_key_t **bldkey,
	       groupsig_key_t *grpkey, groupsig_signature_t *sig,
	       message_t *msg) {

  pbcext_element_Fr_t *alpha, *beta, *gamma;
  pbcext_element_G1_t *aux, *h;
  groupsig_key_t *_bldkey;
  gl19_signature_t *gl19_sig;
  gl19_blindsig_t *gl19_bsig;
  gl19_grp_key_t *gl19_grpkey;
  gl19_bld_key_t *gl19_bldkey;
  hash_t *hm;
  int rc;
  
  if(!bsig || bsig->scheme != GROUPSIG_GL19_CODE ||
     !sig || sig->scheme != GROUPSIG_GL19_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_GL19_CODE ||
     !msg) {
    LOG_EINVAL(&logger, __FILE__, "gl19_blind", __LINE__, LOGERROR);
    return IERROR;
  }

  /* NOTE: This is the first scheme in the library that uses the encrypt and prove
     approach. If new schemes using this approach are added, it may be a good
     idea to create an internal abstraction for encryption. I have already created
     some of the stubs in the crypto/ folder, but then /regretted/ it (too much load
     as long as only one scheme in the library uses this). Keep it in mind. */
  
  gl19_grpkey = (gl19_grp_key_t *) grpkey->key;
  gl19_sig = (gl19_signature_t *) sig->sig;
  gl19_bsig = (gl19_blindsig_t *) bsig->sig;
  _bldkey = NULL;
  rc = IOK;

  alpha = NULL; beta = NULL; gamma = NULL;
  aux = NULL; h = NULL; hm = NULL;

  /* Create fresh blinding keypair */
  if(!*bldkey) {
    if(!(_bldkey = groupsig_bld_key_init(GROUPSIG_GL19_CODE)))
      GOTOENDRC(IERROR, gl19_blind);
    gl19_bldkey = (gl19_bld_key_t *) _bldkey->key;
    if(!(gl19_bldkey->sk = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, gl19_blind);
    if(pbcext_element_Fr_random(gl19_bldkey->sk) == IERROR)
      GOTOENDRC(IERROR, gl19_blind);
    if(!(gl19_bldkey->pk = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, gl19_blind);
    if(pbcext_element_G1_mul(gl19_bldkey->pk,
			     gl19_grpkey->g,
			     gl19_bldkey->sk) == IERROR)
      GOTOENDRC(IERROR, gl19_blind);
  } else {
    gl19_bldkey = (gl19_bld_key_t *) (*bldkey)->key;
  }

  /* Pick alpha, beta, gamma at random from Z^*_p */
  if(!(alpha = pbcext_element_Fr_init())) GOTOENDRC(IERROR, gl19_blind);
  if(pbcext_element_Fr_random(alpha) == IERROR) GOTOENDRC(IERROR, gl19_blind);
  if(!(beta = pbcext_element_Fr_init())) GOTOENDRC(IERROR, gl19_blind);
  if(pbcext_element_Fr_random(beta) == IERROR) GOTOENDRC(IERROR, gl19_blind);
  if(!(gamma = pbcext_element_Fr_init())) GOTOENDRC(IERROR, gl19_blind);
  if(pbcext_element_Fr_random(gamma) == IERROR) GOTOENDRC(IERROR, gl19_blind);
    
  /* Rerandomize the pseudonym encryption under the cpk and 
     add an encryption layer for the pseudonym under the bpk */

  if(!(gl19_bsig->nym1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_blind);
  if(!(gl19_bsig->nym2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_blind);
  if(!(gl19_bsig->nym3 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_blind);
  if(!(gl19_bsig->c1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_blind);
  if(!(gl19_bsig->c2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_blind);
  
  if(!(aux = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_blind);
  if(pbcext_element_G1_mul(aux, gl19_grpkey->g, beta) == IERROR)
    GOTOENDRC(IERROR, gl19_blind);
  if(pbcext_element_G1_add(gl19_bsig->nym1, gl19_sig->nym1, aux) == IERROR)
    GOTOENDRC(IERROR, gl19_blind);
  if(pbcext_element_G1_mul(gl19_bsig->nym2, gl19_grpkey->g, alpha) == IERROR)
    GOTOENDRC(IERROR, gl19_blind);
  if(pbcext_element_G1_mul(aux, gl19_grpkey->cpk, beta) == IERROR)
    GOTOENDRC(IERROR, gl19_blind);
  if(pbcext_element_G1_add(gl19_bsig->nym3, gl19_sig->nym2, aux) == IERROR)
    GOTOENDRC(IERROR, gl19_blind);
  if(pbcext_element_G1_mul(aux, gl19_bldkey->pk, alpha) == IERROR)
    GOTOENDRC(IERROR, gl19_blind);
  if(pbcext_element_G1_add(gl19_bsig->nym3, gl19_bsig->nym3, aux) == IERROR)
    GOTOENDRC(IERROR, gl19_blind);

  /* Encrypt the (hash of the) message */
  if(!(hm = hash_init(HASH_BLAKE2)))
    GOTOENDRC(IERROR, gl19_blind);
  if(hash_update(hm, msg->bytes, msg->length) == IERROR)
    GOTOENDRC(IERROR, gl19_blind);
  if(hash_finalize(hm) == IERROR)
    GOTOENDRC(IERROR, gl19_blind);

  if(!(h = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_blind);
  if(pbcext_element_G1_from_hash(h, hm->hash, hm->length) == IERROR)
    GOTOENDRC(IERROR, gl19_blind);
  if(pbcext_element_G1_mul(gl19_bsig->c1, gl19_grpkey->g, gamma) == IERROR)
    GOTOENDRC(IERROR, gl19_blind);
  if(pbcext_element_G1_mul(aux, gl19_bldkey->pk, gamma) == IERROR)
    GOTOENDRC(IERROR, gl19_blind);
  if(pbcext_element_G1_add(gl19_bsig->c2, h, aux) == IERROR)
    GOTOENDRC(IERROR, gl19_blind);

  if(!*bldkey) *bldkey = _bldkey;
  
 gl19_blind_end:

  if(rc == IERROR) {

    if(_bldkey) {
      if(gl19_bldkey->pk) {
	pbcext_element_G1_free(gl19_bldkey->pk);
	gl19_bldkey->pk = NULL;
      }
      if(gl19_bldkey->sk) {
	pbcext_element_Fr_free(gl19_bldkey->sk);
	gl19_bldkey->sk = NULL;
      }
    }
    
    if(gl19_bsig->nym1) {
      pbcext_element_G1_free(gl19_bsig->nym1);
      gl19_bsig->nym1 = NULL;
    }
    if(gl19_bsig->nym2) {
      pbcext_element_G1_free(gl19_bsig->nym2);
      gl19_bsig->nym2 = NULL;
    }
    if(gl19_bsig->nym3) {
      pbcext_element_G1_free(gl19_bsig->nym3);
      gl19_bsig->nym3 = NULL;
    }
    if(gl19_bsig->c1) {
      pbcext_element_G1_free(gl19_bsig->c1);
      gl19_bsig->c1 = NULL;
    }
    if(gl19_bsig->c2) {
      pbcext_element_G1_free(gl19_bsig->c2);
      gl19_bsig->c2 = NULL;
    }
  }
  
  if(alpha) { pbcext_element_Fr_free(alpha); alpha = NULL; }
  if(beta) { pbcext_element_Fr_free(beta); beta = NULL; }
  if(gamma) { pbcext_element_Fr_free(gamma); gamma = NULL; }
  if(aux) { pbcext_element_G1_free(aux); aux = NULL; }
  if(h) { pbcext_element_G1_free(h); h = NULL; }
  if(hm) { hash_free(hm); hm = NULL; }
  
  return rc;

}

/* blind.c ends here */
