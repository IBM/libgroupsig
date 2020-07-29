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
#include "bigz.h"
#include "kty04.h"
#include "groupsig/kty04/grp_key.h"
#include "groupsig/kty04/mgr_key.h"
#include "groupsig/kty04/signature.h"
#include "groupsig/kty04/gml.h"
#include "groupsig/kty04/identity.h"

int kty04_open(identity_t *id, groupsig_proof_t *proof, 
	       crl_t *crl, groupsig_signature_t *sig, 
	       groupsig_key_t *grpkey, groupsig_key_t *mgrkey, gml_t *gml) {

  kty04_signature_t *kty04_sig;
  kty04_mgr_key_t *mkey;
  kty04_grp_key_t *gkey;
  bigz_t Ai, T1;  
  uint64_t i;
  uint8_t match;

  if(!id || !sig || sig->scheme != GROUPSIG_KTY04_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_KTY04_CODE ||
     !mgrkey || mgrkey->scheme != GROUPSIG_KTY04_CODE ||
     !gml) {
    LOG_EINVAL(&logger, __FILE__, "kty04_open", __LINE__, LOGERROR);
    return IERROR;
  }

  kty04_sig = (kty04_signature_t *) sig->sig;
  mkey = (kty04_mgr_key_t *) mgrkey->key;
  gkey = (kty04_grp_key_t *) grpkey->key;

  /* Get T2^(-x)*T1. Note that sig->A[2] = T2^(-1) and sig->A[6] = T1^(-1) */
  if(!(T1 = bigz_init())) return IERROR;
  if(bigz_invert(T1, kty04_sig->A[6], gkey->n) == IERROR) { 
    bigz_free(T1); 
    return IERROR;
  }

  if(!(Ai = bigz_init())) {
    bigz_free(T1);
    return IERROR;
  }

  if(bigz_powm(Ai, kty04_sig->A[2], mkey->x, gkey->n) == IERROR) {
    bigz_free(T1); bigz_free(Ai);
    return IERROR;
  }
  
  if(bigz_mul(Ai, Ai, T1) == IERROR) {
    bigz_free(T1); bigz_free(Ai);
    return IERROR;    
  }

  if(bigz_mod(Ai, Ai, gkey->n) == IERROR) {
    bigz_free(T1); bigz_free(Ai);
    return IERROR;
  }

  bigz_free(T1);

  /* Go through all the member keys in gml looking for a match memkey->A == Ai */
  match = 0;
  for(i=0; i<gml->n; i++) {  

    errno = 0;

    if(!bigz_cmp(((kty04_gml_entry_t *) gml_get(gml, i))->A, Ai)) {

      if(errno) {
	bigz_free(Ai);
	return IERROR;
      }

      /* Get the identity from the matched entry. */
      if(kty04_identity_copy(id, ((kty04_gml_entry_t *) gml_get(gml, i))->id) == IERROR) {
	bigz_free(Ai);
	return IERROR;
      }

      match = 1;
      break;

    }

    if(errno) {
      bigz_free(Ai);
      return IERROR;
    }

  }

  bigz_free(Ai);

  /* No match: FAIL */
  if(!match) {
    return IFAIL;
  }

  /* /\* If we have received a CRL, update it with the "revoked" member *\/ */
  /* if(crl) { */

  /*   if(!(crl_entry = kty04_crl_entry_init())) { */
  /*     return IERROR; */
  /*   } */
    
  /*   if(kty04_identity_copy(crl_entry->id, gml_entry->id) == IERROR) { */
  /*     kty04_crl_entry_free(crl_entry); */
  /*     return IERROR; */
  /*   } */
    
  /*   crl_entry->trapdoor = trap; */

  /*   if(kty04_crl_insert(crl, crl_entry) == IERROR) { */
  /*     kty04_crl_entry_free(crl_entry); */
  /*     return IERROR; */
  /*   } */

  /* } */

  return IOK;

}

/* open.c ends here */
