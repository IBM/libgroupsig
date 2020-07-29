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
#include "cpy06.h"
#include "groupsig/cpy06/grp_key.h"
#include "groupsig/cpy06/mgr_key.h"
#include "groupsig/cpy06/signature.h"
#include "groupsig/cpy06/gml.h"
#include "groupsig/cpy06/identity.h"
#include "groupsig/cpy06/trapdoor.h"

int cpy06_open(identity_t *id, groupsig_proof_t *proof,
	       crl_t *crl, groupsig_signature_t *sig, 
	       groupsig_key_t *grpkey, groupsig_key_t *mgrkey, gml_t *gml) {

  element_t A;
  cpy06_signature_t *cpy06_sig;
  cpy06_grp_key_t *cpy06_grpkey;
  cpy06_mgr_key_t *cpy06_mgrkey;
  cpy06_sysenv_t *cpy06_sysenv;
  cpy06_gml_entry_t *entry;
  uint64_t i;
  uint8_t match;

  if(!id || !sig || sig->scheme != GROUPSIG_CPY06_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_CPY06_CODE ||
     !mgrkey || mgrkey->scheme != GROUPSIG_CPY06_CODE ||
     !gml) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_open", __LINE__, LOGERROR);
    return IERROR;
  }

  cpy06_sig = sig->sig;
  cpy06_grpkey = grpkey->key;
  cpy06_mgrkey = mgrkey->key;
  cpy06_sysenv = sysenv->data;

  /* In the paper, a signature verification process is included within the open
     procedure to check that the signature is valid. Here, we sepatarate the two
     processes (verify can always be called before opening...) */
  
  /* Recover the signer's A as: A = T3/(T1^xi1 * T2^xi2) */
  element_init_G1(A, cpy06_sysenv->pairing);
  element_pow2_zn(A, cpy06_sig->T1, cpy06_mgrkey->xi1, cpy06_sig->T2, cpy06_mgrkey->xi2);
  element_div(A, cpy06_sig->T3, A);

  /* Look up the recovered A in the GML */
  match = 0;
  for(i=0; i<gml->n; i++) {  

    if(!(entry = gml_get(gml, i))) {
      element_clear(A);
      return IERROR;
    }

    if(!element_cmp(((cpy06_trapdoor_t *)entry->trapdoor->trap)->open, A)) {

      /* Get the identity from the matched entry. */
      if(cpy06_identity_copy(id, entry->id) == IERROR) {
	element_clear(A);
	return IERROR;
      }

      match = 1;
      break;

    }

  }

  element_clear(A);

  /* No match: FAIL */
  if(!match) {
    return IFAIL;
  }

  /* /\* If we have received a CRL, update it with the "revoked" member *\/ */
  /* if(crl) { */

  /*   if(!(crl_entry = cpy06_crl_entry_init())) { */
  /*     return IERROR; */
  /*   } */
    
  /*   if(cpy06_identity_copy(crl_entry->id, gml_entry->id) == IERROR) { */
  /*     cpy06_crl_entry_free(crl_entry); */
  /*     return IERROR; */
  /*   } */
    
  /*   crl_entry->trapdoor = trap; */

  /*   if(cpy06_crl_insert(crl, crl_entry) == IERROR) { */
  /*     cpy06_crl_entry_free(crl_entry); */
  /*     return IERROR; */
  /*   } */

  /* } */

  return IOK;

}

/* open.c ends here */
