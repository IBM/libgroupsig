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
#include "bbs04.h"
#include "groupsig/bbs04/grp_key.h"
#include "groupsig/bbs04/mgr_key.h"
#include "groupsig/bbs04/signature.h"
#include "groupsig/bbs04/gml.h"

int bbs04_open(uint64_t *index,
	       groupsig_proof_t *proof, 
	       crl_t *crl,
	       groupsig_signature_t *sig, 
	       groupsig_key_t *grpkey,
	       groupsig_key_t *mgrkey,
	       gml_t *gml) {

  pbcext_element_G1_t *A, *aux;
  bbs04_signature_t *bbs04_sig;
  bbs04_grp_key_t *bbs04_grpkey;
  bbs04_mgr_key_t *bbs04_mgrkey;
  gml_entry_t *entry;
  uint64_t i;
  uint8_t match;
  int rc;

  if(!index || !sig || sig->scheme != GROUPSIG_BBS04_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_BBS04_CODE ||
     !mgrkey || mgrkey->scheme != GROUPSIG_BBS04_CODE ||
     !gml) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_open", __LINE__, LOGERROR);
    return IERROR;
  }

  bbs04_sig = sig->sig;
  bbs04_grpkey = grpkey->key;
  bbs04_mgrkey = mgrkey->key;
  rc = IOK;
  A = aux = NULL;

  /* In the paper, a signature verification process is included within the open
     procedure to check that the signature is valid. Here, we sepatarate the two
     processes (verify can always be called before opening...) */
  
  /* Recover the signer's A as: A = T3/(T1^xi1 * T2^xi2) */
  if(!(A = pbcext_element_G1_init())) GOTOENDRC(IERROR, bbs04_open);
  if(!(aux = pbcext_element_G1_init())) GOTOENDRC(IERROR, bbs04_open);
  if(pbcext_element_G1_mul(A, bbs04_sig->T1, bbs04_mgrkey->xi1) == IERROR)
    GOTOENDRC(IERROR, bbs04_open);
  if(pbcext_element_G1_mul(aux, bbs04_sig->T2, bbs04_mgrkey->xi2) == IERROR)
    GOTOENDRC(IERROR, bbs04_open);
  if(pbcext_element_G1_add(A, A, aux) == IERROR) GOTOENDRC(IERROR, bbs04_open);
  if(pbcext_element_G1_sub(A, bbs04_sig->T3, A) == IERROR)
    GOTOENDRC(IERROR, bbs04_open);

  /* Look up the recovered A in the GML */
  match = 0;
  for(i=0; i<gml->n; i++) {  

    if(!(entry = gml_get(gml, i))) GOTOENDRC(IERROR, bbs04_open);

    if(!pbcext_element_G1_cmp(entry->data, A)) {

      /* Get the index from the matched entry. */
      *index = entry->id;
      match = 1;
      break;

    }

  }

  /* No match: FAIL */
  if(!match) GOTOENDRC(IFAIL, bbs04_open);
  
  /* /\* If we have received a CRL, update it with the "revoked" member *\/ */
  /* if(crl) { */

  /*   if(!(crl_entry = bbs04_crl_entry_init())) { */
  /*     return IERROR; */
  /*   } */
    
  /*   if(bbs04_identity_copy(crl_entry->id, gml_entry->id) == IERROR) { */
  /*     bbs04_crl_entry_free(crl_entry); */
  /*     return IERROR; */
  /*   } */
    
  /*   crl_entry->trapdoor = trap; */

  /*   if(bbs04_crl_insert(crl, crl_entry) == IERROR) { */
  /*     bbs04_crl_entry_free(crl_entry); */
  /*     return IERROR; */
  /*   } */

  /* } */

 bbs04_open_end:

  if(A) { pbcext_element_G1_free(A); A = NULL; }
  if(aux) { pbcext_element_G1_free(aux); aux = NULL; }

  return rc;
  
}

/* open.c ends here */
