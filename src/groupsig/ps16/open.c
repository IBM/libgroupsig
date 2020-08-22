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
#include "ps16.h"
#include "sys/mem.h"
#include "crypto/spk.h"
#include "groupsig/ps16/proof.h"
#include "groupsig/ps16/grp_key.h"
#include "groupsig/ps16/mgr_key.h"
#include "groupsig/ps16/signature.h"
#include "groupsig/ps16/gml.h"
#include "groupsig/ps16/identity.h"

int ps16_open(identity_t *id, groupsig_proof_t *proof, 
	      crl_t *crl, groupsig_signature_t *sig, 
	      groupsig_key_t *grpkey, groupsig_key_t *mgrkey,
	      gml_t *gml) {

  pbcext_element_GT_t *e1, *e2, *e3;
  pbcext_element_G2_t *ggsk;
  pbcext_element_Fr_t *yinv;
  ps16_signature_t *ps16_sig;
  ps16_proof_t *ps16_proof;
  ps16_grp_key_t *ps16_grpkey;
  ps16_mgr_key_t *ps16_mgrkey;
  ps16_gml_entry_t *ps16_entry;
  byte_t *bsig;
  uint64_t i;
  uint32_t slen;
  uint8_t match;
  int rc;

  if (!id || !sig || sig->scheme != GROUPSIG_PS16_CODE ||
      !grpkey || grpkey->scheme != GROUPSIG_PS16_CODE ||
      !mgrkey || mgrkey->scheme != GROUPSIG_PS16_CODE ||
      !gml) {
    LOG_EINVAL(&logger, __FILE__, "ps16_open", __LINE__, LOGERROR);
    return IERROR;
  }

  ps16_sig = sig->sig;
  ps16_proof = proof->proof;
  ps16_grpkey = grpkey->key;
  ps16_mgrkey = mgrkey->key;
  rc = IOK;
  e1 = e2 = e3 = NULL;
  
  if (!(e1 = pbcext_element_GT_init())) GOTOENDRC(IERROR, ps16_open);
  if (pbcext_pairing(e1, ps16_sig->sigma2, ps16_grpkey->gg) == IERROR)
    GOTOENDRC(IERROR, ps16_open);
  if (!(e2 = pbcext_element_GT_init())) GOTOENDRC(IERROR, ps16_open);
  if (pbcext_pairing(e2, ps16_sig->sigma1, ps16_grpkey->X) == IERROR)
    GOTOENDRC(IERROR, ps16_open);
  if (pbcext_element_GT_div(e1, e1, e2) == IERROR) GOTOENDRC(IERROR, ps16_open);

  if (!(e3 = pbcext_element_GT_init())) GOTOENDRC(IERROR, ps16_open);

  if (!(ggsk = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, ps16_open);
  if (!(yinv = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, ps16_open);

  if (pbcext_element_Fr_inv(yinv, ps16_mgrkey->y) == IERROR)
    GOTOENDRC(IERROR, ps16_open);    
  
  /* Look up the recovered e1 in the GML */
  match = 0;
  for (i=0; i<gml->n; i++) {  

    if (!(ps16_entry = gml_get(gml, i))) GOTOENDRC(IERROR, ps16_open);

    if (pbcext_pairing(e3, ps16_sig->sigma1, ps16_entry->ttau) == IERROR)
      GOTOENDRC(IERROR, ps16_open);

    if (!pbcext_element_GT_cmp(e1, e3)) {

      /* Get the identity from the matched entry. */
      if (ps16_identity_copy(id, ps16_entry->id) == IERROR)
	GOTOENDRC(IERROR, ps16_open);

      /* Compute the aux element for the open proof */
      if (pbcext_element_G2_mul(ggsk, ps16_entry->ttau, yinv) == IERROR)
	GOTOENDRC(IERROR, ps16_open);

      match = 1;
      break;

    }

  }

  /* No match: FAIL */
  if(!match) GOTOENDRC(IFAIL, ps16_open);

  /* Create the proof: we make it a SPK (over the sig) of y */

  /* 
     The paper states very genericly that a PK is needed for ttau satisfying the
     above equation, i.e.:

     e(sig2, gg) / e(sig1, X) = e(sig1, ttau)

     If I am not mistaken, this is equivalent to a PK of y for:

     e(sig2, gg) / e(sig1, X) = e(sig1, gg^ski)^y

     where ski is the secret key of the signer, and gg^ski = Y^{y^-1}.

     In the produced proof, we store B = e(sig1, gg/ski), and thus the SPK is:
     
     pi = SPK[(y): A = B^y ](sig)

     (Note: A = e(sig2,gg)/e(sig1,X) can be recomputed completely from the sig
      and the group key.)

     @TODO: CHECK THIS.

  */

  if(!(ps16_proof->B = pbcext_element_GT_init())) GOTOENDRC(IERROR, ps16_open);
  if (pbcext_pairing(ps16_proof->B, ps16_sig->sigma1, ggsk) == IERROR)
    GOTOENDRC(IERROR, ps16_open);

  /* Export the signature as an array of bytes */
  bsig = NULL;
  if (ps16_signature_export(&bsig, &slen, sig) == IERROR)
    GOTOENDRC(IERROR, ps16_open);

  if (!(ps16_proof->pi = spk_dlog_init())) GOTOENDRC(IERROR, ps16_open);
  
  if (spk_dlog_GT_sign(ps16_proof->pi,
		       e1,
		       ps16_proof->B,
		       ps16_mgrkey->y,
		       bsig,
		       slen) == IERROR)
    GOTOENDRC(IERROR, ps16_open);

 ps16_open_end:

  if (e1) { pbcext_element_GT_clear(e1); e1 = NULL; }
  if (e2) { pbcext_element_GT_clear(e2); e2 = NULL; }
  if (e3) { pbcext_element_GT_clear(e3); e3 = NULL; }
  if (yinv) { pbcext_element_Fr_clear(yinv); yinv = NULL; }
  if (ggsk) { pbcext_element_G2_clear(ggsk); ggsk = NULL; }
  if (bsig) { mem_free(bsig); bsig = NULL; }
  
  if (rc == IERROR) {
    if (ps16_proof->pi) { spk_dlog_free(ps16_proof->pi); ps16_proof = NULL; }
    if (ps16_proof->B) { pbcext_element_GT_clear(ps16_proof->B); ps16_proof->B = NULL; }
  }
  
  return rc;
  
}

/* open.c ends here */
