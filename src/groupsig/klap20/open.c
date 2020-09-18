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
#include "klap20.h"
#include "sys/mem.h"
#include "crypto/spk.h"
#include "math/rnd.h"
#include "groupsig/klap20/proof.h"
#include "groupsig/klap20/grp_key.h"
#include "groupsig/klap20/mgr_key.h"
#include "groupsig/klap20/signature.h"
#include "groupsig/klap20/gml.h"

int klap20_open(uint64_t *index,
	      groupsig_proof_t *proof, 
	      crl_t *crl,
	      groupsig_signature_t *sig, 
	      groupsig_key_t *grpkey,
	      groupsig_key_t *mgrkey,
	      gml_t *gml) {

  pbcext_element_G2_t *ff;
  pbcext_element_GT_t *e1, *e2, *e3;
  klap20_signature_t *klap20_sig;
  klap20_grp_key_t *klap20_grpkey;
  klap20_mgr_key_t *klap20_mgrkey;
  gml_entry_t *klap20_entry;
  klap20_gml_entry_data_t *klap20_data;
  byte_t *bsig;
  uint64_t i, b;
  uint32_t slen;
  uint8_t match;
  int rc;

  if (!index || !sig || sig->scheme != GROUPSIG_KLAP20_CODE ||
      !grpkey || grpkey->scheme != GROUPSIG_KLAP20_CODE ||
      !mgrkey || mgrkey->scheme != GROUPSIG_KLAP20_CODE ||
      !gml) {
    LOG_EINVAL(&logger, __FILE__, "klap20_open", __LINE__, LOGERROR);
    return IERROR;
  }

  klap20_sig = sig->sig;
  klap20_grpkey = grpkey->key;
  klap20_mgrkey = mgrkey->key;
  rc = IOK;
  e1 = e2 = e3 = NULL;

  /* Pick random b from [0,1] */
  if ((rnd_get_random_int_in_range(&b, 1)) == IERROR)
    GOTOENDRC(IERROR, klap20_open);

  if (!(ff = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_open);
  if (!(e1 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, klap20_open);
  if (!(e2 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, klap20_open);
  if (!(e3 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, klap20_open);
  
  /* Look up the recovered e1 in the GML */
  match = 0;
  for (i=0; i<gml->n; i++) {  

    if (!(klap20_entry = gml_get(gml, i))) GOTOENDRC(IERROR, klap20_open);
    klap20_data = klap20_entry->data;
    if (!klap20_data) GOTOENDRC(IERROR, klap20_open);

    if (b) {
      if (pbcext_element_G2_mul(ff, klap20_data->SS1, klap20_mgrkey->z1) == IERROR)
	GOTOENDRC(IERROR, klap20_open);
      if (pbcext_element_G2_neg(ff, ff) == IERROR)
	GOTOENDRC(IERROR, klap20_open);
      if (pbcext_element_G2_add(ff, klap20_data->ff1, ff) == IERROR)
	GOTOENDRC(IERROR, klap20_open);    
    } else { 
      if (pbcext_element_G2_mul(ff, klap20_data->SS0, klap20_mgrkey->z0) == IERROR)
	GOTOENDRC(IERROR, klap20_open);
      if (pbcext_element_G2_neg(ff, ff) == IERROR)
	GOTOENDRC(IERROR, klap20_open);
      if (pbcext_element_G2_add(ff, klap20_data->ff0, ff) == IERROR)
	GOTOENDRC(IERROR, klap20_open);
    }

    if (pbcext_pairing(e1, klap20_sig->uu, ff) == IERROR)
      GOTOENDRC(IERROR, klap20_open);
    if (pbcext_pairing(e2, klap20_sig->ww, klap20_grpkey->gg) == IERROR)
      GOTOENDRC(IERROR, klap20_open);
    if (pbcext_pairing(e3, klap20_grpkey->g, ff) == IERROR)
      GOTOENDRC(IERROR, klap20_open);
    
    if (!pbcext_element_GT_cmp(e1, e2) &&
	!pbcext_element_GT_cmp(klap20_data->tau, e3)) {

      /* Get the identity from the matched entry. */
      *index = klap20_entry->id;
      match = 1;
      break;

    }

  }

  /* No match: FAIL */
  if(!match) GOTOENDRC(IFAIL, klap20_open);

  /* Export the signature as an array of bytes */
  bsig = NULL;
  if (klap20_signature_export(&bsig, &slen, sig) == IERROR)
    GOTOENDRC(IERROR, klap20_open);

  if (!(proof->proof = klap20_spk1_init()))
    GOTOENDRC(IERROR, klap20_open);

  if (!(((klap20_spk1_t *) proof->proof)->tau = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, klap20_open);
  if (pbcext_element_GT_set(((klap20_spk1_t *) proof->proof)->tau, e3) == IERROR)
    GOTOENDRC(IERROR, klap20_open);
  
  if (klap20_spk1_sign(proof->proof,
		       ff,
		       klap20_sig->uu,
		       klap20_grpkey->g,
		       e2,
		       e3,
		       bsig,
		       slen) == IERROR) 
    GOTOENDRC(IERROR, klap20_open);

 klap20_open_end:

  if (ff) { pbcext_element_G2_free(ff); ff = NULL; }
  if (e1) { pbcext_element_GT_free(e1); e1 = NULL; }
  if (e2) { pbcext_element_GT_free(e2); e2 = NULL; }
  if (e3) { pbcext_element_GT_free(e3); e3 = NULL; }
  if (bsig) { mem_free(bsig); bsig = NULL; }
  
  if (rc == IERROR) {
    if (proof->proof) {
      klap20_spk1_free(proof->proof);
      proof->proof = NULL;
    }
  }
  
  return rc;
  
}

/* open.c ends here */
