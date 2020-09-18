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
#include "groupsig/klap20/proof.h"
#include "groupsig/klap20/grp_key.h"
#include "groupsig/klap20/signature.h"
#include "groupsig/klap20/gml.h"

int klap20_open_verify(uint8_t *ok,
		     groupsig_proof_t *proof, 
		     groupsig_signature_t *sig,
		     groupsig_key_t *grpkey) {

  pbcext_element_GT_t *e2;
  klap20_signature_t *klap20_sig;
  klap20_proof_t *klap20_proof;
  klap20_grp_key_t *klap20_grpkey;
  byte_t *bsig;
  int rc;
  uint32_t slen;
  uint8_t _ok;

  if (!proof || proof->scheme != GROUPSIG_KLAP20_CODE ||
      !sig || sig->scheme != GROUPSIG_KLAP20_CODE ||
      !grpkey || grpkey->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klap20_open_verify", __LINE__, LOGERROR);
    return IERROR;
  }

  klap20_sig = sig->sig;
  klap20_grpkey = grpkey->key;
  klap20_proof = proof->proof;
  rc = IOK;
  e2 = NULL;

  if (!(e2 = pbcext_element_GT_init())) GOTOENDRC(IERROR, klap20_open_verify);
  if (pbcext_pairing(e2, klap20_sig->ww, klap20_grpkey->gg) == IERROR)
    GOTOENDRC(IERROR, klap20_open_verify);

  /* Export the signature as an array of bytes */
  bsig = NULL;
  if (klap20_signature_export(&bsig, &slen, sig) == IERROR)
    GOTOENDRC(IERROR, klap20_open_verify);

  if (klap20_spk1_verify(&_ok,
			 klap20_proof,
			 klap20_sig->uu,
			 klap20_grpkey->g,
			 e2,
			 klap20_proof->tau,
			 bsig,
			 slen) == IERROR)
    GOTOENDRC(IERROR, klap20_open_verify);

  *ok = _ok;

 klap20_open_verify_end:

  if (e2) { pbcext_element_GT_free(e2); e2 = NULL; }
  if (bsig) { mem_free(bsig); bsig = NULL; }

  return rc;
  
}

/* open.c ends here */
