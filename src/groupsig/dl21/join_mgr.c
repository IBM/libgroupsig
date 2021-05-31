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
#include <errno.h>
#include <stdlib.h>

#include "dl21.h"
#include "groupsig/dl21/grp_key.h"
#include "groupsig/dl21/mgr_key.h"
#include "groupsig/dl21/mem_key.h"
#include "groupsig/dl21/identity.h"
#include "sys/mem.h"
#include "crypto/spk.h"
#include "shim/pbc_ext.h"

int dl21_get_joinseq(uint8_t *seq) {
  *seq = DL21_JOIN_SEQ;
  return IOK;
}

int dl21_get_joinstart(uint8_t *start) {
  *start = DL21_JOIN_START;
  return IOK;
}

int dl21_join_mgr(message_t **mout,
		  gml_t *gml,
		  groupsig_key_t *mgrkey,
		  int seq,
		  message_t *min,
		  groupsig_key_t *grpkey) {

  pbcext_element_G1_t *n, *H, *h2s;
  pbcext_element_Fr_t *aux;
  dl21_mem_key_t *dl21_memkey;
  dl21_grp_key_t *dl21_grpkey;
  dl21_mgr_key_t *dl21_mgrkey;
  groupsig_key_t *memkey;
  message_t *_mout;
  spk_dlog_t *spk;
  byte_t *bn, *bkey;
  uint64_t len, _len;
  uint32_t size;
  int rc;
  uint8_t ok;
  
  if((seq != 0 && seq != 2) ||
     !mout ||
     !mgrkey || mgrkey->scheme != GROUPSIG_DL21_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_DL21_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21_join_mgr", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  bn = bkey = NULL;
  n = H = h2s = NULL;
  aux = NULL;
  spk = NULL;
  memkey = NULL;
  
  dl21_grpkey = (dl21_grp_key_t *) grpkey->key;
  dl21_mgrkey = (dl21_mgr_key_t *) mgrkey->key;

  /* First step by manager: generate n */
  if (seq == 0) {
    
    if(!(n = pbcext_element_G1_init())) GOTOENDRC(IERROR, dl21_join_mgr);
    if(pbcext_element_G1_random(n) == IERROR) GOTOENDRC(IERROR, dl21_join_mgr);
    
    /* Dump the element into a message */
    if(pbcext_dump_element_G1_bytes(&bn, &len, n) == IERROR) 
      GOTOENDRC(IERROR, dl21_join_mgr);
    
    if(!*mout) {   
      if(!(_mout = message_from_bytes(bn, len))) {
	GOTOENDRC(IERROR, dl21_join_mgr);
      }
      
      *mout = _mout;

    } else {
	
      _mout = *mout;
      if(message_set_bytes(*mout, bn, len) == IERROR)
	GOTOENDRC(IERROR, dl21_join_mgr);
	
    }      
            
  } else {

    /* Second step by manager: compute credential from H and pi_H */
    /* Verify the proof */

    if(!(n = pbcext_element_G1_init())) GOTOENDRC(IERROR, dl21_join_mgr);
    if(pbcext_get_element_G1_bytes(n, &len, min->bytes) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mgr);
    if(!(H = pbcext_element_G1_init())) GOTOENDRC(IERROR, dl21_join_mgr);
    if(pbcext_get_element_G1_bytes(H, &_len, min->bytes + len) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mgr);
    if(!(spk = spk_dlog_import(min->bytes + len + _len, &len)))
      GOTOENDRC(IERROR, dl21_join_mgr);
    if(pbcext_element_G1_to_bytes(&bn, &len, n) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mgr);
    if(spk_dlog_G1_verify(&ok, H, dl21_grpkey->h1,
			  spk, bn, len) == IERROR) {
      GOTOENDRC(IERROR, dl21_join_mgr);
    }

    if(!ok) GOTOENDRC(IERROR, dl21_join_mgr);

    /* Pick x and s at random from Z*_p */
    if(!(memkey = dl21_mem_key_init())) GOTOENDRC(IERROR, dl21_join_mgr);
    dl21_memkey = memkey->key;

    if(!(dl21_memkey->x = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, dl21_join_mgr);
    if(pbcext_element_Fr_random(dl21_memkey->x) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mgr);
    if(!(dl21_memkey->s = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, dl21_join_mgr);
    if(pbcext_element_Fr_random(dl21_memkey->s) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mgr);

    /* Set A = (H*h_2^s*g_1)^(1/isk+x) */
    if(!(dl21_memkey->A = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, dl21_join_mgr);
    if(!(h2s = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, dl21_join_mgr);
    if(pbcext_element_G1_mul(h2s, dl21_grpkey->h2, dl21_memkey->s) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mgr);
    if(pbcext_element_G1_add(dl21_memkey->A, h2s, dl21_grpkey->g1) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mgr);
    if(pbcext_element_G1_add(dl21_memkey->A, dl21_memkey->A, H) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mgr);
    if(!(aux = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, dl21_join_mgr);
    if(pbcext_element_Fr_add(aux, dl21_mgrkey->isk, dl21_memkey->x) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mgr);
    if(pbcext_element_Fr_inv(aux, aux) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mgr);
    if(pbcext_element_G1_mul(dl21_memkey->A, dl21_memkey->A, aux) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mgr);

    /* 
       Mout = (A,x,s) 
       This is stored in a partially filled memkey, byte encoded into a 
       message_t struct
    */

    bkey = NULL; 
    if (dl21_mem_key_export(&bkey, &size, memkey) == IERROR)
      GOTOENDRC(IERROR, dl21_join_mgr);

    if(!*mout) {
      if(!(_mout = message_from_bytes(bkey, size)))
	GOTOENDRC(IERROR, dl21_join_mgr);
      *mout = _mout;

    } else {

      _mout = *mout;
      if(message_set_bytes(_mout, bkey, size) == IERROR)
	GOTOENDRC(IERROR, dl21_join_mgr);
    }    
    
  }
  
 dl21_join_mgr_end:

  if (n) { pbcext_element_G1_free(n); n = NULL; }
  if (H) { pbcext_element_G1_free(H); H = NULL; }
  if (bn) { mem_free(bn); bn = NULL; }    
  if (aux) { pbcext_element_Fr_free(aux); aux = NULL; }
  if (h2s) { pbcext_element_G1_free(h2s); h2s = NULL; }
  if (memkey) { dl21_mem_key_free(memkey); memkey = NULL; }
  if (bkey) { mem_free(bkey); bkey = NULL; }
  if (spk) { spk_dlog_free(spk); spk = NULL; }
  
  return rc;

}

/* join_mgr.c ends here */
