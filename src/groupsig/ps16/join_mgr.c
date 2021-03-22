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

#include "ps16.h"
#include "groupsig/ps16/grp_key.h"
#include "groupsig/ps16/mgr_key.h"
#include "groupsig/ps16/mem_key.h"
#include "groupsig/ps16/gml.h"
#include "crypto/spk.h"
#include "shim/pbc_ext.h"
#include "sys/mem.h"

int ps16_get_joinseq(uint8_t *seq) {
  *seq = PS16_JOIN_SEQ;
  return IOK;
}

int ps16_get_joinstart(uint8_t *start) {
  *start = PS16_JOIN_START;
  return IOK;
}

/**
 * This process deviates slightly from what the PS16 paper defines, as the PKI
 * functionality is not integrated here. See the comment in the join_mem 
 * function for a detailed explanation.
 * 
 * In the join_mgr implemented here, we do not verify any signature of tau using
 * a "standard" keypair+certificate. Nor do we add the signature of tau to the
 * GML (because we don't receive such signature). Rather, it should be the caller
 * who takes care of that using some well tested library/software for PKI 
 * management. 
 *
 * This can be easily done by a calling library as follows:
 *   1) The member digitally signs, using his PKI-backed identity, the bytearray
 *      representation of the <i>min</i> parameter when <i>seq</i>=2 (this
 *      contains the challenge response). 
 *   2) If the join is successful, the manager exports the newly created GML
 *      entry, producing a byte array (which contains the libgroupsig-internal
 *      identity -- an integer). 
 *   3) All the server running the issuer needs to store in its database, is
 *      the output of the previous steps. This can then be queried when an open
 *      is requested.
 */
int ps16_join_mgr(message_t **mout,
		  gml_t *gml,
		  groupsig_key_t *mgrkey,
		  int seq,
		  message_t *min,
		  groupsig_key_t *grpkey) {

  groupsig_key_t *memkey;
  ps16_mem_key_t *ps16_memkey;
  ps16_mgr_key_t *ps16_mgrkey;
  ps16_grp_key_t *ps16_grpkey;
  gml_entry_t *ps16_entry;
  pbcext_element_Fr_t *u;
  pbcext_element_G1_t *n, *tau, *aux;
  pbcext_element_G2_t *ttau;
  pbcext_element_GT_t *e1, *e2;
  spk_dlog_t *pi;
  message_t *_mout;
  byte_t *bn, *bkey;
  uint64_t len, nlen, taulen, ttaulen, pilen;
  uint32_t size;
  uint8_t ok;
  int rc;

  if((seq != 0 && seq != 2) ||
     !mout || !gml || gml->scheme != GROUPSIG_PS16_CODE ||
     !mgrkey || mgrkey->scheme != GROUPSIG_PS16_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ps16_join_mgr", __LINE__, LOGERROR);
    return IERROR;
  }

  ps16_mgrkey = (ps16_mgr_key_t *) mgrkey->key;
  ps16_grpkey = (ps16_grp_key_t *) grpkey->key;
  ps16_entry = NULL;
  bn = bkey = NULL;
  u = NULL;
  n = tau = aux = NULL;
  ttau = NULL;
  e1 = e2 = NULL;
  pi = NULL;
  memkey = NULL;
  rc = IOK;
  
  if (!seq) { /* First step */

    if(!(n = pbcext_element_G1_init())) GOTOENDRC(IERROR, ps16_join_mgr);
    if(pbcext_element_G1_random(n) == IERROR) GOTOENDRC(IERROR, ps16_join_mgr);
    
    /* Dump the element into a message */
    if(pbcext_dump_element_G1_bytes(&bn, &len, n) == IERROR) 
      GOTOENDRC(IERROR, ps16_join_mgr);
    
    if(!*mout) {   
      if(!(_mout = message_from_bytes(bn, len))) {
	GOTOENDRC(IERROR, ps16_join_mgr);
      }

      *mout = _mout;
      
    } else {

      _mout = *mout;
      if(message_set_bytes(*mout, bn, len) == IERROR)
	GOTOENDRC(IERROR, ps16_join_mgr);
      
    }
    
  } else { /* Third step */

    /* Import the (n,tau,ttau,pi) ad hoc message */

    if (!(n = pbcext_element_G1_init())) GOTOENDRC(IERROR, ps16_join_mgr);
    if (pbcext_get_element_G1_bytes(n, &nlen, min->bytes) == IERROR)
      GOTOENDRC(IERROR, ps16_join_mgr);
    if (!(tau = pbcext_element_G1_init())) GOTOENDRC(IERROR, ps16_join_mgr);
    if (pbcext_get_element_G1_bytes(tau, &taulen, min->bytes + nlen) == IERROR)
      GOTOENDRC(IERROR, ps16_join_mgr);
    if (!(ttau = pbcext_element_G2_init())) GOTOENDRC(IERROR, ps16_join_mgr);
    if (pbcext_get_element_G2_bytes(ttau, &ttaulen, min->bytes + nlen + taulen) == IERROR)
      GOTOENDRC(IERROR, ps16_join_mgr);
    if (!(pi = spk_dlog_import(min->bytes + nlen + taulen + ttaulen, &pilen)))
      GOTOENDRC(IERROR, ps16_join_mgr);
    if (pbcext_element_G1_to_bytes(&bn, &nlen, n) == IERROR)
      GOTOENDRC(IERROR, ps16_join_mgr);

    /* Check the SPK and the pairings */
    if (spk_dlog_G1_verify(&ok, tau, ps16_grpkey->g,
			   pi, bn, nlen) == IERROR) {
      GOTOENDRC(IERROR, ps16_join_mgr);
    }
    if (!ok) GOTOENDRC(IERROR, ps16_join_mgr);

    if (!(e1 = pbcext_element_GT_init())) GOTOENDRC(IERROR, ps16_join_mgr);

    if (pbcext_pairing(e1, tau, ps16_grpkey->Y) == IERROR)
      GOTOENDRC(IERROR, ps16_join_mgr);

    if (!(e2 = pbcext_element_GT_init())) GOTOENDRC(IERROR, ps16_join_mgr);
    if (pbcext_pairing(e2, ps16_grpkey->g, ttau) == IERROR)
      GOTOENDRC(IERROR, ps16_join_mgr);
    if (pbcext_element_GT_cmp(e1, e2)) GOTOENDRC(IERROR, ps16_join_mgr);

    /* Compute the partial member key */
    if (!(u = pbcext_element_Fr_init())) GOTOENDRC(IERROR, ps16_join_mgr);
    if (pbcext_element_Fr_random(u) == IERROR) GOTOENDRC(IERROR, ps16_join_mgr);

    if (!(memkey = ps16_mem_key_init())) GOTOENDRC(IERROR, ps16_join_mgr);
    ps16_memkey = memkey->key;
    
    if (!(ps16_memkey->sigma1 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ps16_join_mgr);
    if (pbcext_element_G1_mul(ps16_memkey->sigma1, ps16_grpkey->g, u) == IERROR)
      GOTOENDRC(IERROR, ps16_join_mgr);

    if (!(ps16_memkey->sigma2 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ps16_join_mgr);
    if (!(aux = pbcext_element_G1_init())) GOTOENDRC(IERROR, ps16_join_mgr);    
    if (pbcext_element_G1_mul(aux, tau, ps16_mgrkey->y) == IERROR)
      GOTOENDRC(IERROR, ps16_join_mgr);
    if (pbcext_element_G1_mul(ps16_memkey->sigma2,
			      ps16_grpkey->g,
			      ps16_mgrkey->x) == IERROR) 
      GOTOENDRC(IERROR, ps16_join_mgr);
    if (pbcext_element_G1_add(ps16_memkey->sigma2,
			      aux,
			      ps16_memkey->sigma2) == IERROR)
      GOTOENDRC(IERROR, ps16_join_mgr);
    if (pbcext_element_G1_mul(ps16_memkey->sigma2,
			      ps16_memkey->sigma2,
			      u) == IERROR) 
      GOTOENDRC(IERROR, ps16_join_mgr);    

    /* Add the tuple (i,tau,ttau) to the GML */

    if(!(ps16_entry = ps16_gml_entry_init()))
      GOTOENDRC(IERROR, ps16_join_mgr);
    
    /* Currently, PS16 identities are just uint64_t's */
    ps16_entry->id = gml->n;
    if (!(ps16_entry->data = mem_malloc(sizeof(ps16_gml_entry_data_t))))
      GOTOENDRC(IERROR, ps16_join_mgr);
    ((ps16_gml_entry_data_t *) ps16_entry->data)->tau = tau;
    ((ps16_gml_entry_data_t *) ps16_entry->data)->ttau = ttau;

    if(gml_insert(gml, ps16_entry) == IERROR) GOTOENDRC(IERROR, ps16_join_mgr);

    /* Export the (partial) member key into a msg */
    bkey = NULL; 
    if (ps16_mem_key_export(&bkey, &size, memkey) == IERROR)
      GOTOENDRC(IERROR, ps16_join_mgr);

    if(!*mout) {
      
      if(!(_mout = message_from_bytes(bkey, size)))
	GOTOENDRC(IERROR, ps16_join_mgr);
      *mout = _mout;

    } else {

      _mout = *mout;
      if(message_set_bytes(_mout, bkey, size) == IERROR)
	GOTOENDRC(IERROR, ps16_join_mgr);

    }    
    
  }
  
 ps16_join_mgr_end:

  if (rc == IERROR) {
    if (tau) { pbcext_element_G1_free(tau); tau = NULL; }  
    if (ttau) { pbcext_element_G2_free(ttau); ttau = NULL; }
    if (ps16_entry) { ps16_gml_entry_free(ps16_entry); ps16_entry = NULL; }
  }

  if (u) { pbcext_element_Fr_free(u); u = NULL; }
  if (n) { pbcext_element_G1_free(n); n = NULL; }  
  if (aux) { pbcext_element_G1_free(aux); aux = NULL; }
  if (e1) { pbcext_element_GT_free(e1); e1 = NULL; }
  if (e2) { pbcext_element_GT_free(e2); e2 = NULL; }
  if (pi) { spk_dlog_free(pi); pi = NULL; }
  if (bn) { mem_free(bn); bn = NULL; }
  if (bkey) { mem_free(bkey); bkey = NULL; }
  if (memkey) { ps16_mem_key_free(memkey); memkey = NULL; }
  
  return rc;

}

/* join_mgr.c ends here */
