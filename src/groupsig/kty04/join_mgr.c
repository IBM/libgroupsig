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

#include "kty04.h"
#include "groupsig/kty04/sphere.h"
#include "groupsig/kty04/grp_key.h"
#include "groupsig/kty04/mgr_key.h"
#include "groupsig/kty04/mem_key.h"
#include "groupsig/kty04/gml.h"
#include "groupsig/kty04/identity.h"
#include "groupsig/kty04/trapdoor.h"
#include "bigz.h"
#include "sys/mem.h"

/**
 * @todo The Join procedure includes a protocol for non-adaptive drawing of 
 * random powers such that the group member gets x, and the group manager gets
 * b^x (mod n). For now, and for testing purposes, we just let the user choose 
 * a random x and send it to the manager, but we must implement it as soon as
 * everything is working correctly.
 */

/* static int _join_mgr_draw_random_pow(kty04_grp_key_t *grpkey,  kty04_mgr_key_t *mgrkey, kty04_mem_key_t *memkey) { */
/*   return IERROR; */
/* } */

int kty04_get_joinseq(uint8_t *seq) {
  *seq = KTY04_JOIN_SEQ;
  return IOK;
}

int kty04_get_joinstart(uint8_t *start) {
  *start = KTY04_JOIN_START;
  return IOK;
}

/* @TODO This function still follows the old variable structure for join and 
   I am just changing the interface to remove compiler complaints. But this 
   breaks the functionality! Fix! */
//gml_t *gml, groupsig_key_t *memkey, groupsig_key_t *mgrkey, groupsig_key_t *grpkey) {
int kty04_join_mgr(void **mout, gml_t *gml,
		   groupsig_key_t *mgrkey,
		   int seq, void *min,
		   groupsig_key_t *grpkey) {

  kty04_mgr_key_t *Mkey;
  kty04_grp_key_t *gkey;
  kty04_mem_key_t *mkey;
  kty04_gml_entry_t *entry;
  bigz_t e, einv, x, p1, q1, phin;
  int rc;
  
  if(!mout || !gml || gml->scheme != GROUPSIG_KTY04_CODE ||
     !mgrkey || mgrkey->scheme != GROUPSIG_KTY04_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_join_mgr", __LINE__, LOGERROR);
    return IERROR;
  }
  
  gkey = (kty04_grp_key_t *) grpkey->key;
  Mkey = (kty04_mgr_key_t *) mgrkey->key;
  //  mkey = (kty04_mem_key_t *) memkey->key;

  e = NULL; einv = NULL; x = NULL; p1 = NULL; q1 = NULL; phin = NULL;
  rc = IOK;

  /* Select a random prime e in the inner sphere of Gamma */
  if(!(e = bigz_init())) {
    return IERROR;
  }

  if(sphere_get_random_prime(gkey->inner_gamma, e) == IERROR) {
    GOTOENDRC(IERROR, kty04_join_mgr);
  }

  /* We need the inverse of e mod(phi(n)) = e^(-1) mod((p-1)*(q-1)) */
  if(!(p1 = bigz_init()) || !(q1 = bigz_init()) || 
     !(phin = bigz_init()) || !(einv = bigz_init())) {
    GOTOENDRC(IERROR, kty04_join_mgr);
  }

  if(bigz_sub_ui(p1, Mkey->p, 1) == IERROR) GOTOENDRC(IERROR, kty04_join_mgr);
  if(bigz_sub_ui(q1, Mkey->q, 1) == IERROR) GOTOENDRC(IERROR, kty04_join_mgr);
  if(bigz_mul(phin, p1, q1) == IERROR) GOTOENDRC(IERROR, kty04_join_mgr);
  if(bigz_invert(einv, e, phin) == IERROR) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_join_mgr", __LINE__,
		      EDQUOT, "Wrong group.", LOGERROR);
    GOTOENDRC(IERROR, kty04_join_mgr);
  }

  /* Select a random x in the inner sphere of Lambda */
  if(!(x = bigz_init())) GOTOENDRC(IERROR, kty04_join_mgr);
  if(sphere_get_random_prime(gkey->inner_lambda, x) == IERROR) {
    GOTOENDRC(IERROR,kty04_join_mgr);
  }  

  /* A = (C*a^x*a0)^(e^-1) (mod n) */
  if(bigz_powm(mkey->A, gkey->a, x, gkey->n) == IERROR) 
    GOTOENDRC(IERROR, kty04_join_mgr);
  if(bigz_mul(mkey->A, mkey->A, mkey->C) == IERROR)
    GOTOENDRC(IERROR, kty04_join_mgr);
  if(bigz_mul(mkey->A, mkey->A, gkey->a0) == IERROR)
    GOTOENDRC(IERROR, kty04_join_mgr);
  if(bigz_powm(mkey->A, mkey->A, einv, gkey->n) == IERROR) 
    GOTOENDRC(IERROR, kty04_join_mgr);

  if(bigz_set(mkey->x, x) == IERROR) 
    GOTOENDRC(IERROR, kty04_join_mgr);
  if(bigz_set(mkey->e, e) == IERROR) 
    GOTOENDRC(IERROR, kty04_join_mgr);

  /* We are done: */

  /* Update the gml, if any */
  if(gml) {
    
    /* Initialize the GML entry */ 
    if(!(entry = kty04_gml_entry_init())) 
      GOTOENDRC(IERROR, kty04_join_mgr);
    
    if(bigz_set(*(kty04_trapdoor_t *) entry->trapdoor->trap, mkey->x) == IERROR)
      GOTOENDRC(IERROR, kty04_join_mgr);
    
    if(bigz_set(entry->A, mkey->A) == IERROR)
      GOTOENDRC(IERROR, kty04_join_mgr);

    /* Currently, KTY04 identities are just uint64_t's */
    *(kty04_identity_t *) entry->id->id = gml->n;
    
    if(gml_insert(gml, entry) == IERROR) 
      GOTOENDRC(IERROR, kty04_join_mgr);
    
  }

 kty04_join_mgr_end:
  
  if(e) bigz_free(e);
  if(einv) bigz_free(einv);
  if(x) bigz_free(x);
  if(p1) bigz_free(p1);
  if(q1) bigz_free(q1);
  if(phin) bigz_free(phin);

  return rc;

}

/* join_mgr.c ends here */
