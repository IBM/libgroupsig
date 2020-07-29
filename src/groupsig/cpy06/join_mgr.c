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

#include "cpy06.h"
#include "groupsig/cpy06/grp_key.h"
#include "groupsig/cpy06/mgr_key.h"
#include "groupsig/cpy06/mem_key.h"
#include "groupsig/cpy06/gml.h"
#include "groupsig/cpy06/identity.h"
#include "groupsig/cpy06/trapdoor.h"
#include "wrappers/pbc_ext.h"
#include "sys/mem.h"

int cpy06_get_joinseq(uint8_t *seq) {
  *seq = CPY06_JOIN_SEQ;
  return IOK;
}

int cpy06_get_joinstart(uint8_t *start) {
  *start = CPY06_JOIN_START;
  return IOK;
}


/* @TODO This function still follows the old variable structure for join and 
   I am just changing the interface to remove compiler complaints. But this 
   breaks the functionality! Fix! */
//gml_t *gml, groupsig_key_t *memkey, groupsig_key_t *mgrkey, groupsig_key_t *grpkey) {
int cpy06_join_mgr(void **mout, gml_t *gml,
		   groupsig_key_t *mgrkey,
		   int seq, void *min,
		   groupsig_key_t *grpkey) {

  groupsig_key_t *memkey;
  cpy06_mem_key_t *cpy06_memkey;
  cpy06_mgr_key_t *cpy06_mgrkey;
  cpy06_grp_key_t *cpy06_grpkey;
  cpy06_gml_entry_t *cpy06_entry;
  cpy06_trapdoor_t *cpy06_trap;
  cpy06_sysenv_t *cpy06_sysenv;
  element_t gammat,c;

  if(!mout || !gml || gml->scheme != GROUPSIG_CPY06_CODE ||
     !mgrkey || mgrkey->scheme != GROUPSIG_CPY06_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_join_mgr", __LINE__, LOGERROR);
    return IERROR;
  }
  
  cpy06_memkey = (cpy06_mem_key_t *) memkey->key;
  cpy06_mgrkey = (cpy06_mgr_key_t *) mgrkey->key;
  cpy06_grpkey = (cpy06_grp_key_t *) grpkey->key;
  cpy06_sysenv = sysenv->data;

  /* /\* x \in_R Z^*_p (@todo Should be non-adaptively chosen by member) *\/ */
  /* element_init_Zr(cpy06_memkey->x, cpy06_grpkey->pairing); */
  /* element_random(cpy06_memkey->x); */

  /* t \in_R Z^*_p */
  element_init_Zr(cpy06_memkey->t, cpy06_sysenv->pairing);
  element_random(cpy06_memkey->t);

  /* A = (q*g_1^x)^(1/t+\gamma) */
  element_init_Zr(gammat, cpy06_sysenv->pairing);
  element_add(gammat, cpy06_mgrkey->gamma, cpy06_memkey->t);
  element_invert(gammat, gammat);
  element_init_G1(cpy06_memkey->A, cpy06_sysenv->pairing);
  element_pow_zn(cpy06_memkey->A, cpy06_grpkey->g1, cpy06_memkey->x);
  element_mul(cpy06_memkey->A, cpy06_memkey->A, cpy06_grpkey->q);
  element_pow_zn(cpy06_memkey->A,cpy06_memkey->A, gammat);
  element_clear(gammat);

  /* Update the gml, if any */
  if(gml) {

    /* Initialize the GML entry */
    if(!(cpy06_entry = cpy06_gml_entry_init()))
      return IERROR;

    cpy06_trap = (cpy06_trapdoor_t *) cpy06_entry->trapdoor->trap;

    /* Open trapdoor */
    element_init_same_as(cpy06_trap->open, cpy06_memkey->A);
    element_set(cpy06_trap->open, cpy06_memkey->A);

    /* Trace trapdoor */
    element_init_G1(cpy06_trap->trace, cpy06_sysenv->pairing);
    element_pow_zn(cpy06_trap->trace, cpy06_grpkey->g1, cpy06_memkey->x);

    /* Currently, CPY06 identities are just uint64_t's */
    *(cpy06_identity_t *) cpy06_entry->id->id = gml->n;
    
    if(gml_insert(gml, cpy06_entry) == IERROR) {
      cpy06_gml_entry_free(cpy06_entry); cpy06_entry = NULL;
      return IERROR;
    }
    
  }

  return IOK;

}

/* join_mgr.c ends here */
