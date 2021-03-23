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

#include "bbs04.h"
#include "groupsig/bbs04/grp_key.h"
#include "groupsig/bbs04/mgr_key.h"
#include "groupsig/bbs04/mem_key.h"
#include "groupsig/bbs04/gml.h"
#include "shim/pbc_ext.h"
#include "sys/mem.h"

int bbs04_get_joinseq(uint8_t *seq) {
  *seq = BBS04_JOIN_SEQ;
  return IOK;
}

int bbs04_get_joinstart(uint8_t *start) {
  *start = BBS04_JOIN_START;
  return IOK;
}

int bbs04_join_mgr(message_t **mout, gml_t *gml,
		   groupsig_key_t *mgrkey,
		   int seq, message_t *min,
		   groupsig_key_t *grpkey) {

  groupsig_key_t *memkey;
  bbs04_mem_key_t *bbs04_memkey;
  bbs04_mgr_key_t *bbs04_mgrkey;
  bbs04_grp_key_t *bbs04_grpkey;
  gml_entry_t *bbs04_entry;
  pbcext_element_Fr_t *gammax;
  message_t *_mout;
  byte_t *bkey;
  uint32_t size;
  int rc;

  if(!mout || !gml || gml->scheme != GROUPSIG_BBS04_CODE ||
     !mgrkey || mgrkey->scheme != GROUPSIG_BBS04_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_join_mgr", __LINE__, LOGERROR);
    return IERROR;
  }

  bbs04_mgrkey = (bbs04_mgr_key_t *) mgrkey->key;
  bbs04_grpkey = (bbs04_grp_key_t *) grpkey->key;
  rc = IOK;
  bkey = NULL;
  gammax = NULL;
  memkey = NULL;

  if(!(memkey = bbs04_mem_key_init())) GOTOENDRC(IERROR, bbs04_join_mgr);
  bbs04_memkey = (bbs04_mem_key_t *) memkey->key;

  /* Select memkey->x randomly in Z_p^* */
  if(!(bbs04_memkey->x = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_join_mgr);
  if(pbcext_element_Fr_random(bbs04_memkey->x) == IERROR)
    GOTOENDRC(IERROR, bbs04_join_mgr);

  /* Compute memkey->A = g_1^(1/(mgrkey->gamma+memkey->x)) */
  if(!(gammax = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_join_mgr);
  if(pbcext_element_Fr_add(gammax, bbs04_mgrkey->gamma, bbs04_memkey->x) == IERROR)
    GOTOENDRC(IERROR, bbs04_join_mgr);

  if(!(bbs04_memkey->A = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bbs04_join_mgr);
  if(pbcext_element_G1_set(bbs04_memkey->A, bbs04_grpkey->g1) == IERROR)
    GOTOENDRC(IERROR, bbs04_join_mgr);
  if(pbcext_element_Fr_inv(gammax, gammax) == IERROR)
    GOTOENDRC(IERROR, bbs04_join_mgr);
  if(pbcext_element_G1_mul(bbs04_memkey->A, bbs04_memkey->A, gammax) == IERROR)
    GOTOENDRC(IERROR, bbs04_join_mgr);

  /* Optimization */
  if(!(bbs04_memkey->Ag2 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, bbs04_join_mgr);

  if(pbcext_pairing(bbs04_memkey->Ag2, bbs04_memkey->A, bbs04_grpkey->g2) == IERROR)
    GOTOENDRC(IERROR, bbs04_join_mgr);

  /* Update the GML */
    
  /* Initialize the GML entry */
  if(!(bbs04_entry = bbs04_gml_entry_init()))
    GOTOENDRC(IERROR, bbs04_join_mgr);

  if(!(bbs04_entry->data = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bbs04_join_mgr);
  if(pbcext_element_G1_set(bbs04_entry->data, bbs04_memkey->A) == IERROR)
    GOTOENDRC(IERROR, bbs04_join_mgr);
  bbs04_entry->id = gml->n;
  
  if(gml_insert(gml, bbs04_entry) == IERROR) GOTOENDRC(IERROR, bbs04_join_mgr);

  /* Dump the key into a msg */
  bkey = NULL; 
  if (bbs04_mem_key_export(&bkey, &size, memkey) == IERROR)
    GOTOENDRC(IERROR, bbs04_join_mgr);
  
  if(!*mout) {
    if(!(_mout = message_from_bytes(bkey, size)))
      GOTOENDRC(IERROR, bbs04_join_mgr);
    *mout = _mout;
    
  } else {
    
    _mout = *mout;
    if(message_set_bytes(_mout, bkey, size) == IERROR)
      GOTOENDRC(IERROR, bbs04_join_mgr);
  }
  
 bbs04_join_mgr_end:

  if (gammax) { pbcext_element_Fr_free(gammax); gammax = NULL; }
  if (memkey) { bbs04_mem_key_free(memkey); memkey = NULL; }
  if (bkey) { mem_free(bkey); bkey = NULL; }
  if (rc == IERROR) { bbs04_gml_entry_free(bbs04_entry); bbs04_entry = NULL; }
  
  return rc;

}

/* join_mgr.c ends here */
