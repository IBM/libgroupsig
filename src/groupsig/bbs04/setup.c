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
#include <math.h>

#include "bbs04.h"
#include "logger.h"
#include "groupsig/bbs04/grp_key.h"
#include "groupsig/bbs04/mgr_key.h"
#include "groupsig/bbs04/gml.h"
#include "sys/mem.h"
#include "shim/pbc_ext.h"

int bbs04_init() {
  
  if(pbcext_init(BLS12_381) == IERROR) {
    return IERROR;
  }  

  return IOK;

}

int bbs04_clear() {  
  return IOK;
}

int bbs04_setup(groupsig_key_t *grpkey,
		groupsig_key_t *mgrkey,
		gml_t *gml) {

  bbs04_grp_key_t *gkey;
  bbs04_mgr_key_t *mkey;
  pbcext_element_Fr_t *inv;
  int rc;

  if(!grpkey || grpkey->scheme != GROUPSIG_BBS04_CODE ||
     !mgrkey || mgrkey->scheme != GROUPSIG_BBS04_CODE ||
     !gml) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_setup", __LINE__, LOGERROR);
    return IERROR;
  }

  gkey = grpkey->key;
  mkey = mgrkey->key;
  rc = IOK;
  inv = NULL;

  /* Select random generator g2 in G2. Since G2 is a cyclic multiplicative group 
     of prime order, any element is a generator, so choose some random element. */
  if(!(gkey->g2 = pbcext_element_G2_init())) GOTOENDRC(IERROR, bbs04_setup);
  if(pbcext_element_G2_random(gkey->g2) == IERROR)
    GOTOENDRC(IERROR, bbs04_setup);

  /* @TODO g1 is supposed to be the trace of g2... */
  if(!(gkey->g1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, bbs04_setup);
  if(pbcext_element_G1_random(gkey->g1) == IERROR)
    GOTOENDRC(IERROR, bbs04_setup);

  /* h random in G1 \ 1 */
  if(!(gkey->h = pbcext_element_G1_init())) GOTOENDRC(IERROR, bbs04_setup);
  do {
    if(pbcext_element_G1_random(gkey->h) == IERROR)
      GOTOENDRC(IERROR, bbs04_setup);
  } while(pbcext_element_G1_is0(gkey->h));

  /* xi1 and xi2 random in Z^*_p */
  if(!(mkey->xi1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bbs04_setup);
  if(pbcext_element_Fr_random(mkey->xi1) == IERROR)
    GOTOENDRC(IERROR, bbs04_setup);
  if(!(mkey->xi2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bbs04_setup);
  if(pbcext_element_Fr_random(mkey->xi2))
    GOTOENDRC(IERROR, bbs04_setup);

  /* u = h^(1/xi1) */
  if(!(inv = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bbs04_setup);
  if(!(gkey->u = pbcext_element_G1_init())) GOTOENDRC(IERROR, bbs04_setup);
  if(pbcext_element_Fr_inv(inv, mkey->xi1) == IERROR)
    GOTOENDRC(IERROR, bbs04_setup);
  if(pbcext_element_G1_mul(gkey->u, gkey->h, inv) == IERROR)
    GOTOENDRC(IERROR, bbs04_setup);

  /* v = h^(1/xi2) */
  if(!(gkey->v = pbcext_element_G1_init())) GOTOENDRC(IERROR, bbs04_setup);
  if(pbcext_element_Fr_inv(inv, mkey->xi2) == IERROR)
    GOTOENDRC(IERROR, bbs04_setup);
  if(pbcext_element_G1_mul(gkey->v, gkey->h, inv) == IERROR)
    GOTOENDRC(IERROR, bbs04_setup);

  /* gamma random in Z^*_p */
  if(!(mkey->gamma = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bbs04_setup);
  if(pbcext_element_Fr_random(mkey->gamma) == IERROR)
    GOTOENDRC(IERROR, bbs04_setup);

  /* w = g_2^gamma */
  if(!(gkey->w = pbcext_element_G2_init())) GOTOENDRC(IERROR, bbs04_setup);
  if(pbcext_element_G2_mul(gkey->w, gkey->g2, mkey->gamma) == IERROR)
    GOTOENDRC(IERROR, bbs04_setup);

  /* Optimizations */

  /* hw = e(h,w) */
  if(!(gkey->hw = pbcext_element_GT_init())) GOTOENDRC(IERROR, bbs04_setup);

  if(pbcext_pairing(gkey->hw, gkey->h, gkey->w) == IERROR)
    GOTOENDRC(IERROR, bbs04_setup);

  /* hg2 = e(h, g2) */
  if(!(gkey->hg2 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bbs04_setup);
  if(pbcext_pairing(gkey->hg2, gkey->h, gkey->g2) == IERROR)
    GOTOENDRC(IERROR, bbs04_setup);

  /* g1g2 = e(g2, g2) */
  if(!(gkey->g1g2 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bbs04_setup);
  if(pbcext_pairing(gkey->g1g2, gkey->g1, gkey->g2) == IERROR)
    GOTOENDRC(IERROR, bbs04_setup);

 bbs04_setup_end:

  if(inv) { pbcext_element_Fr_free(inv); inv = NULL; }

  return rc;

}

/* setup.c ends here */
