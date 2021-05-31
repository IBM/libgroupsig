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

#include "dl21seq.h"
#include "groupsig/dl21seq/grp_key.h"
#include "groupsig/dl21seq/mgr_key.h"
#include "sys/mem.h"

int dl21seq_init() {

  if(pbcext_init(BLS12_381) == IERROR) {
    return IERROR;
  }
  
  return IOK;

}

int dl21seq_clear() {
  return IOK;  
}

int dl21seq_setup(groupsig_key_t *grpkey,
		  groupsig_key_t *mgrkey,
		  gml_t *gml) {

  dl21seq_grp_key_t *gkey;
  dl21seq_mgr_key_t *mkey;
  int rc, status;

  if(!grpkey || grpkey->scheme != GROUPSIG_DL21SEQ_CODE ||
     !mgrkey || grpkey->scheme != GROUPSIG_DL21SEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21seq_setup", __LINE__, LOGERROR);
    return IERROR;
  }

  gkey = grpkey->key;
  mkey = mgrkey->key;
  rc = IOK;

  /* Initialize the manager key */
  if(!(mkey->isk = pbcext_element_Fr_init())) GOTOENDRC(IERROR, dl21seq_setup);
  if(pbcext_element_Fr_random(mkey->isk) == IERROR)
    GOTOENDRC(IERROR, dl21seq_setup);

  /* Initialize the group key */
  
  /* Compute random generators g1, h1 and h2 in G1. Since G1 is a cyclic 
     group of prime order, just pick random elements.  */
  if(!(gkey->g1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, dl21seq_setup);
  if(pbcext_element_G1_random(gkey->g1) == IERROR)
    GOTOENDRC(IERROR, dl21seq_setup);

  if(!(gkey->h1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, dl21seq_setup);
  if(pbcext_element_G1_random(gkey->h1) == IERROR)
    GOTOENDRC(IERROR, dl21seq_setup);

  if(!(gkey->h2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, dl21seq_setup);
  if(pbcext_element_G1_random(gkey->h2) == IERROR)
    GOTOENDRC(IERROR, dl21seq_setup);

  /* Compute random generator g2 in G2. Since G2 is a cyclic group of prime 
     order, just pick a random element. */
  if(!(gkey->g2 = pbcext_element_G2_init())) GOTOENDRC(IERROR, dl21seq_setup);
  if(pbcext_element_G2_random(gkey->g2) == IERROR)
    GOTOENDRC(IERROR, dl21seq_setup);

  /* Set the Issuer public key */
  if(!(gkey->ipk = pbcext_element_G2_init())) GOTOENDRC(IERROR, dl21seq_setup);
  if(pbcext_element_G2_mul(gkey->ipk, gkey->g2, mkey->isk) == IERROR)
    GOTOENDRC(IERROR, dl21seq_setup);

 dl21seq_setup_end:

  if (rc == IERROR) {
    if (mkey->isk) { pbcext_element_Fr_free(mkey->isk); mkey->isk = NULL; }
    if (gkey->g1) { pbcext_element_G1_free(gkey->g1); gkey->g1 = NULL; }
    if (gkey->h1) { pbcext_element_G1_free(gkey->h1); gkey->h1 = NULL; }
    if (gkey->h2) { pbcext_element_G1_free(gkey->h2); gkey->h2 = NULL; }
    if (gkey->g2) { pbcext_element_G2_free(gkey->g2); gkey->g2 = NULL; }
    if (gkey->ipk) { pbcext_element_G2_free(gkey->ipk); gkey->ipk = NULL; }
  }

  return rc;

}

/* setup.c ends here */
