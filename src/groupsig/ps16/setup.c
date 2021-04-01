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

#include "ps16.h"
#include "logger.h"
#include "groupsig/ps16/grp_key.h"
#include "groupsig/ps16/mgr_key.h"
#include "groupsig/ps16/gml.h"
#include "sys/mem.h"
#include "shim/pbc_ext.h"

int ps16_init() {

  if(pbcext_init(BLS12_381) == IERROR) {
    return IERROR;
  }  

  return IOK;

}

int ps16_clear() {  
  return IOK;
}

int ps16_setup(groupsig_key_t *grpkey,
	       groupsig_key_t *mgrkey,
	       gml_t *gml) {

  ps16_grp_key_t *gkey;
  ps16_mgr_key_t *mkey;
  pbcext_element_Fr_t *inv;
  int rc;

  if(!grpkey || grpkey->scheme != GROUPSIG_PS16_CODE ||
     !mgrkey || mgrkey->scheme != GROUPSIG_PS16_CODE ||
     !gml) {
    LOG_EINVAL(&logger, __FILE__, "ps16_setup", __LINE__, LOGERROR);
    return IERROR;
  }

  gkey = grpkey->key;
  mkey = mgrkey->key;
  rc = IOK;

  /* Set manager key */
  if(!(mkey->x = pbcext_element_Fr_init())) GOTOENDRC(IERROR, ps16_setup);
  if(pbcext_element_Fr_random(mkey->x) == IERROR)
    GOTOENDRC(IERROR, ps16_setup);
  if(!(mkey->y = pbcext_element_Fr_init())) GOTOENDRC(IERROR, ps16_setup);
  if(pbcext_element_Fr_random(mkey->y))
    GOTOENDRC(IERROR, ps16_setup);
  
  /* Set group key */
  if(!(gkey->g = pbcext_element_G1_init())) GOTOENDRC(IERROR, ps16_setup);
  if(pbcext_element_G1_random(gkey->g) == IERROR)
    GOTOENDRC(IERROR, ps16_setup);  
  if(!(gkey->gg = pbcext_element_G2_init())) GOTOENDRC(IERROR, ps16_setup);
  if(pbcext_element_G2_random(gkey->gg) == IERROR)
    GOTOENDRC(IERROR, ps16_setup);
  
  if(!(gkey->X = pbcext_element_G2_init())) GOTOENDRC(IERROR, ps16_setup);
  if(pbcext_element_G2_mul(gkey->X, gkey->gg, mkey->x) == IERROR)
    GOTOENDRC(IERROR, ps16_setup);
  if(!(gkey->Y = pbcext_element_G2_init())) GOTOENDRC(IERROR, ps16_setup);
  if(pbcext_element_G2_mul(gkey->Y, gkey->gg, mkey->y) == IERROR)
    GOTOENDRC(IERROR, ps16_setup);  

 ps16_setup_end:

  if (rc == IERROR) {
    if (mkey->x) { pbcext_element_Fr_free(mkey->x); mkey->x = NULL; }
    if (gkey->g) { pbcext_element_G1_free(gkey->g); gkey->g = NULL; }
    if (gkey->g) { pbcext_element_G2_free(gkey->gg); gkey->gg = NULL; }
    if (gkey->X) { pbcext_element_G2_free(gkey->X); gkey->X = NULL; }
    if (gkey->Y) { pbcext_element_G2_free(gkey->Y); gkey->Y = NULL; }    
  }

  return rc;

}

/* setup.c ends here */
