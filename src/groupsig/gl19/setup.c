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

#include "gl19.h"
#include "logger.h"
#include "groupsig/gl19/grp_key.h"
#include "groupsig/gl19/mgr_key.h"
#include "math/nt.h"
#include "sys/mem.h"


int gl19_init() {

  if(pbcext_init(BLS12_381) == IERROR) {
    return IERROR;
  }
  
  return IOK;

}

int gl19_clear() {
  return IOK;  
}

int gl19_setup(groupsig_key_t *grpkey,
	       groupsig_key_t *mgrkey,
	       gml_t *gml) {

  gl19_grp_key_t *gkey;
  gl19_mgr_key_t *mkey;
  int rc;
  uint8_t call;
  
  if(!grpkey || grpkey->scheme != GROUPSIG_GL19_CODE ||
     !mgrkey || grpkey->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_setup", __LINE__, LOGERROR);
    return IERROR;
  }
  
  gkey = grpkey->key;
  mkey = mgrkey->key;
  rc = IOK;
  call = 0;

  /* 
   * If the group key is "empty" (we check gkey->g for this), we interpret this
   * as the first call. In this case, we generate the Issuer's keypair, and all 
   * the group public key except for the Converter's public key.
   */
  if (!gkey->g1) {

    call = 1;
    
    /* Initialize the manager key */
    if(!(mkey->isk = pbcext_element_Fr_init())) GOTOENDRC(IERROR, gl19_setup);
    if(pbcext_element_Fr_random(mkey->isk) == IERROR)
      GOTOENDRC(IERROR, gl19_setup);

    /* Initialize the group key */

    /* Compute random generators g1, g, h, h1 and h2 in G1. Since G1 is a cyclic
       group of prime order, just pick random elements.  */
    if(!(gkey->g1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, gl19_setup);
    if(pbcext_element_G1_random(gkey->g1) == IERROR)
      GOTOENDRC(IERROR, gl19_setup);
    
    if(!(gkey->g = pbcext_element_G1_init())) GOTOENDRC(IERROR, gl19_setup);
    if(pbcext_element_G1_random(gkey->g) == IERROR)
      GOTOENDRC(IERROR, gl19_setup);

    if(!(gkey->h = pbcext_element_G1_init())) GOTOENDRC(IERROR, gl19_setup);
    if(pbcext_element_G1_random(gkey->h) == IERROR)
      GOTOENDRC(IERROR, gl19_setup);
    
    if(!(gkey->h1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, gl19_setup);
    if(pbcext_element_G1_random(gkey->h1) == IERROR)
      GOTOENDRC(IERROR, gl19_setup);

    if(!(gkey->h2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, gl19_setup);
    if(pbcext_element_G1_random(gkey->h2) == IERROR)
      GOTOENDRC(IERROR, gl19_setup);

    if(!(gkey->h3 = pbcext_element_G1_init())) GOTOENDRC(IERROR, gl19_setup);
    if(pbcext_element_G1_random(gkey->h3) == IERROR)
      GOTOENDRC(IERROR, gl19_setup);    
    
    /* Compute random generator g2 in G2. Since G2 is a cyclic group of prime 
       order, just pick a random element. */
    if(!(gkey->g2 = pbcext_element_G2_init())) GOTOENDRC(IERROR, gl19_setup);
    if(pbcext_element_G2_random(gkey->g2) == IERROR)
      GOTOENDRC(IERROR, gl19_setup);

    /* Add the Issuer's public key to the group key */
    if(!(gkey->ipk = pbcext_element_G2_init())) GOTOENDRC(IERROR, gl19_setup);
    if(pbcext_element_G2_mul(gkey->ipk, gkey->g2, mkey->isk) == IERROR)
      GOTOENDRC(IERROR, gl19_setup);    
  }
  
  /*
   * If the group key is not "empty" (gkey->g1 != null), we interpret this as 
   * the second call. In this case, we set the manager's key to an initialized
   * Converter key (using the value of g computed in the first call), and fill
   * the received public key with the public part of the Converter's keypair.
   */
  else {

    call = 2;

    if(!gkey->g) {
      LOG_EINVAL_MSG(&logger, __FILE__, "gl19_setup", __LINE__,
		     "The group public key has not been properly initialized",
		     LOGERROR);
      return IERROR;
    }

    /* Generate the Converter's private key */
    if(!(mkey->csk = pbcext_element_Fr_init())) GOTOENDRC(IERROR, gl19_setup);
    if(pbcext_element_Fr_random(mkey->csk) == IERROR)
      GOTOENDRC(IERROR, gl19_setup);

    /* Add the Converter's public key to the group key */
    if(!(gkey->cpk = pbcext_element_G1_init())) GOTOENDRC(IERROR, gl19_setup);
    if(pbcext_element_G1_mul(gkey->cpk, gkey->g, mkey->csk) == IERROR)
      GOTOENDRC(IERROR, gl19_setup);

    /* Generate the Extractor's private key */
    if(!(mkey->esk = pbcext_element_Fr_init())) GOTOENDRC(IERROR, gl19_setup);
    if(pbcext_element_Fr_random(mkey->esk) == IERROR)
      GOTOENDRC(IERROR, gl19_setup);

    /* Add the Extractor's public key to the group key */
    if(!(gkey->epk = pbcext_element_G1_init())) GOTOENDRC(IERROR, gl19_setup);
    if(pbcext_element_G1_mul(gkey->epk, gkey->g, mkey->esk) == IERROR)
      GOTOENDRC(IERROR, gl19_setup);
    
  }  

 gl19_setup_end:

  if (rc == IERROR) {

    /* These are only allocated in "1" calls -- don't clean them upon 
       error otherwise. */    
    if (call == 1) {
      if (mkey->isk) { pbcext_element_Fr_free(mkey->isk); mkey->isk = NULL; }
      if (gkey->g1) { pbcext_element_G1_free(gkey->g1); gkey->g1 = NULL; }
      if (gkey->g) { pbcext_element_G1_free(gkey->g); gkey->g = NULL; }
      if (gkey->h) { pbcext_element_G1_free(gkey->h); gkey->h1 = NULL; }
      if (gkey->h1) { pbcext_element_G1_free(gkey->h1); gkey->h1 = NULL; }
      if (gkey->h2) { pbcext_element_G1_free(gkey->h2); gkey->h2 = NULL; }
      if (gkey->h3) { pbcext_element_G1_free(gkey->h3); gkey->h3 = NULL; }      
      if (gkey->g2) { pbcext_element_G2_free(gkey->g2); gkey->g2 = NULL; }
      if (gkey->ipk) { pbcext_element_G2_free(gkey->ipk); gkey->ipk = NULL; }
    }

    if (mkey->csk) { pbcext_element_Fr_free(mkey->csk); mkey->csk = NULL; }    
    if (gkey->cpk) { pbcext_element_G1_free(gkey->cpk); gkey->cpk = NULL; }
    if (mkey->esk) { pbcext_element_Fr_free(mkey->esk); mkey->esk = NULL; }
    if (gkey->epk) { pbcext_element_G1_free(gkey->epk); gkey->epk = NULL; }    

  }

  return rc;

}

/* setup.c ends here */
