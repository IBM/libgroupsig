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
#include <pbc/pbc.h>

#include "cpy06.h"
#include "groupsig/cpy06/grp_key.h"
#include "groupsig/cpy06/mgr_key.h"
#include "groupsig/cpy06/gml.h"
#include "math/nt.h"
#include "sys/mem.h"
#include "wrappers/pbc_ext.h"

/* @todo Global variable for quick modification. This should be passed 
   as parameter to _param_generated */
//size_t bitlimit;

/** 
 * @fn static int _setup_parameters_check(int d, unsigned int bitlimit)
 * @brief Checks the input parameters of the setup function.
 *
 * @param[in] bitlimit The produced groups will be of order at most 2^bitlimit-1.
 * 
 * @return IOK if the parameters are valid, IERROR otherwise
 */
static int _setup_parameters_check(unsigned int bitlimit) {

  if(!bitlimit) {
    LOG_EINVAL(&logger, __FILE__, "_setup_parameters_check", __LINE__, LOGERROR);
    return IERROR;
  }

  return IOK;

}

static int _param_generated(pbc_cm_t cm, void *data) {                                                                              
  
  cpy06_genparam_t *genparam;
  
  /* Initialize params */
   genparam = (cpy06_genparam_t *) data;
   pbc_param_init_d_gen(genparam->param, cm);
   if(!(genparam->r = bigz_init_set(&cm->r)) ||
      bigz_sizeinbase(genparam->r, 2) < genparam->bitlimit||
      bigz_sizeinbase(genparam->r, 2) > genparam->bitlimit + genparam->bitlimit/10) {
     bigz_free(genparam->r);
     pbc_param_clear(genparam->param);
     return 0;
   }
  
  return 1;
                                                                                                         
}                                                                                                                   

/**
 * @fn static int _f_param_generate(cpy06_genparam_t *genparam, int bitlimit)
 * @brief Find a Type F curve with at least 'bitlimit' bits in r.
 *
 * @param[in] bitlimit The produced groups will be of order at least 2^bitlimit-1.
 *
 * @return IOK if the parameters are valid, IERROR otherwise
 */
static int _f_param_generate(cpy06_genparam_t *genparam, int bitlimit) {

  pairing_t pairing;
  int attempt_bits = bitlimit;
  
  /* Initialize params */
  pbc_param_init_f_gen(genparam->param, attempt_bits);
  pairing_init_pbc_param(pairing, genparam->param);
  genparam->bitlimit = bitlimit;

  while(bigz_sizeinbase((bigz_t)pairing->r, 2) < bitlimit){
    pbc_param_clear(genparam->param);
    pairing_clear(pairing);
    attempt_bits++;
    pbc_param_init_f_gen(genparam->param, attempt_bits);
    pairing_init_pbc_param(pairing, genparam->param);
  }

  genparam->r = bigz_init_set((bigz_t)pairing->r);
  pairing_clear(pairing);
  return IOK;
}

groupsig_config_t* cpy06_config_init() {
  
  groupsig_config_t *cfg;

  if(!(cfg = (groupsig_config_t *) mem_malloc(sizeof(groupsig_config_t)))) {
    return NULL;
  }

  cfg->scheme = GROUPSIG_CPY06_CODE;
  if(!(cfg->config = (cpy06_config_t *) mem_malloc(sizeof(cpy06_config_t)))) {
    mem_free(cfg); cfg = NULL;
    return NULL;
  }

  CPY06_CONFIG_SET_DEFAULTS((cpy06_config_t *) cfg->config);

  return cfg;

}

int cpy06_config_free(groupsig_config_t *cfg) {

  if(!cfg) {
    return IOK;
  }

  mem_free(cfg->config); cfg->config = NULL;
  mem_free(cfg);
  return IOK;

}

int cpy06_setup(groupsig_key_t *grpkey, groupsig_key_t *mgrkey, gml_t *gml, groupsig_config_t *config) {

  cpy06_genparam_t genparam;
  cpy06_config_t *cpy06_config;
  cpy06_grp_key_t *gkey;
  cpy06_mgr_key_t *mkey;
  cpy06_sysenv_t *cpy06_sysenv;
  element_t inv;
  unsigned int d;
  int status;

  if(!grpkey || grpkey->scheme != GROUPSIG_CPY06_CODE ||
     !mgrkey || grpkey->scheme != GROUPSIG_CPY06_CODE ||
     !config || config->scheme != GROUPSIG_CPY06_CODE ||
     !gml) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_setup", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get input parameters from config->config */ 
  cpy06_config = (cpy06_config_t *) config->config;

  /* if(_setup_parameters_check(cpy06_config->bitlimit) == IERROR) { */
  /*   return IERROR; */
  /* } */

  gkey = grpkey->key;
  mkey = mgrkey->key;

  status = 0;
  status = _f_param_generate(&genparam, cpy06_config->bitlimit);
  if(status != IOK){
    return IERROR;
  }

  /* First, copy the param and pairing to the CPY06 internal environment */
  if(!(cpy06_sysenv = (cpy06_sysenv_t *) mem_malloc(sizeof(cpy06_sysenv_t)))) {
    return IERROR;
  }

  if(pbcext_param_copy(cpy06_sysenv->param, genparam.param) == IERROR) {
    mem_free(cpy06_sysenv); cpy06_sysenv = NULL;
    return IERROR;
  }

  if(cpy06_sysenv_update(cpy06_sysenv) == IERROR) {
    pbc_param_clear(cpy06_sysenv->param);
    mem_free(cpy06_sysenv); cpy06_sysenv = NULL;
    return IERROR;
  }

  /* Initialize the pairing structure with the obtained params */
  pairing_init_pbc_param(cpy06_sysenv->pairing, cpy06_sysenv->param);

  /* Select random generator g2 in G2. Since G2 is a cyclic multiplicative group 
     of prime order, any element is a generator, so choose some random element. */
  element_init_G2(gkey->g2, cpy06_sysenv->pairing);
  element_random(gkey->g2);
  
  element_init_G1(gkey->g1, cpy06_sysenv->pairing);
  // gkey->pairing->phi(gkey->g1, gkey->g2, gkey->pairing);
  element_random(gkey->g1);

  /* Create group manager private key */

  /* \xi_1 \in_R Z^*_p */
  element_init_Zr(mkey->xi1, cpy06_sysenv->pairing);
  element_random(mkey->xi1);
  
  /* \xi_2 \in_R Z^*_p */
  element_init_Zr(mkey->xi2, cpy06_sysenv->pairing);
  element_random(mkey->xi2);

  /* \gamma \in_R Z^*_p */
  element_init_Zr(mkey->gamma, cpy06_sysenv->pairing);
  element_random(mkey->gamma);
  
  /* Create group public key */

  /* Q \in_R G1 */
  element_init_G1(gkey->q, cpy06_sysenv->pairing);
  element_random(gkey->q);

  /* R = g2^\gamma */
  element_init_G2(gkey->r, cpy06_sysenv->pairing);
  element_pow_zn(gkey->r, gkey->g2, mkey->gamma);
  
  /* W \in_R G2 \setminus 1 */
  element_init_G2(gkey->w, cpy06_sysenv->pairing);
  element_random(gkey->w);

  /* Z \in_R G1 \setminus 1 */
  element_init_G1(gkey->z, cpy06_sysenv->pairing);
  do {
    element_random(gkey->z);
  } while(element_is1(gkey->z));

  /* X = Z^(\xi_1^-1) */
  element_init_Zr(inv, cpy06_sysenv->pairing);
  element_invert(inv, mkey->xi1);
  element_init_G1(gkey->x, cpy06_sysenv->pairing);
  element_pow_zn(gkey->x, gkey->z, inv);

  /* Y = Z^(\xi_2^-1) */
  element_invert(inv, mkey->xi2);
  element_init_G1(gkey->y, cpy06_sysenv->pairing);
  element_pow_zn(gkey->y, gkey->z, inv);

  /* For computation optimizations */

  /* T5 = e(g1, W) */
  element_init_GT(gkey->T5, cpy06_sysenv->pairing);
  element_pairing(gkey->T5, gkey->g1, gkey->w);

  /* e2 = e(z,g2) */
  element_init_GT(gkey->e2, cpy06_sysenv->pairing);
  element_pairing(gkey->e2, gkey->z, gkey->g2);

  /* e3 = e(z,r) */
  element_init_GT(gkey->e3, cpy06_sysenv->pairing);
  element_pairing(gkey->e3, gkey->z, gkey->r);

  /* e4 = e(g1,g2) */
  element_init_GT(gkey->e4, cpy06_sysenv->pairing);
  element_pairing(gkey->e4, gkey->g1, gkey->g2);

  /* e5 = e(q,g2) */
  element_init_GT(gkey->e5, cpy06_sysenv->pairing);
  element_pairing(gkey->e5, gkey->q, gkey->g2);

  /* Clear data */
  element_clear(inv);
  bigz_free(genparam.r);
  pbc_param_clear(genparam.param);

  return IOK;

}

/* setup.c ends here */
