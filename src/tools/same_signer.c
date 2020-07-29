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
#include <libgen.h>

#include "groupsig.h"
#include "gml.h"
#include "crl.h"

#include "message.h"
#include "logger.h"

log_t logger;
sysenv_t *sysenv;

int main(int argc, char *argv[]) {

  char *s_sig1, *s_sig2, *s_grpkey, *s_mgrkey, *s_gml, *s_crl;
  groupsig_key_t *grpkey, *mgrkey;
  gml_t *gml;
  crl_t *crl;
  groupsig_signature_t *sig1, *sig2;
  identity_t *id1, *id2;
  int key_format, sig_format;
  uint8_t scheme;

  if(argc == 1) {
    fprintf(stdout, "Usage: %s <scheme> <sig1> <sig2> <grp_key> <mgr_key> <GML> <CRL>\n",
	    basename(argv[0]));
    return IOK;
  }

  if((groupsig_get_code_from_str(&scheme, argv[1])) == IERROR) {
    fprintf(stderr, "Error: Wrong scheme %s\n", argv[1]);
    return IERROR;
  }

  /* @todo fixed key formats! */
  if(scheme == GROUPSIG_KTY04_CODE) {
    key_format = GROUPSIG_KEY_FORMAT_FILE_NULL_B64;
    sig_format = GROUPSIG_SIGNATURE_FORMAT_FILE_NULL_B64;
  } else if (scheme == GROUPSIG_BBS04_CODE ||
	     scheme == GROUPSIG_CPY06_CODE) {
    key_format = GROUPSIG_KEY_FORMAT_FILE_NULL;
    sig_format = GROUPSIG_SIGNATURE_FORMAT_FILE_NULL;
  }

  s_sig1 = argv[2];
  s_sig2 = argv[3];
  s_grpkey = argv[4];
  s_mgrkey = argv[5];
  s_gml = argv[6];
  s_crl = argv[7];

  groupsig_init(time(NULL));

  if(!(grpkey = groupsig_grp_key_import(scheme,
					key_format,
					s_grpkey))) {
    fprintf(stderr, "Error: invalid group key %s.\n", s_grpkey);
    return IERROR;
  }

  if(!(mgrkey = groupsig_mgr_key_import(scheme,
					key_format,
					s_mgrkey))) {
    fprintf(stderr, "Error: invalid manager key %s.\n", s_mgrkey);
    return IERROR;
  }

  if(!(gml = gml_import(scheme, GML_FILE, s_gml))) {
    fprintf(stderr, "Error: invalid GML %s.\n", s_gml);
    return IERROR;
  }

  if(!(crl = crl_import(scheme, CRL_FILE, s_crl))) {
    fprintf(stderr, "Error: invalid CRL %s.\n", s_crl);
    return IERROR;
  }

  if(!(sig1 = groupsig_signature_import(scheme,
  				        sig_format,
				   	s_sig1))) {
    fprintf(stderr, "Error: failed to import signature %s\n", s_sig1);
    return IERROR;
  }

  if(!(sig2 = groupsig_signature_import(scheme,
  				        sig_format,
				   	s_sig2))) {
    fprintf(stderr, "Error: failed to import signature %s\n", s_sig1);
    return IERROR;
  }

  if(!(id1 = identity_init(scheme))) {
    fprintf(stderr, "Error creating identity.\n");
    return IERROR;
  }

  if(groupsig_open(id1, NULL, NULL, sig1, grpkey, mgrkey, gml) == IERROR) {
    fprintf(stderr, "Error opening signature.\n");
    return IERROR;
  }

  if(!(id2 = identity_init(scheme))) {
    fprintf(stderr, "Error creating identity.\n");
    return IERROR;
  }

  if(groupsig_open(id2, NULL, NULL, sig2, grpkey, mgrkey, gml) == IERROR) {
    fprintf(stderr, "Error opening signature.\n");
    return IERROR;
  }

  if(*(uint64_t *) id1->id == *(uint64_t *) id2->id) {
    fprintf(stdout, "Same signer.\n");
    return IOK;
  }

  fprintf(stdout, "Different signer.\n");
  return IOK;
  
}

/* same_signer.c ends here */
