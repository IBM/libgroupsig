/*                               -*- Mode: C -*- 
 *
 *	libgroupsig Group Signatures library
 *	Copyright (C) 2012-2013 Jesus Diaz Vico
 *
 *		
 *
 *	This file is part of the libgroupsig Group Signatures library.
 *
 *
 *  The libgroupsig library is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License as 
 *  defined by the Free Software Foundation, either version 3 of the License, 
 *  or any later version.
 *
 *  The libroupsig library is distributed WITHOUT ANY WARRANTY; without even 
 *  the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
 *  See the GNU Lesser General Public License for more details.
 *
 *
 *  You should have received a copy of the GNU Lesser General Public License 
 *  along with Group Signature Crypto Library.  If not, see <http://www.gnu.org/
 *  licenses/>
 *
 * @file: blind.c
 * @brief: 
 * @author: jesus
 * Maintainer: 
 * @date: lun jun 11 12:53:13 2012 (+0200)
 * @version: 
 * Last-Updated: lun ago  5 15:10:56 2013 (+0200)
 *           By: jesus
 *     Update #: 4
 * URL: 
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "types.h"
#include "sysenv.h"
#include "bigz.h"
#include "sys/mem.h"
#include "dl21.h"
#include "groupsig/dl21/grp_key.h"
#include "groupsig/dl21/mem_key.h"
#include "groupsig/dl21/signature.h"
#include "groupsig/dl21/identity.h"
#include "shim/hash.h"
#include "shim/pbc_ext.h"

int dl21_identify(uint8_t *ok,
		  groupsig_proof_t **proof,
		  groupsig_key_t *grpkey,
		  groupsig_key_t *memkey,
		  groupsig_signature_t *sig,
		  message_t *msg) {
  
  pbcext_element_G1_t *hscp;
  dl21_signature_t *dl21_sig;
  dl21_mem_key_t *dl21_memkey;
  hash_t *hc;
  char *msg_scp;
  int rc;
  uint8_t _ok;
  
  if(!ok ||
     !grpkey || grpkey->scheme != GROUPSIG_DL21_CODE ||
     !memkey || memkey->scheme != GROUPSIG_DL21_CODE ||
     !sig || sig->scheme != GROUPSIG_DL21_CODE ||
     !msg) {
    LOG_EINVAL(&logger, __FILE__, "dl21_identify", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  hscp = NULL;
  hc = NULL;
  msg_scp = NULL;
  
  dl21_sig = sig->sig;
  dl21_memkey = memkey->key;

  /* Recompute nym */
  
  /* Parse scope value from msg */
  if(message_json_get_key(&msg_scp, msg, "$.scope") == IERROR)
    GOTOENDRC(IERROR, dl21_identify);

  if(!(hscp = pbcext_element_G1_init())) GOTOENDRC(IERROR, dl21_identify);
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, dl21_identify);
  if(hash_update(hc, (byte_t *) msg_scp, strlen(msg_scp)) == IERROR)
    GOTOENDRC(IERROR, dl21_identify);
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, dl21_identify);
  pbcext_element_G1_from_hash(hscp, hc->hash, hc->length);

  if(pbcext_element_G1_mul(hscp, hscp, dl21_memkey->y) == IERROR)
    GOTOENDRC(IERROR, dl21_identify);
  
  /* Check if nym = h(scp)^y */
  if(pbcext_element_G1_cmp(hscp, dl21_sig->nym)) {
    *ok = 0;
    GOTOENDRC(IOK, dl21_identify);
  } else {
    *ok = 1;
  }
    
 dl21_identify_end:

  if(hscp) { pbcext_element_G1_free(hscp); hscp = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }
  
  return rc;

}

/* identify.c ends here */
