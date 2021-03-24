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
 * @file: proof.c
 * @brief: 
 * @author: jesus
 * Maintainer: 
 * @date: lun dic 10 21:24:27 2012 (-0500)
 * @version: 
 * Last-Updated: lun ago  5 15:11:47 2013 (+0200)
 *           By: jesus
 *     Update #: 7
 * URL: 
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <math.h>

#include "types.h"
#include "sysenv.h"
#include "sys/mem.h"
#include "shim/base64.h"
#include "shim/pbc_ext.h"
#include "misc/misc.h"
#include "dl21.h"
#include "groupsig/dl21/proof.h"
#include "crypto/spk.h"

groupsig_proof_t* dl21_proof_init() {

  groupsig_proof_t *proof;

  if(!(proof = (groupsig_proof_t *) mem_malloc(sizeof(groupsig_proof_t)))) {
    return NULL;
  }

  proof->scheme = GROUPSIG_DL21_CODE;
  if (!(proof->proof = spk_dlog_init())) {
    mem_free(proof); proof = NULL;
    return NULL;
  }

  return proof;

}

int dl21_proof_free(groupsig_proof_t *proof) {

  if(!proof) {
    LOG_EINVAL_MSG(&logger, __FILE__, "dl21_proof_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IERROR;
  }

  if(proof->proof) { spk_dlog_free(proof->proof); proof->proof = NULL; }
  mem_free(proof);

  return IOK;

}

char* dl21_proof_to_string(groupsig_proof_t *proof) {

  if(!proof || proof->scheme != GROUPSIG_DL21_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21_proof_to_string", __LINE__, LOGERROR);
    return NULL;
  }
  
  return NULL;

}

int dl21_proof_copy(groupsig_proof_t *dst, groupsig_proof_t *src) {

  dl21_proof_t *dl21_dst, *dl21_src;
  
  if (!dst || !src) {
    LOG_EINVAL(&logger, __FILE__, "dl21_proof_copy", __LINE__, LOGERROR);
    return IERROR;    
  }

  dl21_dst = dst->proof;
  dl21_src = src->proof;
  
  if (spk_dlog_copy(dl21_dst, dl21_src) == IERROR) {
    spk_dlog_free(dl21_dst); dl21_dst = NULL;
    return IERROR;
  }

  return IOK;
  
}

int dl21_proof_export(byte_t **bytes, uint32_t *size, groupsig_proof_t *proof) {

  dl21_proof_t *dl21_proof;
  byte_t *_bytes, *__bytes;
  int rc, _size;
  uint64_t proof_len;

  if(!proof || proof->scheme != GROUPSIG_DL21_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21_proof_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  dl21_proof = proof->proof;

  if ((_size = dl21_proof_get_size(proof)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }  

  /* Dump GROUPSIG_DL21_CODE */
  _bytes[0] = GROUPSIG_DL21_CODE;

  /* Export the SPK */
  __bytes = &_bytes[1];  
  if (spk_dlog_export(&__bytes,
		      &proof_len,
		      dl21_proof) == IERROR)
    GOTOENDRC(IERROR, dl21_proof_export);
  
  /* Sanity check */
  if (_size != proof_len+1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "dl21_proof_export", __LINE__,
  		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, dl21_proof_export);
  }

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, _size);
    mem_free(_bytes); _bytes = NULL;
  }

  *size = _size;  

 dl21_proof_export_end:
  
  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }
  return rc;

}

groupsig_proof_t* dl21_proof_import(byte_t *source, uint32_t size) {

  groupsig_proof_t *proof;
  uint64_t proof_len;
  int rc;
  uint8_t scheme;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "dl21_proof_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;

  if(!(proof = dl21_proof_init())) {
    return NULL;
  }

  /* First byte: scheme */
  scheme = source[0];
  if (scheme != proof->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "dl21_proof_import", __LINE__, 
		      EDQUOT, "Unexpected proof scheme.", LOGERROR);
    GOTOENDRC(IERROR, dl21_proof_import);
  }

  if (!(proof->proof = spk_dlog_init()))
    GOTOENDRC(IERROR, dl21_proof_import);

  if (!(proof->proof = spk_dlog_import(&source[1], &proof_len)))
    GOTOENDRC(IERROR, dl21_proof_import);
  
  if (proof_len != size - 1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "dl21_proof_import", __LINE__, 
		      EDQUOT, "Unexpected proof size.", LOGERROR);
    GOTOENDRC(IERROR, dl21_proof_import);
  }

 dl21_proof_import_end:

  if(rc == IERROR && proof) { dl21_proof_free(proof); proof = NULL; }
  if(rc == IOK) return proof;
  return NULL;  
  
}

int dl21_proof_get_size(groupsig_proof_t *proof) {

  dl21_proof_t *dl21_proof;
  uint64_t size, proof_len;
  
  if(!proof || proof->scheme != GROUPSIG_DL21_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21_proof_get_size", __LINE__, LOGERROR);
    return -1;
  }

  dl21_proof = proof->proof;

  if ((proof_len = spk_dlog_get_size(dl21_proof)) == -1)
    return -1;

  size = proof_len + /* sizeof(int)*1 */ + 1;

  if (size > INT_MAX) return -1;
  
  return (int) size;

}

/* proof.c ends here */
