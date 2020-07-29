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

#include <stdlib.h>

#include "types.h"
#include "crl.h"
#include "crl_handles.h"
#include "logger.h"

const crl_handle_t* crl_handle_from_code(uint8_t code) {

  int i;
  
  for(i=0; i<CRL_HANDLES_N; i++) {
    if(CRL_HANDLES[i]->scheme == code)
      return CRL_HANDLES[i];
  }

  return NULL;

}

crl_t* crl_init(uint8_t scheme) {

  const crl_handle_t *ch;

  /* Get the CRL handles from the code */
  if(!(ch = crl_handle_from_code(scheme))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "crl_init", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return NULL;
  }
  
  return ch->crl_init();  

}

int crl_free(crl_t *crl) {

  const crl_handle_t *ch;

  /* Get the CRL handles from the code */
  if(!(ch = crl_handle_from_code(crl->scheme))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "crl_free", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return IERROR;
  }
  
  return ch->crl_free(crl);  

}

int crl_insert(crl_t *crl, void *entry) {

  const crl_handle_t *ch;

  if(!crl || !entry) {
    LOG_EINVAL(&logger, __FILE__, "crl_insert", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the CRL handles from the code */
  if(!(ch = crl_handle_from_code(crl->scheme))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "crl_insert", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return IERROR;
  }

  return ch->crl_insert(crl, entry);

}

int crl_remove(crl_t *crl, uint64_t index) {

  const crl_handle_t *ch;

  if(!crl) {
    LOG_EINVAL(&logger, __FILE__, "crl_remove", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the CRL handles from the code */
  if(!(ch = crl_handle_from_code(crl->scheme))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "crl_remove", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return IERROR;
  }

  return ch->crl_remove(crl, index);

}

void* crl_get(crl_t *crl, uint64_t index) {

  const crl_handle_t *ch;

  if(!crl) {
    LOG_EINVAL(&logger, __FILE__, "crl_get", __LINE__, LOGERROR);
    return NULL;
  }

  /* Get the CRL handles from the code */
  if(!(ch = crl_handle_from_code(crl->scheme))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "crl_get", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return NULL;
  }

  return ch->crl_get(crl, index);
    
}

crl_t* crl_import(uint8_t code, crl_format_t format, void *source) {

  const crl_handle_t *ch;

  if(!source) {
    LOG_EINVAL(&logger, __FILE__, "crl_import", __LINE__, LOGERROR);
    return NULL;
  }

  /* Get the CRL handles from the code */
  if(!(ch = crl_handle_from_code(code))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "crl_export", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return NULL;
  }

  return ch->crl_import(format, source);

}

int crl_export(crl_t *crl, void *dst, crl_format_t format) {

  const crl_handle_t *ch;

  if(!crl || !dst) {
    LOG_EINVAL(&logger, __FILE__, "crl_export", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the CRL handles from the code */
  if(!(ch = crl_handle_from_code(crl->scheme))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "crl_export", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return IERROR;
  }

  return ch->crl_export(crl, dst, format);

}

/* void* crl_entry_init(crl_t *crl) { */

/*   const crl_handle_t *ch; */

/*   if(!crl) { */
/*     LOG_EINVAL(&logger, __FILE__, "crl_compare_entries", __LINE__, LOGERROR); */
/*     return NULL; */
/*   } */

/*   return ch->crl_entry_init(); */

/* } */

int crl_compare_entries(int *eq, void *entry1, void *entry2, crl_cmp_entries_f cmp) {

  if(!eq || !entry1 || !entry2) {
    LOG_EINVAL(&logger, __FILE__, "crl_compare_entries", __LINE__, LOGERROR);
    return IERROR;
  }

  errno = 0;
  *eq = cmp(entry1, entry2);
  if(errno) {
    LOG_ERRORCODE(&logger, __FILE__, "crl_compare_entries (cmp)", __LINE__, 
		  errno, LOGERROR);
    return IERROR;
  }

  return IOK;

}

int crl_entry_exists(crl_t *crl, void *entry) {

  const crl_handle_t *ch;

  if(!crl || !entry) {
    LOG_EINVAL(&logger, __FILE__, "crl_entry_exists", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the CRL handles from the code */
  if(!(ch = crl_handle_from_code(crl->scheme))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "crl_export", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return IERROR;
  }

  return ch->crl_entry_exists(crl, entry);  

}

int crl_trapdoor_exists(crl_t *crl, trapdoor_t *trap) {

  const crl_handle_t *ch;

  if(!crl || !trap) {
    LOG_EINVAL(&logger, __FILE__, "crl_entry_exists", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the CRL handles from the code */
  if(!(ch = crl_handle_from_code(crl->scheme))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "crl_export", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return IERROR;
  }

  return ch->crl_trapdoor_exists(crl, trap);  

}


/* crl_t* crl_init() { */

/*   crl_t *crl; */

/*   if(!(crl = (crl_t *) malloc(sizeof(crl_t)))) { */
/*     LOG_ERRORCODE(&logger, __FILE__, "crl_init", __LINE__, errno, LOGERROR); */
/*     return NULL; */
/*   } */

/*   crl->entries = NULL; */
/*   crl->n = 0; */

/*   return crl; */

/* } */

/* int crl_free(crl_t *crl) { */

/*   if(!crl) { */
/*     LOG_EINVAL_MSG(&logger, __FILE__, "crl_free", __LINE__, "Nothing to free.", */
/* 		   LOGWARN); */
/*     return IOK; */
/*   } */

/*   free(crl->entries); */

/*   return IOK; */

/* } */

/* int crl_insert(crl_t *crl, void *entry) { */

/*   if(!crl || !entry) { */
/*     LOG_EINVAL(&logger, __FILE__, "crl_insert", __LINE__, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   if(!(crl->entries = (void **) realloc(crl->entries, sizeof(void *)*(crl->n+1)))) { */
/*     LOG_ERRORCODE(&logger, __FILE__, "crl_insert", __LINE__, errno, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   crl->entries[crl->n] = entry; */
/*   crl->n++; */

/*   return IOK; */

/* } */

/* int crl_remove(crl_t *crl, uint64_t index) { */

/*   /\** @todo This function is highly inefficient! *\/ */
/*   /\* Perhaps a quick solution, without changing the ADT could be to add a */
/*      "empty entries" array, and just set to NULL any removed entry. When  */
/*      a new entry is added, if there are empty entries, add it into one of */
/*      them, otherwise, increment the size of the array (but a compact function */
/*      executed periodically would be necessary then...) .*\/ */

/*   if(!crl) { */
/*     LOG_EINVAL(&logger, __FILE__, "crl_remove", __LINE__, LOGERROR); */
/*     return IERROR; */
/*   } */
  
/*   if(index >= crl->n) { */
/*     LOG_EINVAL_MSG(&logger, __FILE__, "crl_remove", __LINE__, "Invalid index.", */
/* 		   LOGERROR); */
/*     return IERROR; */
/*   } */

/*   /\* If it is not the last entry, move all the posterior entries one place *\/ */
/*   if(crl->n - index - 1) { */
/*     memmove(&crl->entries[index], &crl->entries[index+1], sizeof(void*)*(crl->n - index - 1)); */
/*   } else { /\* If is the last entry, just set it to NULL *\/ */
/*     crl->entries[index] = NULL; */
/*   } */
  
/*   /\* Decrement the number of entries *\/ */
/*   crl->n--; */

/*   return IOK; */

/* } */

/* void* crl_get(crl_t *crl, uint64_t index) { */

/*   if(!crl) { */
/*     LOG_EINVAL(&logger, __FILE__, "crl_get", __LINE__, LOGERROR); */
/*     return NULL; */
/*   } */
  
/*   if(index >= crl->n) { */
/*     LOG_EINVAL_MSG(&logger, __FILE__, "crl_get", __LINE__, "Invalid index.", */
/* 		   LOGERROR); */
/*     return NULL; */
/*   } */

/*   return crl->entries[index]; */
  
/* } */

/* int crl_compare_entries(int *eq, void *entry1, void *entry2, crl_cmp_entries_f cmp) { */

/*   if(!eq || !entry1 || !entry2) { */
/*     LOG_EINVAL(&logger, __FILE__, "crl_compare_entries", __LINE__, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   errno = 0; */
/*   *eq = cmp(entry1, entry2); */
/*   if(errno) { */
/*     LOG_ERRORCODE(&logger, __FILE__, "crl_compare_entries (cmp)", __LINE__,  */
/* 		  errno, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   return IOK; */

/* } */


/* crl.c ends here */
