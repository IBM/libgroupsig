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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "misc/misc.h"
#include "sys/mem.h"
#include "kty04.h"
#include "groupsig/kty04/gml.h"
#include "groupsig/kty04/identity.h"
#include "groupsig/kty04/trapdoor.h"

/* Private functions */
static int _is_supported_format(gml_format_t format) {
  
  uint32_t i;
  
  for(i=0; i<KTY04_SUPPORTED_GML_FORMATS_N; i++) {
    if(format == KTY04_SUPPORTED_GML_FORMATS[i]) return 1;
  }
  
  return 0;
  
}

static kty04_gml_entry_t* _gml_entry_import_file(FILE *fd, gml_format_t format,
						 uint8_t *eof) {

  identity_t *id;
  kty04_gml_entry_t *entry;
  char *line, *sid, *sA, *strapdoor;
  int rc;
    
  if(!fd || !eof) {
    LOG_EINVAL(&logger, __FILE__, "_gml_entry_import_file",
 	       __LINE__, LOGERROR);
    return NULL;
  }

  entry = NULL; line = NULL; sA = NULL; strapdoor = NULL;
  rc = IOK;

  /* Read until the next '\n': this function is crafted to read entries converted
     using gml_entry_to_string, so we know lines will end that way. If that changes,
     this function should be adapted consequently. */
  line = NULL;
  if(misc_read_file_line(fd, &line) == IERROR) {
    return NULL;
  }

  /* Check if we have reached EOF */
  if(feof(fd)) {
    *eof = 1;
    if(line) { free(line); line = NULL; }
    return NULL;
  }

  /* To be on the safe side, we make isd, sA and strapdoor as long as line */
  if(!(sid = (char *) malloc(sizeof(char)*strlen(line)+1))) {
    LOG_ERRORCODE(&logger, __FILE__, "_gml_entry_import_file", __LINE__,
		  errno, LOGERROR);
    GOTOENDRC(IERROR, _gml_entry_import_file);
  }
  memset(sid, 0, strlen(line)+1);

  if(!(sA = (char *) malloc(sizeof(char)*strlen(line)+1))) {
    LOG_ERRORCODE(&logger, __FILE__, "_gml_entry_import_file", __LINE__,
		  errno, LOGERROR);
    GOTOENDRC(IERROR, _gml_entry_import_file);
  }
  memset(sA, 0, strlen(line)+1);

  if(!(strapdoor = (char *) malloc(sizeof(char)*strlen(line)+1))) {
    LOG_ERRORCODE(&logger, __FILE__, "_gml_entry_import_file", __LINE__,
		  errno, LOGERROR);
    GOTOENDRC(IERROR, _gml_entry_import_file);
  }
  memset(strapdoor, 0, strlen(line)+1);

  /* The lines have the format "<id> <A> <trapdoor>" */
  if((rc = sscanf(line, "%s\t%s\t%s", sid, sA, strapdoor)) == EOF) {
    LOG_ERRORCODE(&logger, __FILE__, "_gml_entry_import_file", __LINE__,
		  errno, LOGERROR);
    GOTOENDRC(IERROR, _gml_entry_import_file);
  }

  if(rc != 3) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "_gml_entry_import_file", __LINE__,
		      EDQUOT, "Corrupted GML file.", LOGERROR);
    GOTOENDRC(IERROR, _gml_entry_import_file);
  }

  /* Create the entry and fill it */
  if(!(entry = kty04_gml_entry_init()))
    GOTOENDRC(IERROR, _gml_entry_import_file);
  
  if(!(id = identity_from_string(GROUPSIG_KTY04_CODE, sid))) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "_gml_entry_import_file", __LINE__,
		      EDQUOT, "Corrupted GML file.", LOGERROR);
    GOTOENDRC(IERROR, _gml_entry_import_file);    
  }
  
  if(kty04_identity_copy(entry->id, id) == IERROR) {
    identity_free(id);
    GOTOENDRC(IERROR, _gml_entry_import_file);
  }

  identity_free(id); id = NULL;

  if(bigz_set_str(entry->A, sA, 10) == IERROR) {
    identity_free(entry->id);
    LOG_ERRORCODE_MSG(&logger, __FILE__, "_gml_entry_import_file", __LINE__,
		      EDQUOT, "Corrupted GML file.", LOGERROR);
    GOTOENDRC(IERROR, _gml_entry_import_file);
  }

  if(bigz_set_str(*(kty04_trapdoor_t *) entry->trapdoor->trap, 
		  strapdoor, 10) == IERROR) {
    identity_free(entry->id);
    bigz_free(entry->A);
    LOG_ERRORCODE_MSG(&logger, __FILE__, "_gml_entry_import_file", __LINE__,
		      EDQUOT, "Corrupted GML file.", LOGERROR);
    GOTOENDRC(IERROR, _gml_entry_import_file);
  }

 _gml_entry_import_file_end:

  if(line) { mem_free(line); line = NULL; }
  if(sid) { mem_free(sid); sid = NULL; }
  if(sA) { mem_free(sA); sA = NULL; }
  if(strapdoor) { free(strapdoor); strapdoor = NULL; }

  if(rc == IERROR) {
    if(entry) kty04_gml_entry_free(entry);
  }
  
  return entry;

}

static gml_t* _gml_import_file(char *filename) {

  gml_t *gml;
  kty04_gml_entry_t *entry;
  FILE *fd;
  uint8_t eof;

  if(!filename) {
    LOG_EINVAL(&logger, __FILE__, "_gml_import_file", __LINE__, LOGERROR);
    return NULL;
  }

  /* Open the file for reading... */
  if(!(fd = fopen(filename, "r") )) {
    LOG_ERRORCODE(&logger, __FILE__, "_gml_import_file", __LINE__, errno, LOGERROR);
    return NULL;
  }

  if(!(gml = kty04_gml_init())) {
    fclose(fd);
    return NULL;
  }
  
  /* Read the GML entries */
  eof = 0;
  while(!eof) {
    
    /** @todo GML entry type fixed to "string"  */
    /* Parse the next member key */

    eof = 0;

    /* We have an error if we receive NULL withouth reaching EOF */
    if(!(entry = _gml_entry_import_file(fd, GML_FILE, &eof)) && !eof) {
      gml_free(gml);
      fclose(fd);
      return NULL;
    }
    
    /* If we got one, store it in the GML structure */
    if(entry) {
      if(gml_insert(gml,entry) == IERROR) {
	gml_free(gml);
	fclose(fd);
	return NULL;
      }
    }

  }
  
  fclose(fd);

  return gml;

}

static int _gml_export_new_entry_file(kty04_gml_entry_t *entry, char *filename) {

  FILE *fd;
  char *sentry;

  if(!entry || !filename) {
    LOG_EINVAL(&logger, __FILE__, "_gml_export_new_entry_file", __LINE__, LOGERROR);
    return IERROR;
  }
  
  if(!(fd = fopen(filename, "a"))) {
    LOG_ERRORCODE(&logger, __FILE__, "_gml_export_new_entry_file", __LINE__, errno, LOGERROR);
    return IERROR;
  }
  
  if(!(sentry = kty04_gml_entry_to_string(entry))) {
    fclose(fd); fd = NULL;
    return IERROR;
  }

  fprintf(fd, "%s\n", sentry);
  free(sentry); sentry = NULL;

  fclose(fd);

  return IOK;

}

static int _gml_export_file(gml_t *gml, char *filename) {

  uint64_t i;
  FILE *fd;
  char *sentry;

  if(!gml || !filename) {
    LOG_EINVAL(&logger, __FILE__, "_gml_export_file", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(fd = fopen(filename, "w"))) {
    LOG_ERRORCODE(&logger, __FILE__, "_gml_export_file", __LINE__,
		  errno, LOGERROR);
    return IERROR;
  }

  /* Dump all the entries */
  /** @todo The entries are dumped just as "tabbed tostringed-numbers" (perhaps
      several formats should be supported)*/
  for(i=0; i<gml->n; i++) {
    if(!(sentry = kty04_gml_entry_to_string((kty04_gml_entry_t *) gml->entries[i]))) {
      fclose(fd); fd = NULL;
      return IERROR;
    }
    fprintf(fd, "%s\n", sentry);
    free(sentry); sentry = NULL;
  }

  fclose(fd); fd = NULL;

  return IOK;

}

/* Public functions */

/* entry functions  */

kty04_gml_entry_t* kty04_gml_entry_init() {
  
  kty04_gml_entry_t *entry;

  if(!(entry = (kty04_gml_entry_t *) malloc(sizeof(kty04_gml_entry_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_gml_entry_init", __LINE__,
		  errno, LOGERROR);
    return NULL;
  }

  if(!(entry->id = identity_init(GROUPSIG_KTY04_CODE))) {
    identity_free(entry->id); entry->id = NULL;
    mem_free(entry); entry = NULL;
    return NULL;
  }

  if(!(entry->trapdoor = trapdoor_init(GROUPSIG_KTY04_CODE))) {
    identity_free(entry->id); entry->id = NULL;
    mem_free(entry); entry = NULL;
    return NULL;
  }

  if(!(entry->A = bigz_init())) {
    identity_free(entry->id); entry->id = NULL;
    trapdoor_free(entry->trapdoor);
    free(entry); entry = NULL;
  }

  /* entry->id = NULL; */
  /* entry->trapdoor = NULL; */
  /* entry->A = NULL; */
  
  return entry;

}


int kty04_gml_entry_free(kty04_gml_entry_t *entry) {

  int rc;

  if(!entry) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_gml_entry_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  rc = IOK;
  
  rc += identity_free(entry->id);
  rc += trapdoor_free(entry->trapdoor);
  rc += bigz_free(entry->A);
  free(entry); entry = NULL;

  if(rc) rc = IERROR;
  
  return rc;

}

int kty04_gml_entry_cmp_As(void *entry1, void *entry2) {

  kty04_gml_entry_t *e1, *e2;

  if(!entry1 || !entry2) {
    LOG_EINVAL(&logger, __FILE__, "kty04_gml_entry_cmp_As", __LINE__, LOGERROR);
    return 0;
  }

  e1 = (kty04_gml_entry_t *) entry1;
  e2 = (kty04_gml_entry_t *) entry2;

  return bigz_cmp(e1->A, e2->A);

}

int kty04_gml_entry_cmp_trapdoors(void *entry1, void *entry2) {

  kty04_gml_entry_t *e1, *e2;

  if(!entry1 || !entry2) {
    LOG_EINVAL(&logger, __FILE__, "kty04_gml_entry_cmp_trapdoors", __LINE__, LOGERROR);
    return 0;
  }

  e1 = (kty04_gml_entry_t *) entry1;
  e2 = (kty04_gml_entry_t *) entry2;

  return bigz_cmp(*(kty04_trapdoor_t *) e1->trapdoor->trap, *(kty04_trapdoor_t *) e2->trapdoor->trap);

}

char* kty04_gml_entry_to_string(kty04_gml_entry_t *entry) {

  char *strapdoor, *sA, *sid, *sentry;
  uint64_t sentry_len;

  if(!entry) {
    LOG_EINVAL(&logger, __FILE__, "kty04_gml_entry_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  /* A string representation of a GML entry will be: 
     <id>\t<A>\t<trapdoor> */

  /* Get the string representations of the entry's fields */
  if(!(sid = identity_to_string(entry->id))) {
    return NULL;
  }

  if(!(sA = bigz_get_str(10, entry->A))) {
    mem_free(sid); sid = NULL;
    return NULL;
  }

  if(!(strapdoor = bigz_get_str(10, *(kty04_trapdoor_t *) entry->trapdoor->trap))) {
    mem_free(sid); sid = NULL;
    mem_free(sA); sA = NULL;
    return NULL;
  }

  /* Calculate the length of the entry, adding a tab and a \n */
  sentry_len = strlen(sid)+strlen(sA)+strlen(strapdoor)+strlen("\t\t");

  if(!(sentry = (char *) malloc(sizeof(char)*sentry_len+1))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_gml_entry_to_string", __LINE__, errno,
		  LOGERROR);
    free(strapdoor); strapdoor = NULL;
    mem_free(sid); sid = NULL;
    free(sA); sA = NULL;
    return NULL;
  }

  memset(sentry, 0, sentry_len*sizeof(char));
  sprintf(sentry, "%s\t%s\t%s", sid, sA, strapdoor);

  mem_free(sid);
  mem_free(sA);
  mem_free(strapdoor);

  return sentry;
 
}

/* list functions */

gml_t* kty04_gml_init() {

  gml_t *gml;

  if(!(gml = (gml_t *) malloc(sizeof(gml_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_gml_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  gml->scheme = GROUPSIG_KTY04_CODE;
  gml->entries = NULL;
  gml->n = 0;

  return gml;

}

int kty04_gml_free(gml_t *gml) {

  uint64_t i;

  if(!gml || gml->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_gml_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  for(i=0; i<gml->n; i++) {
    kty04_gml_entry_free(gml->entries[i]);
  }

  mem_free(gml->entries); gml->entries = NULL;
  mem_free(gml);

  return IOK;

}

int kty04_gml_insert(gml_t *gml, void *entry) {

  if(!gml || gml->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_gml_insert", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(gml->entries = (void **) 
       realloc(gml->entries, sizeof(kty04_gml_entry_t *)*(gml->n+1)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_gml_insert", __LINE__, errno, LOGERROR);
    return IERROR;
  }

  gml->entries[gml->n] = entry;
  gml->n++;

  return IOK;

}

int kty04_gml_remove(gml_t *gml, uint64_t index) {

  if(!gml || gml->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_gml_remove", __LINE__, LOGERROR);
    return IERROR;
  }

  if(index >= gml->n) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_gml_remove", __LINE__, "Invalid index.",
  		   LOGERROR);
    return IERROR;
  }

  /* Just set it to NULL */
  /** @todo This will generate a lot of unused memory! Use some other ADT */
  gml->entries[index] = NULL;
  
  /* Decrement the number of entries */
  gml->n--;

  return IOK;

}

void* kty04_gml_get(gml_t *gml, uint64_t index) {

  if(!gml || gml->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_gml_get", __LINE__, LOGERROR);
    return NULL;
  }

  if(index >= gml->n) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_gml_get", __LINE__, "Invalid index.",
  		   LOGERROR);
    return NULL;
  }

  return gml->entries[index];
  
}

gml_t* kty04_gml_import(gml_format_t format, void *src) {

  if(!src) {
    LOG_EINVAL(&logger, __FILE__, "kty04_gml_import", __LINE__, LOGERROR);
    return NULL;
  }

  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_gml_import", __LINE__,
		   "Unsupported GML type.", LOGERROR);
    return NULL;
  }

  /* If the received source is empty, means that we have to
     return an empty (new) GML */

  switch(format) {
  case GML_FILE:
    return _gml_import_file((char *) src);
  default:
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_gml_import", __LINE__,
		   "Unsupported GML format.", LOGERROR);
    return NULL;
  }

  return NULL;
 
}

int kty04_gml_export(gml_t *gml, void *dst, gml_format_t format) {

  if(!gml || gml->scheme != GROUPSIG_KTY04_CODE || 
     !dst) {
    LOG_EINVAL(&logger, __FILE__, "kty04_gml_export", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_gml_export", __LINE__,
		   "Unsupported GML format.", LOGERROR);
    return IERROR;
  }

  switch(format) {
  case GML_FILE:
    return _gml_export_file(gml, (char *) dst);
  default:
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_gml_export", __LINE__,
		   "Unsupported GML format.", LOGERROR);
    return IERROR;
  }

  return IERROR;

}

int kty04_gml_export_new_entry(void *entry, void *dst, gml_format_t format) {

  if(!entry || !dst) {
    LOG_EINVAL(&logger, __FILE__, "kty04_gml_export_new_entry", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_gml_export_new_entry", __LINE__,
		   "Unsupported GML format.", LOGERROR);
    return IERROR;
  }

  switch(format) {
  case GML_FILE:
    return _gml_export_new_entry_file(entry, (char *) dst);
  default:
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_gml_export_new_entry", __LINE__,
		   "Unsupported GML format.", LOGERROR);
    return IERROR;
  }

  return IERROR;  

}

/* int _gml_append_entry_export_file(kty04_gml_entry_t *entry, char *filename) { */

/*   FILE *fd; */
/*   char *sentry; */

/*   if(!entry || !filename) { */
/*     LOG_EINVAL(&logger, __FILE__, "_gml_append_entry_export_file", __LINE__, LOGERROR); */
/*     return IERROR; */
/*   } */
  
/*   if(!(fd = fopen(filename, "a"))) { */
/*     LOG_ERRORCODE(&logger, __FILE__, "_gml_append_entry_export_file", __LINE__, errno, LOGERROR); */
/*     return IERROR; */
/*   } */
  
/*   if(!(sentry = _gml_entry_to_string(entry))) { */
/*     fclose(fd); fd = NULL; */
/*     return IERROR; */
/*   } */

/*   fprintf(fd, "%s\n", sentry); */
/*   free(sentry); sentry = NULL; */

/*   fclose(fd); */

/*   return IOK; */

/* } */

/* int gml_append_entry_export(kty04_gml_entry_t *entry, gml_type_t type, void *dst) { */

/*   if(!entry || !dst) { */
/*     LOG_EINVAL(&logger, __FILE__, "gml_append_entry_export", __LINE__, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   if(!_is_supported_type(type)) { */
/*     LOG_EINVAL_MSG(&logger, __FILE__, "gml_append_entry_export", __LINE__, */
/* 		   "Unsupported GML format.", LOGERROR); */
/*     return IERROR; */
/*   } */

/*   switch(type) { */
/*   case GML_FILE: */
/*     return _gml_append_entry_export_file(entry, (char *) dst); */
/*   default: */
/*     LOG_EINVAL_MSG(&logger, __FILE__, "gml_append_entry_export", __LINE__, */
/* 		   "Unsupported GML format.", LOGERROR); */
/*     return IERROR; */
/*   } */

/*   return IERROR; */

/* } */

/* /\**  */
/*  * @fn static int _gml_check_empty_file(char * filename) */
/*  * @brief Returns 1 if the given filename does not exist or is empty and */
/*  *  0 otherwise. If an error occurs, errno is updated consequently. */
/*  *  */
/*  * @param[in] filename The name of the file to explore. */
/*  *  */
/*  * @return 1 if the file is empty or does not exist, 0 if not, with errno  */
/*  *  updated as needed. */
/*  *\/ */
/* static int _gml_check_empty_file(char * filename) { */
  
/*   struct stat buf; */
/*   int fd; */

/*   if(!filename) { */
/*     LOG_EINVAL(&logger, __FILE__, "_gml_check_empty_file", __LINE__, LOGERROR); */
/*     return 1; */
/*   } */

/*   /\* The file exists *\/ */
/*   if(access(filename, F_OK) != -1) { */

/*     /\* Open the file *\/ */
/*     if((fd = open(filename, O_RDONLY)) == -1) { */
/*       LOG_ERRORCODE(&logger, __FILE__, "_gml_check_empty_file", __LINE__,  */
/* 		    errno, LOGERROR); */
/*       return 1; */
/*     }     */

/*     /\* Get the size of the file *\/ */
/*     if(fstat(fd, &buf) == -1) { */
/*       LOG_ERRORCODE(&logger, __FILE__, "_gml_check_empty_file", __LINE__,  */
/* 		    errno, LOGERROR); */
/*       close(fd); */
/*       return 1; */
/*     } */

/*     close(fd); */

/*     /\* If the size is 0, it is empty *\/ */
/*     if(!buf.st_size) { */
/*       return 1; */
/*     } */

/*     return 0; */
    
/*   } else { */
/*     return 1; */
/*   } */

/*   LOG_ERRORCODE_MSG(&logger, __FILE__, "_gml_check_empty_file", __LINE__, EDQUOT, */
/* 		    "Unexpected execution flow.", LOGERROR);		     */
/*   return 1; */

/* } */

/* kty04_gml.c ends here */
