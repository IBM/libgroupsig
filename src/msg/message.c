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
#include <stdint.h>

#include "logger.h"
#include "message.h"
#include "misc.h"
#include "shim/base64.h"
#include "sys/mem.h"

/* Static functions */

static int _is_supported_format(message_format_t format) {

  int i;

  for(i=0; i<SUPPORTED_MESSAGE_FORMATS_N; i++) {
    if(SUPPORTED_MESSAGE_FORMATS[i] == format) {
      return 1;
    }
  }

  return 0;

}

static int _message_export_null_file(message_t *msg, char *dst) {
  
  FILE *fd;
  size_t rc;

  if(!msg || !dst) {
    LOG_EINVAL(&logger, __FILE__, "_message_export_null_file", __LINE__,
               LOGERROR);
    return IERROR;
  }

  /* Dump the contents of the message into the specified file */
  if(!(fd = fopen(dst, "w"))) {
    LOG_ERRORCODE(&logger, __FILE__, "_message_export_null_file", __LINE__,
                  errno, LOGERROR);
    return IERROR;
  }

  if((rc = fwrite(msg->bytes, 1, msg->length, fd)) < msg->length) {
    LOG_ERRORCODE(&logger, __FILE__, "_message_export_null_file", __LINE__,
                  EBADF, LOGERROR);
    fclose(fd); fd = NULL;
    return IERROR;
  }

  fclose(fd); fd = NULL;

  return IOK;

}

/* static char* _message_export_string_b64(message_t *msg, char *dst) { */

/*   if(!msg) { */
/*     LOG_EINVAL(&logger, __FILE__, "_message_export_string_b64",  */
/*                __LINE__, LOGERROR); */
/*     return NULL; */
/*   } */

/*   dst = base64_encode(msg->bytes, msg->length); */

/*   return dst; */

/* } */

static int _message_import_null_file(message_t *msg, char *source) {

  if(!msg || !source) {
    LOG_EINVAL(&logger, __FILE__, "_message_import_null_file", 
               __LINE__, LOGERROR);
    return IERROR;
  }

  /* Read the file contents */
  msg->bytes = NULL;
  if(message_misc_read_file_to_bytestring(source, &msg->bytes, &msg->length) == IERROR) {
    return IERROR;
  }

  return IOK;
  
}

/* static int _message_import_string_b64(message_t *msg, char *source) { */

/*   if(!source) { */
/*     LOG_EINVAL(&logger, __FILE__, "_message_import_string_b64", __LINE__, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   if(!(msg->bytes = base64_decode(source, strlen(source), &msg->length))) { */
/*     return IERROR; */
/*   } */

/*   return IOK; */

/* } */

/* Public functions */

message_t* message_init() {
  
  message_t *msg;

  if(!(msg = (message_t *) malloc(sizeof(message_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "message_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  msg->bytes = NULL;
  msg->length = 0;

  return msg;
  
}

message_t* message_from_string(char *str) {
  
  message_t *msg;
  
  if(!str) {
    LOG_EINVAL(&logger, __FILE__, "message_from_str", __LINE__, LOGERROR);
    return NULL;
  }
  
  if(!(msg = message_init()))
    return NULL;
  
  if(message_set_bytes_from_string(msg, str) == IERROR) {
    message_free(msg); msg = NULL;
    return NULL;
  }
  
  return msg;
  
}

message_t* message_from_bytes(byte_t *bytes, uint64_t length) {
  
  message_t *msg;
  
  if(!bytes || !length) {
    LOG_EINVAL(&logger, __FILE__, "message_from_bytes", __LINE__, LOGERROR);
    return NULL;
  }

  if(!(msg = message_init()))
    return NULL;
  
  if(!(msg->bytes = (byte_t *) mem_malloc(sizeof(byte_t)*length))) {
    message_free(msg); msg = NULL;
    return NULL;
  }
 
  memcpy(msg->bytes, bytes, length);
  msg->length = length;
  
  return msg;
  
}

int message_free(message_t *msg) {
  
  if(!msg) {
    LOG_EINVAL_MSG(&logger, __FILE__, "message_free", __LINE__, 
                   "Nothing to free.", LOGWARN);
    return IERROR;
  }
    
  if(msg->bytes) { free(msg->bytes); msg->bytes = NULL; }

  free(msg); msg = NULL;
  
  return IOK;
  
}

int message_set_bytes(message_t *msg, byte_t *bytes, uint64_t length) {

  if(!msg || !bytes || !length) {
    LOG_EINVAL(&logger, __FILE__, "message_set_bytes", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(msg->bytes = (byte_t *) malloc(sizeof(byte_t)*length))) {
    LOG_ERRORCODE(&logger, __FILE__, "message_set_bytes", __LINE__, errno, LOGERROR);
    return IERROR;
  }
  
  memcpy(msg->bytes, bytes, length);
  msg->length = length;

  return IOK;

}

int message_set_bytes_from_string(message_t *msg, char *string) {

  if(!msg || !string) {
    LOG_EINVAL(&logger, __FILE__, "message_set_bytes_from_string", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(msg->bytes = (byte_t *) strdup(string))) {
    LOG_ERRORCODE(&logger, __FILE__, "message_set_bytes_from_string", __LINE__, errno, LOGERROR);
    return IERROR;
  }

  msg->length = strlen(string);

  return IOK;

}

int message_copy(message_t *dst, message_t *src) {

  if(!dst || !src) {
    LOG_EINVAL(&logger, __FILE__, "message_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(dst->bytes = (byte_t *) malloc(sizeof(byte_t*)*(src->length+1)))) {
    LOG_ERRORCODE(&logger, __FILE__, "message_copy", __LINE__, errno, LOGERROR);
    return IERROR;
  }
  memset(dst->bytes, 0, src->length+1);

  memcpy(dst->bytes, src->bytes, src->length);
  dst->length = src->length;

  return IOK;

}

char* message_to_string(message_t *msg) {

  char *smsg;
  
  if(!msg) {
    LOG_EINVAL(&logger, __FILE__, "message_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  if(!(smsg = (char *) malloc(sizeof(char)*(msg->length+1)))) {
    LOG_ERRORCODE(&logger, __FILE__, "message_to_string", __LINE__, errno,
		  LOGERROR);
    return NULL;
  }

  memset(smsg, 0, (msg->length+1)*sizeof(char));

  /* WARNING! Note that this string may not be printable! */
  memcpy(smsg, msg->bytes, msg->length);
  
  return smsg;

}

char* message_to_base64(message_t *msg) {

  if(!msg) {
    LOG_EINVAL(&logger, __FILE__, "message_to_base64", __LINE__, LOGERROR);
    return NULL;
  }

  return base64_encode(msg->bytes, msg->length);

}

message_t* message_from_base64(char *b64) {

  message_t *msg;
  byte_t *bytes;
  uint64_t len;
  
  if (!b64) {
    LOG_EINVAL(&logger, __FILE__, "message_from_base64", __LINE__, LOGERROR);
    return NULL;    
  }

  if(!(bytes = base64_decode(b64, &len))) {
    LOG_ERRORCODE(&logger, __FILE__, "message_from_base64", __LINE__, errno,
		  LOGERROR);
    return NULL;
  }

  if(!(msg = message_from_bytes(bytes, len))) {
    LOG_ERRORCODE(&logger, __FILE__, "message_from_base64", __LINE__, errno,
		  LOGERROR);
    return NULL; 
  }

  return msg;

}

int message_export(void *dst, message_format_t format, message_t *msg) {

  if(!msg) {
    LOG_EINVAL(&logger, __FILE__, "message_export", __LINE__, LOGERROR);
    return IERROR;
  }

  /* See if the given format is supported*/
  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "message_export", __LINE__,
		   "The specified format is not supported.", LOGERROR);
    return IERROR;
  }

  switch(format) {
  case MESSAGE_FORMAT_NULL_FILE: 
    return _message_export_null_file(msg, dst);
  /* case MESSAGE_FORMAT_STRING_B64: */
  /*   if(!_message_export_string_b64(msg, dst)) return IERROR; */
  /*   break; */
  default:
    LOG_EINVAL_MSG(&logger, __FILE__, "message_export", __LINE__,
		   "The specified format is not supported.", LOGERROR);
    return IERROR;
  }

  /* This should not happen */
  return IERROR;

}

int message_import(message_t* msg, message_format_t format, void *src) {

  if(!msg || !src) {
    LOG_EINVAL(&logger, __FILE__, "message_import", __LINE__, LOGERROR);
    return IERROR;
  }

  /* See if the given format is supported*/
  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "message_export", __LINE__,
		   "The specified format is not supported.", LOGERROR);
    return IERROR;
  }

  switch(format) {
  case MESSAGE_FORMAT_NULL_FILE: /* Just return the bytes */
    return _message_import_null_file(msg, src);
  /* case MESSAGE_FORMAT_STRING_B64: */
  /*   return _message_import_string_b64(msg, src); */
  default:
    LOG_EINVAL_MSG(&logger, __FILE__, "message_export", __LINE__,
		   "The specified format is not supported.", LOGERROR);
    return IERROR;
  }

  return IERROR;
  
}

/* message.c ends here */
