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
#include <stdarg.h>
#include <time.h>
#include <stdlib.h>

#include "logger.h"
#include "types.h" 

int log_init(char *filename, uint8_t mode, uint8_t verbosity, log_t *log) {

  struct tm *st;
  time_t t;

  if(!filename || !log) {
    return IERROR;
  }

  log->verbosity = verbosity;
  log->filename = filename;

  if(!(log->fd = fopen(log->filename, "a"))) {
    return IERROR;
  }

  if(time(&t) == (time_t) -1) {
    fclose(log->fd);
    return IERROR;
  }

  if(!(st = localtime(&t))) {
    fclose(log->fd);
    return IERROR;
  }

  fprintf(log->fd, "Beginning log at %04d/%02d/%02d %02d:%02d:%02d\n", st->tm_year+1900, 
	  st->tm_mon+1, st->tm_mday, st->tm_hour, st->tm_min, st->tm_sec);
  
  if(mode < LOGDEBUG || mode > LOGERROR) {
    log->mode = LOGERROR;
  } else {
    log->mode = mode;
  }
  fflush(log->fd);
  log->initialized = 1;

  return IOK;

}

int log_free(log_t *log) {

  struct tm *st;
  time_t t;

  if(!log) {
    return IOK;
  }

  if(time(&t) == (time_t) -1) {
    fclose(log->fd);
    return IERROR;
  }

  if(!(st = localtime(&t))) {
    fclose(log->fd);
    return IERROR;
  }

  fprintf(log->fd, "Closing log at %04d/%02d/%02d %02d:%02d:%02d\n", st->tm_year+1900, 
	  st->tm_mon+1, st->tm_mday, st->tm_hour, st->tm_min, st->tm_sec);

  fclose(log->fd);

  return IOK;
}

int log_message(log_t *log, const char *filename, const char *caller, 
		const int line, const char *message, uint8_t priority) {

  /* Input parameters control */
  if(!log || !caller || !message) {
    return IERROR;
  }

  /* Check logging mode and priority */
  if(log->initialized) {

    if(priority >= log->mode) {

      if(!errno && !message) {

	if(log->mode == LOGERROR || log->mode == LOGWARN) {
	  fprintf(log->fd, "%s: Unknown error\n", caller);
	} else {
	  fprintf(log->fd, "%s: Unknown error (%s:%d)\n", caller, filename, line);
	}

      } else {

	if(log->mode == LOGERROR || log->mode == LOGWARN) {
	  fprintf(log->fd, "%s: %s\n", caller, message);
	} else {
	  fprintf(log->fd, "%s: %s (%s:%d)\n", caller, message, filename, line);
	}

      }

    }
    fflush(log->fd);
  }

  /* if(priority >= log->mode /\* && log->verbosity *\/) { */
  /*   if(!errno && !message) { */
  /*     fprintf(stderr, "Error: Unknown error\n"); */
  /*   } else { */
  /*     if(message) { */
  /* 	fprintf(stderr, "Error: %s\n", message); */
  /*     } else { */
  /* 	fprintf(stderr, "Error: %s\n", strerror(errno)); */
  /*     } */
  /*   } */
  /* } */

  return IOK;

}

int log_printargs(log_t *log, const char *caller, uint8_t priority, char *argv[],
		  int argc) {

  int i;
  
  if(!log || !caller || !argv || argc <= 0) {
    return IERROR;
  }

  if(log->initialized) {
    fprintf(log->fd, "%s: Running ", caller);
    for(i=1; i<argc; i++) {
      fprintf(log->fd, "%s ", argv[i]);
    }
    fprintf(log->fd, "\n");
    fflush(log->fd);
  }

  return IOK;

}

int log_printf(log_t *log, uint8_t priority, const char *format, ...) {

  va_list arg;
  //  int done;

  if(!log || !format) {
    return IERROR;
  }

  if(priority >= log->mode && log->initialized) {

    va_start(arg, format);
    /*done = */vfprintf(log->fd, format, arg);
    va_end(arg);
    fprintf(log->fd, "\n");
    fflush(log->fd);
    //    return done;

  }

  /* if(priority == LOGERROR && !log->stderrquiet) { */
  /*   va_start(arg, format); */
  /*   vfprintf(stderr, format, arg); */
  /*   va_end(arg); */
  /*   fprintf(stderr, "\n"); */
  /* } */


  return IOK;

}

/* logger.c ends here */
