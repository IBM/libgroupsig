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

#ifndef _GS_OPTIONS_H
#define _GS_OPTIONS_H

#include <stdint.h>
#include <unistd.h>

#include "include/groupsig.h"
#include "include/types.h"

#define OPTIONS_ERROR(fd, op, v)			\
  fprintf(fd, "Error: invalid option %s %s\n", op, v);	\
  errno = EINVAL;

#define OPTIONS_ERROR_LOG_OPT(fd, op, v, l, f, c, li, e, p)	\
  fprintf(fd, "Error: invalid option %s %s\n", op, v);		\
  LOG_ERRORCODE(l, f, c, li, e, p);

#define OPTIONS_ERROR_LOG_MSG(fd, s, l, f, c, li, e, p)			\
  fprintf(fd, "Error: %s\n", s);					\
  LOG_ERRORCODE_MSG(l, f, c, li, e, s, p);

#define OPT_STRING "h::g:M:m:s:S:p:G:c:k:P:e:v:l:L:d:i:"

extern char *optarg;
extern int optind, opterr, optopt;

/**
 * @struct gs_options_t
 * @brief Stores the parsed input options for the main program
 *  
 * Since this is a test program, the config parameters are "hard coded" for
 * KTY04. To include support for new schemes into this tool, a more advanced
 * [command] interface should be implemented.
 */
typedef struct {
  uint8_t help; /**< Help menu requested indicator. */
  const groupsig_t *gs; /**< Code for the group signature scheme. */
  uint8_t action; /**< Specifies the action to perform. */
  groupsig_key_t *grpkey; /**< Specifies where to read or write the group key. */ 
  char *grpkey_name;
  groupsig_key_t *mgrkey; /**< Specifies where to read or write the manager key. */
  char *mgrkey_name;
  groupsig_key_t *memkey; /**< Specifies where to read or write the member key. */
  char *memkey_name;
  groupsig_signature_t *signature; /**< Specifies where to read or write the signature. */
  char *signature_name;
  groupsig_signature_t **signatures; /**< Specifies where to read or write the signatures,
		       when more than one signature is required. */
  uint16_t n_sigs; /**< Set to the number of signatures in the previous 
		      array. */
  groupsig_proof_t *proof; /**< Specifies where to read or write the proof. */
  char *proof_name;
  gml_t *gml; /**< Specifies where to read or write the GML. */
  char *gml_name;
  crl_t *crl; /**< Specifies where to read or write the CRL. */
  char *crl_name;
  groupsig_config_t *config; /**< Configuration options for setups. */
  uint64_t security; /**< Security parameter (KTY04). */
  uint64_t primesize; /**< Prime size for generation (KTY04) . */
  double epsilon; /**< Epsilon parameter (KTY04). */  
  uint64_t index; /**< Index (from KTY04 GMLs). */
  message_t *msg; /**< A I/O message to sign/verify.... */
  char *msg_name; 
  trapdoor_t *trap;
  identity_t *id;
  uint8_t verbosity; /**< Verbosity level. */
  uint8_t log_level; /**< Controls which messages will be logged. */
  char *log; /**< Determines the log file to use. */
  char *dir; /** delete when changed to PF_INET model */
} gs_options_t;

/**
 * @fn int gs_options_parse(int argc, char *argv[], gs_options_t *opt)
 * @brief Parses the command line parameters
 *
 * Parses the command line parameters, returning ERROR when the
 * parameters are not valid and OK when they are. If an
 * unexpected error occurs, errno will be consequently updated.
 *
 * @param[out] opt Configuration parameters structure initialized to the 
 * @param[in] argc Number of arguments in argv
 * @param[in] argv Parameters
 *  read values
 *
 * @return IOK when the parameters are valid, IERROR when they are not. If an 
 *  unexpected error occurs, errno will be consequently updated.
 */
int gs_options_parse(int argc, char *argv[], gs_options_t *opt);

/** 
 * @fn int gs_options_free(gs_options_t *opt)
 * Frees the memory allocated for the options.
 * 
 * @param opt The options structure
 * 
 * @return IOK or IERROR
 */
int gs_options_free(gs_options_t *opt);

#endif /* _GS_OPTIONS_H */

/* gs_options.h ends here */
