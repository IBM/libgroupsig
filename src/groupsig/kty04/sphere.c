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
#include <string.h>

#include "sphere.h"
#include "math/nt.h"

sphere_t* sphere_init() {
  
  sphere_t *sp;
  
  if(!(sp = (sphere_t *) malloc(sizeof(sphere_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "sphere_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  if(!(sp->center = bigz_init())) {
    free(sp); sp = NULL;
    return NULL;
  }

  if(!(sp->radius = bigz_init())) {
    free(sp->center); sp->center = NULL;
    free(sp); sp = NULL;
    return NULL;
  }
  
  return sp;

}

int sphere_free(sphere_t *sp) {

  int rc;

  if(!sp) {
    LOG_EINVAL(&logger, __FILE__, "sphere_free", __LINE__, LOGWARN);
    return IERROR;
  }
  
  rc = bigz_free(sp->center);
  rc += bigz_free(sp->radius);
  free(sp); sp = NULL;

  if(rc) return IERROR;
  
  return IOK;

}

int sphere_get_min(sphere_t *sp, bigz_t min) {

  bigz_t _min;

  if(!sp || !min) {
    LOG_EINVAL(&logger, __FILE__, "sphere_get_min", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(_min = bigz_init())) return IERROR;

  if(bigz_sub(_min, sp->center, sp->radius) == IERROR) {
    bigz_free(_min);
    return IERROR;
  }

  if(bigz_add_ui(_min, _min, 1) == IERROR) {
    bigz_free(_min);
    return IERROR;
  }

  if(bigz_set(min, _min) == IERROR) {
    bigz_free(_min);
    return IERROR;
  }
  
  bigz_free(_min);

  return IOK;

}

int sphere_get_max(sphere_t *sp, bigz_t max) {

  bigz_t _max;

  if(!sp) {
    LOG_EINVAL(&logger, __FILE__, "sphere_get_max", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(_max = bigz_init())) {
    return IERROR;
  }

  if(bigz_add(_max, sp->center, sp->radius) == IERROR) {
    bigz_free(_max);
    return IERROR;
  }

  if(bigz_sub_ui(_max, _max, 1) == IERROR) {
    bigz_free(_max);
    return IERROR;
  }

  if(bigz_set(max, _max) == IERROR) {
    bigz_free(_max);
    return IERROR;
  }

  bigz_free(_max);

  return IOK;

}

int sphere_get_inner(sphere_t *sp, uint64_t epsilon, uint64_t k, sphere_t *inner) {

  uint64_t u;

  if(!sp || !inner) {
    LOG_EINVAL(&logger, __FILE__, "sphere_get_inner", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Given the sphere S(2^l, 2^u), its inner sphere is defined as
     S(2^l, 2^((u-2)/epsilon - k) */

  /* Get u from 2^u */
  errno = 0;
  u = bigz_sizeinbase(sp->radius, 2)-1;
  if(errno) {
    return IERROR;
  }
  
  /** @todo What happens if u-2 is not divisible by epsilon? */
  u -= 2;
  u /= epsilon;
  u -= k;

  /* Set the radius and the center of the inner sphere and exit */
  if(bigz_ui_pow_ui(inner->radius, 2, u) == IERROR) return IERROR;
  if(bigz_set(inner->center, sp->center) == IERROR) return IERROR;

  return IOK;

}

int sphere_get_random(sphere_t *sp, bigz_t r) {

  bigz_t upper, _r;

  if(!sp || !r) {
    LOG_EINVAL(&logger, __FILE__, "sphere_get_random", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(_r = bigz_init())) {
    return IERROR;
  }

  if(!(upper = bigz_init_set(sp->radius))) {
    bigz_free(_r);
    return IERROR;
  }

  if(bigz_mul_ui(upper, upper, 2) == IERROR) {
    bigz_free(_r); bigz_free(upper);
    return IERROR;
  }

  if(bigz_sub_ui(upper, upper, 2) == IERROR) {
    bigz_free(_r); bigz_free(upper);
    return IERROR;
  }

  /* This sets _r to a random number in [0, 2*sp->radius-2] */
  if(bigz_urandomm(_r, sysenv->big_rand, upper) == IERROR) {
    bigz_free(_r); bigz_free(upper);
    return IERROR;
  }

  bigz_free(upper);

  /* Now add (sp->center-sp->radius+1) to _r to get a random number in 
     [sp->center-radius+1, sp->center+radius-1] */
  if(bigz_add(_r, _r, sp->center) == IERROR) {
    bigz_free(_r);
    return IERROR;
  }
  
  if(bigz_sub(_r, _r, sp->radius) == IERROR) {
    bigz_free(_r);
    return IERROR;    
  }

  if(bigz_add_ui(_r, _r, 1) == IERROR) {
    bigz_free(_r);
    return IERROR;
  }

  if(bigz_set(r, _r) == IERROR) {
    bigz_free(_r);
    return IERROR;
  }
  
  bigz_free(_r);

  return IOK;

}

int sphere_get_random_prime(sphere_t *sp, bigz_t p) {

  bigz_t lower, upper, r;

  if(!sp || !p) {
    LOG_EINVAL(&logger, __FILE__, "sphere_get_random_prime", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the lower and upper limits of the sphere */
  if(!(lower = bigz_init_set(sp->center))) return IERROR;

  if(bigz_sub(lower, lower, sp->radius) == IERROR) {
    bigz_free(lower);
    return IERROR;
  }

  if(bigz_add_ui(lower, lower, 1) == IERROR) {
    bigz_free(lower);
    return IERROR;
  }

  if(!(upper = bigz_init_set(sp->center))) {
    bigz_free(lower);
    return IERROR;
  }
  
  if(bigz_add(upper, upper, sp->radius) == IERROR) {
    bigz_free(lower); bigz_free(upper);
    return IERROR;
  }

  if(bigz_sub_ui(upper, upper, 1) == IERROR) {
    bigz_free(lower); bigz_free(upper);
    return IERROR;
  }

  /* Get a random prime in that interval */
  if(!(r = bigz_init())) {
    bigz_free(lower); bigz_free(upper);
    return IERROR;
  }
   
  if(nt_genprime_random_interval(lower, upper, r) == IERROR) {
    bigz_free(lower); bigz_free(upper);
    bigz_free(r);
    return IERROR;
  }

  if(bigz_set(p, r) == IERROR) {
    bigz_free(lower); bigz_free(upper);
    bigz_free(r);
    return IERROR;   
  }

  bigz_free(lower);
  bigz_free(upper);
  bigz_free(r);

  return IOK;

}

int sphere_get_product_spheres(sphere_t *sp1, sphere_t *sp2, sphere_t *sp) {

  bigz_t min, max, sp1_aux, sp2_aux, center, radius;
  int rc;

  if(!sp1 || !sp2 || !sp) {
    LOG_EINVAL(&logger, __FILE__, "sphere_get_product_spheres", __LINE__,
	       LOGERROR);
    return IERROR;
  }
  
  min=NULL; max=NULL, sp1_aux=NULL; sp2_aux=NULL; center=NULL; radius=NULL;
  rc = IOK;

  /** @todo Right now, this function only supports product of spheres with all 
      their elements >= 0. */

  /* min = sp1->min*sp2->min */
  if(!(sp1_aux = bigz_init())) return IERROR;

  if(sphere_get_min(sp1, sp1_aux) == IERROR) { 
    rc = IERROR; 
    goto get_product_spheres_error; 
  }

  if(!(sp2_aux = bigz_init()))  { 
    rc = IERROR; 
    goto get_product_spheres_error; 
  }

  if(sphere_get_min(sp2, sp2_aux) == IERROR) { 
    rc = IERROR; 
    goto get_product_spheres_error; 
  }

  if(!(min = bigz_init())) { 
    rc = IERROR; 
    goto get_product_spheres_error;
  }

  if(bigz_mul(min, sp1_aux, sp2_aux) == IERROR) { 
    rc = IERROR; 
    goto get_product_spheres_error; 
  }

  /* max = sp1->max*sp2->max */
  if(sphere_get_max(sp1, sp1_aux) == IERROR) { 
    rc = IERROR; 
    goto get_product_spheres_error; 
  }
  
  if(sphere_get_max(sp2, sp2_aux) == IERROR) { 
    rc = IERROR; 
    goto get_product_spheres_error; 
  }
  
  if(!(max = bigz_init())) { 
    rc = IERROR; 
    goto get_product_spheres_error; 
  }
  
  if(bigz_mul(max, sp1_aux, sp2_aux) == IERROR) { 
    rc = IERROR; 
    goto get_product_spheres_error; 
  }

  /* center = min+max/2 */
  if(bigz_add(sp1_aux, min, max) == IERROR) { 
    rc = IERROR; 
    goto get_product_spheres_error; 
  }

  if(!(center = bigz_init())) { 
    rc = IERROR; 
    goto get_product_spheres_error; 
  }

  if(bigz_tdiv_ui(center, NULL, sp1_aux, 2) == IERROR) { 
    rc = IERROR; 
    goto get_product_spheres_error; 
  }

  /* radius = max-min/2 */
  if(bigz_sub(sp1_aux, max, min) == IERROR) { 
    rc = IERROR; 
    goto get_product_spheres_error; 
  }

  if(!(radius = bigz_init())) { 
    rc = IERROR; 
    goto get_product_spheres_error; 
  }

  if(bigz_tdiv_ui(radius, NULL, sp1_aux, 2)) { 
    rc = IERROR; 
    goto get_product_spheres_error; 
  }

  /* Now, get the greatest power of two less than radius */
  if(nt_get_greatest_power2_smaller_n(radius, radius) == IERROR) {
    rc = IERROR;
    goto get_product_spheres_error;
  }

  if(bigz_set(sp->center, center) == IERROR) { 
    goto get_product_spheres_error; 
    rc = IERROR; 
  }

  if(bigz_set(sp->radius, radius)) rc = IERROR;

 get_product_spheres_error:
  
  if(sp1_aux) bigz_free(sp1_aux);
  if(sp2_aux) bigz_free(sp2_aux);
  if(min) bigz_free(min);
  if(max) bigz_free(max);
  if(center) bigz_free(center);
  if(radius) bigz_free(radius);

  return rc;

}

char* sphere_to_string(sphere_t *sp) { // was int sphere_fprintf(FILE *fd, sphere_t *sp) {

  char *scenter, *sradius, *ssphere;
  uint32_t length;

  if(!sp) {
    LOG_EINVAL(&logger, __FILE__, "sphere_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  if(!(scenter = bigz_get_str(10, sp->center))) return NULL;
  if(!(sradius = bigz_get_str(10, sp->radius))) {
    free(scenter); scenter = NULL;
    return NULL;
  }
  
  length = strlen(scenter)+strlen("center: \n")+
    strlen(sradius)+strlen("radius: \n\n");

  if(!(ssphere = (char *) malloc(sizeof(char)*(length+1)))) {
    LOG_ERRORCODE(&logger, __FILE__, "sphere_to_string", __LINE__, errno, LOGERROR);
    free(scenter); scenter = NULL;
    return NULL;
  }
  memset(ssphere, 0, length+1);

  sprintf(ssphere, 
	  "center: %s\n"
	  "radius: %s\n\n", 
	  scenter, sradius);
  
  free(scenter); scenter = NULL;
  free(sradius); sradius = NULL;

  return ssphere;

}

/* int sphere_fprintf_b64(FILE *fd, sphere_t *sp) { */

/*   gnutls_datum_t datum, *b64=NULL; */
/*   byte_t *bcenter=NULL, *bradius=NULL, *bsphere=NULL; */
/*   size_t scenter, sradius, ssphere, offset; */
/*   uint32_t i; */
/*   int rc; */

/*   if(!sp) { */
/*     fprintf(stderr, "Error in sphere_fprintf_b64 (%d): %s\n", */
/* 	    __LINE__, strerror(EINVAL)); */
/*     errno = EINVAL; */
/*     return IERROR;    */
/*   } */

/*   rc = IOK; */
  
/*   /\* Export the variables to binary data *\/ */
/*   if(!(bcenter = bigz_export(NULL, &scenter, 1, 1, 1, 0, sp->center))) { */
/*     fprintf(stderr, "Error in sphere_fprintf_b64 (%d): %s\n", */
/* 	    __LINE__, "bigz_export."); */
/*     return IERROR; */
/*   } */

/*   if(!(bradius = bigz_export(NULL, &sradius, 1, 1, 1, 0, sp->radius))) { */
/*     fprintf(stderr, "Error in sphere_fprintf_b64 (%d): %s\n", */
/* 	    __LINE__, "bigz_export."); */
/*     rc = IERROR; */
/*     goto error; */
/*   } */

/*   /\* To separate the different values, and be able to parse them later, we use */
/*      the 'syntax': "'c='<c>'r='<r>'",  */
/*      where the values between '' are printed in ASCII, and the <x> are the binary  */
/*      data obtained above. Therefore, the total length of the group key will be  */
/*      2*3+scenter+sradius. */
/*      @todo although does not seem very probable, it is possible that the binary  */
/*      data of c, r, ... contains the ASCII codes of 'Lc=', 'Lr=', etc.. This will */
/*      obviously lead to program malfunction... */
/*   *\/ */

/*   ssphere = 6+scenter+sradius; */
  
/*   /\* Copy everything into a unique array *\/ */
/*   if(!(bsphere = (byte_t *) malloc(sizeof(byte_t)*ssphere))) { */
/*     fprintf(stderr, "Error in sphere_fprintf_b64 (%d): %s\n",  */
/* 	    __LINE__, strerror(errno)); */
/*     rc = IERROR; */
/*     goto error; */
/*   } */

/*   memset(bsphere, 0, ssphere); */

/*   offset = 0; */

/*   bsphere[0] = 'c'; */
/*   bsphere[1] = '='; */
/*   memcpy(&bsphere[2], bcenter, scenter); */
/*   offset += 2+scenter; */

/*   bsphere[offset] = 'r'; */
/*   bsphere[offset+1] = '='; */
/*   memcpy(&bsphere[offset+2], bradius, sradius); */
/*   offset += 2+sradius; */

/*   /\* Convert it to a base64 string prepended with SPHERE_MSG *\/ */
/*   if(ssphere != offset) { */
/*     fprintf(stderr, "Error in sphere_fprintf_b64 (%d): %s\n", */
/* 	    __LINE__, "Conversion failure\n"); */
/*     rc = IERROR; */
/*     goto error; */
/*   } */

/*   datum.data = bsphere; */
/*   datum.size = ssphere; */

/*   if(!(b64 = (gnutls_datum_t *) malloc(sizeof(gnutls_datum_t)))) { */
/*     fprintf(stderr, "Error in sphere_fprintf_b64 (%d): %s\n",  */
/* 	    __LINE__, strerror(errno)); */
/*     rc = IERROR; */
/*     goto error; */
/*   } */

/*   if((rc = gnutls_pem_base64_encode_alloc(SPHERE_MSG, */
/* 					  &datum, */
/* 					  b64)) != GNUTLS_E_SUCCESS) { */
/*     fprintf(stderr, "Error in sphere_fprintf_b64 (%d): %s\n",  */
/* 	    __LINE__, gnutls_strerror(rc)); */
/*     rc = IERROR; */
/*     goto error;     */
/*   } */
  
/*   /\* We have the associated base64 string in cs97_b64. Print it and we are done. *\/ */
/*   fprintf(fd, "%s", b64->data); */

/*   gnutls_free(b64); */

/*  error: */

/*   if(bcenter) { free(bcenter); bcenter = NULL; } */
/*   if(bradius) { free(bradius); bradius = NULL; } */
/*   if(bsphere) { free(bsphere); bsphere = NULL; } */

/*   return rc; */
  
/* } */

/* sphere.c ends here */
