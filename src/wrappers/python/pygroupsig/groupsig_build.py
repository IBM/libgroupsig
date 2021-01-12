# file "groupsig_build.py"

from pygroupsig.common_build import ffibuilder

#import pygroupsig.grp_key_build
#import pygroupsig.message_build
#import pygroupsig.signature_build
#import pygroupsig.blindsig_build
#import pygroupsig.identity_build

ffibuilder.cdef("""
typedef struct {
uint8_t code; 
char name[10];
uint8_t has_gml;
uint8_t has_crl;
uint8_t has_pbc;
} groupsig_description_t;
""")

ffibuilder.cdef("""
typedef int (*init_f)(void);
""")

ffibuilder.cdef("""
typedef int (*clear_f)(void);  
""")

ffibuilder.cdef("""
typedef int (*setup_f)(groupsig_key_t *grpkey, groupsig_key_t *mgrkey, gml_t *gml);
""")

ffibuilder.cdef("""
typedef int (*get_joinseq_f)(uint8_t *seq);
""")

ffibuilder.cdef("""
typedef int (*get_joinstart_f)(uint8_t *start);
""")

ffibuilder.cdef("""
typedef int (*join_mem_f)(message_t **mout, groupsig_key_t *memkey,
int seq, message_t *min, groupsig_key_t *grpkey);
""")

ffibuilder.cdef("""
typedef int (*join_mgr_f)(message_t **mout, gml_t *gml,
groupsig_key_t *mgrkey,
int seq, message_t *min,
groupsig_key_t *grpkey);
""")

ffibuilder.cdef("""
typedef int (*sign_f)(groupsig_signature_t *sig, message_t *msg, groupsig_key_t *memkey, 
groupsig_key_t *grpkey, unsigned int seed);
""")

ffibuilder.cdef("""
typedef int (*verify_f)(uint8_t *ok, groupsig_signature_t *sig, message_t *msg, 
groupsig_key_t *grpkey);
""")

ffibuilder.cdef("""
typedef int (*verify_batch_f)(uint8_t *ok,
groupsig_signature_t **sigs,
message_t **msgs,
uint32_t n,
groupsig_key_t *grpkey);
""")

ffibuilder.cdef("""
typedef int (*reveal_f)(
trapdoor_t *trap, 
crl_t *crl, 
gml_t *gml, 
uint64_t index);
""")

ffibuilder.cdef("""
typedef int (*open_f)(
uint64_t *index, 
groupsig_proof_t *proof, 
crl_t *crl, 
groupsig_signature_t *sig, 
groupsig_key_t *grpkey, 
groupsig_key_t *mgrkey, 
gml_t *gml);
""")

ffibuilder.cdef("""
typedef int (*open_verify_f)(
uint8_t *ok, 
groupsig_proof_t *proof, 
groupsig_signature_t *sig, 
groupsig_key_t *grpkey);
""")

ffibuilder.cdef("""
typedef int (*trace_f)(
uint8_t *ok, 
groupsig_signature_t *sig, 
groupsig_key_t *grpkey, 
crl_t *crl, 
groupsig_key_t *mgrkey, 
gml_t *gml);
""")

ffibuilder.cdef("""
typedef int (*claim_f)(
groupsig_proof_t *proof, 
groupsig_key_t *memkey, 
groupsig_key_t *grpkey, 
groupsig_signature_t *sig);
""")

ffibuilder.cdef("""
typedef int (*claim_verify_f)(
uint8_t *ok, 
groupsig_proof_t *proof, 
groupsig_signature_t *sig, 
groupsig_key_t *grpkey);
""")

ffibuilder.cdef("""
typedef int (*prove_equality_f)(
groupsig_proof_t *proof, 
groupsig_key_t *memkey, 
groupsig_key_t *grpkey, 
groupsig_signature_t **sigs, 
uint16_t n_sigs);
""")

ffibuilder.cdef("""
typedef int (*prove_equality_verify_f)(
uint8_t *ok, 
groupsig_proof_t *proof, 
groupsig_key_t *grpkey,
groupsig_signature_t **sigs, 
uint16_t n_sigs);
""")

ffibuilder.cdef("""
typedef int (*blind_f)(groupsig_blindsig_t *bsig, groupsig_key_t **bldkey,
groupsig_key_t *grpkey, groupsig_signature_t *sig,
message_t *msg);
""")

ffibuilder.cdef("""
typedef int (*convert_f)(groupsig_blindsig_t **csig,
groupsig_blindsig_t **bsig, uint32_t n_bsigs,
groupsig_key_t *grpkey, groupsig_key_t *mgrkey,
groupsig_key_t *bldkey, message_t *msg);
""")

ffibuilder.cdef("""
typedef int (*unblind_f)(
identity_t *nym,
groupsig_signature_t *sig,
groupsig_blindsig_t *bsig,
groupsig_key_t *grpkey, groupsig_key_t *bldkey,
message_t *msg);
""")

ffibuilder.cdef("""
typedef int (*identify_f)(
uint8_t *ok,
groupsig_proof_t **proof,
groupsig_key_t *grpkey,
groupsig_key_t *memkey,
groupsig_signature_t *sig,
message_t *msg);
""")

ffibuilder.cdef("""
typedef int (*link_f)(
groupsig_proof_t **proof,
groupsig_key_t *grpkey,
groupsig_key_t *memkey,
message_t *msg,
groupsig_signature_t **sigs,
message_t **msgs,
uint32_t n);
""")

ffibuilder.cdef("""
typedef int (*verify_link_f)(
uint8_t *ok,
groupsig_key_t *grpkey,
groupsig_proof_t *proof,
message_t *msg,
groupsig_signature_t **sigs,
message_t **msgs,
uint32_t n);
""")

ffibuilder.cdef("""
typedef int (*seqlink_f)(
groupsig_proof_t **proof,
groupsig_key_t *grpkey,
groupsig_key_t *memkey,
message_t *msg,
groupsig_signature_t **sigs,
message_t **msgs,
uint32_t n);
""")

ffibuilder.cdef("""
typedef int (*verify_seqlink_f)(
uint8_t *ok,
groupsig_key_t *grpkey,
groupsig_proof_t *proof,
message_t *msg,
groupsig_signature_t **sigs,
message_t **msgs,
uint32_t n);
""")

ffibuilder.cdef("""
typedef struct {
const groupsig_description_t *desc; 
init_f init; 
clear_f clear;
setup_f setup; 
get_joinseq_f get_joinseq; 
get_joinstart_f get_joinstart; 
join_mem_f join_mem;
join_mgr_f join_mgr; 
sign_f sign; 
verify_f verify;
verify_batch_f verify_batch;
open_f open;
open_verify_f open_verify;
reveal_f reveal; 
trace_f trace; 
claim_f claim; 
claim_verify_f claim_verify; 
prove_equality_f prove_equality; 
prove_equality_verify_f prove_equality_verify; 
blind_f blind; 
convert_f convert; 
unblind_f unblind; 
identify_f identify; 
link_f link; 
verify_link_f verify_link;
seqlink_f seqlink; 
verify_seqlink_f verify_seqlink;
} groupsig_t;
""")
