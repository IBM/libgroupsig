# file "klap20_build"

from pygroupsig.common_build import ffibuilder

ffibuilder.cdef("#define GROUPSIG_KLAP20_CODE 5")
#ffibuilder.cdef('#define GROUPSIG_KLAP20_NAME "KLAP20"')
ffibuilder.cdef("#define KLAP20_JOIN_START 0")
ffibuilder.cdef("#define KLAP20_JOIN_SEQ 3")

ffibuilder.cdef("""
int klap20_init();
""")

ffibuilder.cdef("""
int klap20_clear();
""")

ffibuilder.cdef("""                
int klap20_setup(
groupsig_key_t *grpkey, 
groupsig_key_t *mgrkey, 
gml_t *gml);
""")
                
ffibuilder.cdef("""
int klap20_get_joinseq(uint8_t *seq);
""")                

ffibuilder.cdef("""                
int klap20_get_joinstart(uint8_t *start);
""")
                
ffibuilder.cdef("""
int klap20_join_mem(
message_t **mout, 
groupsig_key_t *memkey,
int seq, 
message_t *min, 
groupsig_key_t *grpkey);
""")                

ffibuilder.cdef("""                
int klap20_join_mgr(
message_t **mout, 
gml_t *gml,
groupsig_key_t *mgrkey,
int seq, 
message_t *min, 
groupsig_key_t *grpkey);
""")
                
ffibuilder.cdef("""
int klap20_sign(
groupsig_signature_t *sig, 
message_t *msg, 
groupsig_key_t *memkey, 
groupsig_key_t *grpkey,
unsigned int seed);
""")                

ffibuilder.cdef("""                
int klap20_verify(
uint8_t *ok, 
groupsig_signature_t *sig, 
message_t *msg, 
groupsig_key_t *grpkey);
""")

ffibuilder.cdef("""                
int klap20_verify_batch(
uint8_t *ok, 
groupsig_signature_t **sigs, 
message_t **msgs, 
uint32_t n,
groupsig_key_t *grpkey);
""")

ffibuilder.cdef("""
int klap20_open(
uint64_t *index, 
groupsig_proof_t *proof,
crl_t *crl, 
groupsig_signature_t *sig, 
groupsig_key_t *grpkey, 
groupsig_key_t *mgrkey, gml_t *gml);
""")

ffibuilder.cdef("""
int klap20_open_verify(
uint8_t *ok,
groupsig_proof_t *proof, 
groupsig_signature_t *sig, 
groupsig_key_t *grpkey);
""")
