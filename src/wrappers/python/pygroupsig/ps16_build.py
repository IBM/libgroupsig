# file "ps16_build"

from pygroupsig.common_build import ffibuilder

ffibuilder.cdef("#define GROUPSIG_PS16_CODE 4")
#ffibuilder.cdef('#define GROUPSIG_PS16_NAME "PS16"')
ffibuilder.cdef("#define PS16_JOIN_START 0")
ffibuilder.cdef("#define PS16_JOIN_SEQ 3")

ffibuilder.cdef("""
int ps16_init();
""")

ffibuilder.cdef("""
int ps16_clear();
""")

ffibuilder.cdef("""                
int ps16_setup(
groupsig_key_t *grpkey, 
groupsig_key_t *mgrkey, 
gml_t *gml);
""")
                
ffibuilder.cdef("""
int ps16_get_joinseq(uint8_t *seq);
""")                

ffibuilder.cdef("""                
int ps16_get_joinstart(uint8_t *start);
""")
                
ffibuilder.cdef("""
int ps16_join_mem(
message_t **mout, 
groupsig_key_t *memkey,
int seq, 
message_t *min, 
groupsig_key_t *grpkey);
""")                

ffibuilder.cdef("""                
int ps16_join_mgr(
message_t **mout, 
gml_t *gml,
groupsig_key_t *mgrkey,
int seq, 
message_t *min, 
groupsig_key_t *grpkey);
""")
                
ffibuilder.cdef("""
int ps16_sign(
groupsig_signature_t *sig, 
message_t *msg, 
groupsig_key_t *memkey, 
groupsig_key_t *grpkey,
unsigned int seed);
""")                

ffibuilder.cdef("""                
int ps16_verify(
uint8_t *ok, 
groupsig_signature_t *sig, 
message_t *msg, 
groupsig_key_t *grpkey);
""")

ffibuilder.cdef("""
int ps16_open(
uint64_t *index, 
groupsig_proof_t *proof,
crl_t *crl, 
groupsig_signature_t *sig, 
groupsig_key_t *grpkey, 
groupsig_key_t *mgrkey, gml_t *gml);
""")

ffibuilder.cdef("""
int ps16_open_verify(
uint8_t *ok,
groupsig_proof_t *proof, 
groupsig_signature_t *sig, 
groupsig_key_t *grpkey);
""")
