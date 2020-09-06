# file "bbs04_build"

from pygroupsig.common_build import ffibuilder

ffibuilder.cdef("#define GROUPSIG_BBS04_CODE 1")
#ffibuilder.cdef('#define GROUPSIG_BBS04_NAME "BBS04"')
ffibuilder.cdef("#define BBS04_JOIN_START 0")
ffibuilder.cdef("#define BBS04_JOIN_SEQ 1")

ffibuilder.cdef("""
int bbs04_init();
""")

ffibuilder.cdef("""
int bbs04_clear();
""")

ffibuilder.cdef("""                
int bbs04_setup(
groupsig_key_t *grpkey, 
groupsig_key_t *mgrkey, 
gml_t *gml);
""")
                
ffibuilder.cdef("""
int bbs04_get_joinseq(uint8_t *seq);
""")                

ffibuilder.cdef("""                
int bbs04_get_joinstart(uint8_t *start);
""")
                
ffibuilder.cdef("""
int bbs04_join_mem(
message_t **mout, 
groupsig_key_t *memkey,
int seq, 
message_t *min, 
groupsig_key_t *grpkey);
""")                

ffibuilder.cdef("""                
int bbs04_join_mgr(
message_t **mout, 
gml_t *gml,
groupsig_key_t *mgrkey,
int seq, 
message_t *min, 
groupsig_key_t *grpkey);
""")
                
ffibuilder.cdef("""
int bbs04_sign(
groupsig_signature_t *sig, 
message_t *msg, 
groupsig_key_t *memkey, 
groupsig_key_t *grpkey,
unsigned int seed);
""")                

ffibuilder.cdef("""                
int bbs04_verify(
uint8_t *ok, 
groupsig_signature_t *sig, 
message_t *msg, 
groupsig_key_t *grpkey);
""")

ffibuilder.cdef("""
int bbs04_open(
uint64_t *index, 
groupsig_proof_t *proof,
crl_t *crl, 
groupsig_signature_t *sig, 
groupsig_key_t *grpkey, 
groupsig_key_t *mgrkey, gml_t *gml);
""")
