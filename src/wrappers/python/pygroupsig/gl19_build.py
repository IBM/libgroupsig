# file "gl19_build"

from pygroupsig.common_build import ffibuilder

ffibuilder.cdef("#define GROUPSIG_GL19_CODE 3")
#ffibuilder.cdef('#define GROUPSIG_GL19_NAME "GL19"')
ffibuilder.cdef("#define GL19_JOIN_START 0")
ffibuilder.cdef("#define GL19_JOIN_SEQ 3")

ffibuilder.cdef("""
int gl19_init();
""")

ffibuilder.cdef("""
int gl19_clear();
""")

ffibuilder.cdef("""                
int gl19_setup(groupsig_key_t *grpkey, groupsig_key_t *mgrkey, gml_t *gml);
""")
                
ffibuilder.cdef("""
int gl19_get_joinseq(uint8_t *seq);
""")                

ffibuilder.cdef("""                
int gl19_get_joinstart(uint8_t *start);
""")
                
ffibuilder.cdef("""
int gl19_join_mem(message_t **mout, groupsig_key_t *memkey,
		  int seq, message_t *min, groupsig_key_t *grpkey);
""")                

ffibuilder.cdef("""                
int gl19_join_mgr(message_t **mout, gml_t *gml,
		  groupsig_key_t *mgrkey,
		  int seq, message_t *min, groupsig_key_t *grpkey);
""")
                
ffibuilder.cdef("""
int gl19_sign(groupsig_signature_t *sig, message_t *msg, groupsig_key_t *memkey, 
	       groupsig_key_t *grpkey, unsigned int seed);
""")                

ffibuilder.cdef("""                
int gl19_verify(uint8_t *ok, groupsig_signature_t *sig, message_t *msg, 
		 groupsig_key_t *grpkey);
""")
                
ffibuilder.cdef("""
int gl19_blind(groupsig_blindsig_t *bsig, groupsig_key_t **bldkey,
	       groupsig_key_t *grpkey, groupsig_signature_t *sig,
	       message_t *msg);
""")                

ffibuilder.cdef("""
int gl19_convert(groupsig_blindsig_t **csig,
		 groupsig_blindsig_t **bsig, uint32_t n_bsigs,
		 groupsig_key_t *grpkey, groupsig_key_t *mgrkey,
		 groupsig_key_t *bldkey, message_t *msg);
""")
                
ffibuilder.cdef("""
int gl19_unblind(identity_t *nym, groupsig_signature_t *sig,
		 groupsig_blindsig_t *bsig,
		 groupsig_key_t *grpkey, groupsig_key_t *bldkey,
		 message_t *msg);
""")                
