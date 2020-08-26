const jsgroupsig = require("../build/Release/jsgroupsig")

/** Constants defined in libgroupsig **/
/* @TODO: Is there a more portable way to do this? */

/* Supported group schemes */
//const KTY04 = 0;
const BBS04 = 1;
//const CPY06 = 2;
const GL19 = 3;
const PS16 = 4;

module.exports = {

    /** Constants **/

    /* Group codes */
    //KTY04: KTY04,
    BBS04: BBS04,
    //CPY06: CPY06,
    GL19: GL19,
    PS16: PS16,

    /** Functions **/
    
    /* Scheme functions */
    hello_world: jsgroupsig.gs_hello_world,
    is_supported_scheme: jsgroupsig.gs_is_supported_scheme,
    get_groupsig_from_str: jsgroupsig.gs_get_groupsig_from_str,
    get_groupsig_from_code: jsgroupsig.gs_get_groupsig_from_code,
    init: jsgroupsig.gs_init,
    clear: jsgroupsig.gs_clear,
    /*sysenv_update: jsgroupsig.gs_sysenv_update,
    sysenv_get: jsgroupsig.gs_sysenv_get,
    sysenv_free: jsgroupsig.gs_senv_free,*/
    get_joinseq: jsgroupsig.gs_get_joinseq,
    get_joinstart: jsgroupsig.gs_get_joinstart,
    join_mem: jsgroupsig.gs_join_mem,
    join_mgr: jsgroupsig.gs_join_mgr,
    setup: jsgroupsig.gs_setup,
    sign: jsgroupsig.gs_sign,
    verify: jsgroupsig.gs_verify,
    blind: jsgroupsig.gs_blind,
    open: function (sig, grpkey, mgrkey, gml = null, crl = null) {
	let id = null;
	let proof = null;
	let code = jsgroupsig.gs_signature_get_code(sig);
	if (jsgroupsig.gs_has_open_proof(code) == 1) {
	    proof = jsgroupsig.gs_proof_init(code);
	}
	id = jsgroupsig.gs_open(sig, grpkey, mgrkey, gml, proof);
	return { "id": id, "proof": proof }; 
    },
    open_verify: function (proof, sig, grpkey, id = null) {
	return jsgroupsig.gs_open_verify(proof, sig, grpkey, id);
    },
    convert: jsgroupsig.gs_convert,
    unblind: function (bsig, bldkey, sig = null, grpkey = null) {
	let nym = null;
	let msg = jsgroupsig.gs_message_init();
	if (!sig) {
	    nym = jsgroupsig.gs_unblind(bsig, bldkey, msg);
	} else if (!grpkey) {
	    nym = jsgroupsig.gs_unblind(bsig, bldkey, msg, sig);
	} else {
	    nym = jsgroupsig.gs_unblind(bsig, bldkey, msg, sig, grpkey);
	}
	return { "nym": nym, "msg": msg };
    },
    get_code_from_str: jsgroupsig.gs_get_code_from_str,

    /* grp_key.h functions */    
    grp_key_handle_from_code: jsgroupsig.gs_grp_key_handle_from_code,
    grp_key_init: jsgroupsig.gs_grp_key_init,
    grp_key_free: jsgroupsig.gs_grp_key_free,
    grp_key_copy: jsgroupsig.gs_grp_key_copy,
    grp_key_get_size: jsgroupsig.gs_grp_key_get_size,
    grp_key_export: jsgroupsig.gs_grp_key_export, 
    grp_key_import: jsgroupsig.gs_grp_key_import,
    grp_key_to_string: jsgroupsig.gs_grp_key_to_string,

    /* mgr_key.h functions */
    mgr_key_handle_from_code: jsgroupsig.gs_mgr_key_handle_from_code,
    mgr_key_init: jsgroupsig.gs_mgr_key_init,
    mgr_key_free: jsgroupsig.gs_mgr_key_free,
    mgr_key_copy: jsgroupsig.gs_mgr_key_copy,
    mgr_key_get_size: jsgroupsig.gs_mgr_key_get_size,
    mgr_key_export: jsgroupsig.gs_mgr_key_export,
    mgr_key_import: jsgroupsig.gs_mgr_key_import,
    mgr_key_to_string: jsgroupsig.gs_mgr_key_to_string,

    /* mem_key.h functions */
    mem_key_handle_from_code: jsgroupsig.gs_mem_key_handle_from_code,
    mem_key_init: jsgroupsig.gs_mem_key_init,
    mem_key_free: jsgroupsig.gs_mem_key_free,
    mem_key_copy: jsgroupsig.gs_mem_key_copy,
    mem_key_get_size: jsgroupsig.gs_mem_key_get_size,
    mem_key_export: jsgroupsig.gs_mem_key_export,
    mem_key_import: jsgroupsig.gs_mem_key_import,
    mem_key_to_string: jsgroupsig.gs_mem_key_to_string,
    
    /* bld_key.h functions */
    bld_key_handle_from_code: jsgroupsig.gs_bld_key_handle_from_code,
    bld_key_init: jsgroupsig.gs_bld_key_init,
    bld_key_free: jsgroupsig.gs_bld_key_free,
    bld_key_random: jsgroupsig.gs_bld_key_random,
    bld_key_copy: jsgroupsig.gs_bld_key_copy,
    bld_key_get_size: jsgroupsig.gs_bld_key_get_size,
    bld_key_export: jsgroupsig.gs_bld_key_export,
    bld_key_export_pub: jsgroupsig.gs_bld_key_export_pub,
    bld_key_import: jsgroupsig.gs_bld_key_import,
    bld_key_to_string: jsgroupsig.gs_bld_key_to_string,

    /* signature.h */
    signature_handle_from_code: jsgroupsig.gs_signature_handle_from_code,
    signature_init: jsgroupsig.gs_signature_init,
    signature_free: jsgroupsig.gs_signature_free,
    signature_copy: jsgroupsig.gs_signature_copy,
    signature_get_size: jsgroupsig.gs_signature_get_size,
    signature_export: jsgroupsig.gs_signature_export,
    signature_import: jsgroupsig.gs_signature_import,
    signature_to_string: jsgroupsig.gs_signature_to_string,

    /* blindsig.h */
    blindsig_handle_from_code: jsgroupsig.gs_blindsig_handle_from_code,
    blindsig_init: jsgroupsig.gs_blindsig_init,
    blinsig_free: jsgroupsig.gs_blindsig_free,
    blindsig_copy: jsgroupsig.gs_blindsig_copy,
    blindsig_get_size: jsgroupsig.gs_blindsig_get_size,
    blindsig_export: jsgroupsig.gs_blindsig_export,
    blindsig_import: jsgroupsig.gs_blindsig_import,
    blindsig_to_string: jsgroupsig.gs_blindsig_to_string,

    /* proof.h */
    proof_handle_from_code: jsgroupsig.gs_proof_handle_from_code,
    proof_init: jsgroupsig.gs_proof_init,
    proof_free: jsgroupsig.gs_proof_free,
    proof_copy: jsgroupsig.gs_proof_copy,
    proof_get_size: jsgroupsig.gs_proof_get_size,
    proof_export: jsgroupsig.gs_proof_export,
    proof_import: jsgroupsig.gs_proof_import,
    proof_to_string: jsgroupsig.gs_proof_to_string,    

    /* identity.h */
    identity_handle_from_code: jsgroupsig.gs_identity_handle_from_code,
    identity_init: jsgroupsig.gs_identity_init,
    identity_free: jsgroupsig.gs_identity_free,
    identity_copy: jsgroupsig.gs_identity_copy,
    identity_cmp: jsgroupsig.gs_identity_cmp,
    identity_to_string: jsgroupsig.gs_identity_to_string,
    identity_from_string: jsgroupsig.gs_identity_from_string,

    /* gml.h */
    gml_handle_from_code: jsgroupsig.gs_gml_handle_from_code,
    gml_init: jsgroupsig.gs_gml_init,
    gml_free: jsgroupsig.gs_gml_free,
    gml_export: jsgroupsig.gs_gml_export_file,
    gml_import: jsgroupsig.gs_gml_import,

    /* message.h */
    message_init: jsgroupsig.gs_message_init,
    message_free: jsgroupsig.gs_message_free,
    message_from_string: jsgroupsig.gs_message_from_string,
    message_to_string: jsgroupsig.gs_message_to_string,    
    message_from_stringb64: jsgroupsig.gs_message_from_stringb64,
    message_to_stringb64: jsgroupsig.gs_message_to_stringb64
    
}
