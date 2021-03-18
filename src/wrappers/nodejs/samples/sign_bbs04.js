#!/usr/bin/env nodejs

const jsgroupsig = require('jsgroupsig');

/* Init groupsig */
jsgroupsig.init(jsgroupsig.BBS04);

/* Init grp_key */
let grpkey = jsgroupsig.grp_key_init(jsgroupsig.BBS04);

/* Init manager key */
let mgrkey = jsgroupsig.mgr_key_init(jsgroupsig.BBS04);

/* Init GML */
let gml = jsgroupsig.gml_init(jsgroupsig.BBS04);

/* Setup call: initializes group key and manager key */
jsgroupsig.setup(jsgroupsig.BBS04, grpkey, mgrkey, gml);

/* Add a member */
let memkey = jsgroupsig.mem_key_init(jsgroupsig.BBS04);
let msg1 = jsgroupsig.join_mgr(0, mgrkey, grpkey, null, gml);
let msg2 = jsgroupsig.join_mem(1, memkey, grpkey, msg1);

/* sign */
let sig = jsgroupsig.sign("Hello, World!", memkey, grpkey);

/* verify */
let ok = jsgroupsig.verify(sig, "Hello, World!", grpkey);

if (ok) console.log("VALID signature.");
else console.log("WRONG signature.");

/* Open the signature */
let id = jsgroupsig.open(sig, grpkey, mgrkey, gml);
let { index, proof } = jsgroupsig.open(sig, grpkey, mgrkey, gml);
console.log("Signer was: "+index);

/* Free stuff */
jsgroupsig.gml_free(gml);
jsgroupsig.grp_key_free(grpkey);
jsgroupsig.mgr_key_free(mgrkey);
jsgroupsig.mem_key_free(memkey);
jsgroupsig.clear(jsgroupsig.BBS04);
