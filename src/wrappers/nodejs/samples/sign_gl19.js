#!/usr/bin/env nodejs

const jsgroupsig = require('jsgroupsig');

/* Init groupsig */
jsgroupsig.init(jsgroupsig.GL19);

/* Init grp_key */
let grpkey = jsgroupsig.grp_key_init(jsgroupsig.GL19);

/* Init issuer and converter keys */
let isskey = jsgroupsig.mgr_key_init(jsgroupsig.GL19);
let cnvkey = jsgroupsig.mgr_key_init(jsgroupsig.GL19);

/* Setup call 1: initializes (partial) group key and issuer key */
jsgroupsig.setup(jsgroupsig.GL19, grpkey, isskey);

/* Setup call 2: completes group key and initializes converter key */
jsgroupsig.setup(jsgroupsig.GL19, grpkey, cnvkey);

/* Add a member */
let memkey = jsgroupsig.mem_key_init(jsgroupsig.GL19);
let msg1 = jsgroupsig.join_mgr(0, isskey, grpkey);
let msg2 = jsgroupsig.join_mem(1, memkey, grpkey, msg1);
let msg3 = jsgroupsig.join_mgr(2, isskey, grpkey, msg2);
let msg4 = jsgroupsig.join_mem(3, memkey, grpkey, msg3);

/* sign */
let sig = jsgroupsig.sign("Hello, World!", memkey, grpkey);

/* verify */
let ok = jsgroupsig.verify(sig, "Hello, World!", grpkey);

if (ok) console.log("VALID signature.");
else console.log("WRONG signature.");

jsgroupsig.clear(jsgroupsig.GL19);
