let chai = require('chai');
const expect = require('chai').expect;
let assert = require('assert');

const jsgroupsig = require('../lib/index.js');

function setupFull() {
    /* Note: for testing we run all the setup calls within this function.
       In the real world, the first call to setup should be done by the issuer,
       the second by the converter. See the repository documentation for more
       info. */
    jsgroupsig.init(jsgroupsig.PS16);
    let ps16 = jsgroupsig.get_groupsig_from_code(jsgroupsig.PS16);
    let grpkey = jsgroupsig.grp_key_init(jsgroupsig.PS16);
    let mgrkey = jsgroupsig.mgr_key_init(jsgroupsig.PS16);
    let gml = jsgroupsig.gml_init(jsgroupsig.PS16);
    jsgroupsig.setup(jsgroupsig.PS16, grpkey, mgrkey, gml);
    return {
	'grpkey': grpkey,
	'mgrkey': mgrkey,
	'gml': gml
    };
}

function addMember(mgrkey, grpkey, gml) {
    let memkey = jsgroupsig.mem_key_init(jsgroupsig.PS16);
    let msg1 = jsgroupsig.join_mgr(0, mgrkey, grpkey, null, gml);
    let msg2 = jsgroupsig.join_mem(1, memkey, grpkey, msg1);
    let msg3 = jsgroupsig.join_mgr(2, mgrkey, grpkey, msg2, gml);
    jsgroupsig.join_mem(3, memkey, grpkey, msg3);
    
    return memkey;
}

describe('PS16 Group key operations', function() {

    it('initializes a group key.', function() {
	jsgroupsig.init(jsgroupsig.PS16, 0);	
	let grpkey = jsgroupsig.grp_key_init(jsgroupsig.PS16);
	assert.notEqual(grpkey, null);
    });

    it('exports and imports a group key.', function() {
	let ps16 = setupFull();
	let str = jsgroupsig.grp_key_export(ps16.grpkey);
	let grpkey = jsgroupsig.grp_key_import(jsgroupsig.PS16, str);
	assert.notEqual(grpkey, null);
    });

});

describe('PS16 Manager key operations', function() {

    it('initializes a manager key.', function() {
	jsgroupsig.init(jsgroupsig.PS16, 0);	
	let mgrkey = jsgroupsig.mgr_key_init(jsgroupsig.PS16);
	assert.notEqual(mgrkey, null);
    });

    it('exports and imports a manager key.', function() {
	let ps16 = setupFull();
	let str = jsgroupsig.mgr_key_export(ps16.mgrkey);
	let mgrkey = jsgroupsig.mgr_key_import(jsgroupsig.PS16, str);
	assert.notEqual(mgrkey, null);
    });


});

describe('PS16 Member key operations', function() {

    it('initializes a member key.', function() {
	jsgroupsig.init(jsgroupsig.PS16, 0);	
	let memkey = jsgroupsig.mem_key_init(jsgroupsig.PS16);
	assert.notEqual(memkey, null);
    });

    it('exports and imports a member key.', function() {
	let ps16 = setupFull();
	let memkey = addMember(ps16.mgrkey, ps16.grpkey, ps16.gml);
	let str = jsgroupsig.mem_key_export(memkey);
	let memkey2 = jsgroupsig.mem_key_import(jsgroupsig.PS16, str);
	assert.notEqual(memkey2, null);
    });    

});

describe('PS16 Signature operations', function() {

    it('initializes a signature.', function() {
	jsgroupsig.init(jsgroupsig.PS16, 0);
	let sig = jsgroupsig.signature_init(jsgroupsig.PS16);
	assert.notEqual(sig, null);
    });

    it('exports and imports a signature.', function() {
	let ps16 = setupFull();
	let memkey = addMember(ps16.mgrkey, ps16.grpkey, ps16.gml);
	let sig = jsgroupsig.sign("Hello, World!", memkey, ps16.grpkey);
	let str = jsgroupsig.signature_export(sig);
	let sig2 = jsgroupsig.signature_import(jsgroupsig.PS16, str);
	let b = jsgroupsig.verify(sig2, "Hello, World!", ps16.grpkey);
	assert.equal(b, true);
    });      
    
});

describe('PS16 Group operations', function() {
    
    it('sets up group and manager keys.', function() {
	let ps16 = setupFull();
	assert.notEqual(ps16.grpkey, null);
	assert.notEqual(ps16.mgrkey, null);
    });

    it('the manager starts the join protocol', function() {
	let s = jsgroupsig.get_joinstart(jsgroupsig.PS16);
	assert.equal(s, 0);
    });

    it('the join protocol has 4 messages', function() {
	let s = jsgroupsig.get_joinseq(jsgroupsig.PS16);
	assert.equal(s, 3); // start counting in 0
    });

    it('adds a new group member.', function() {
	let ps16 = setupFull();
	let memkey = addMember(ps16.mgrkey, ps16.grpkey, ps16.gml);
	assert.notEqual(memkey, null);
    });

    it('a VALID string signature is accepted.', function() {
	let ps16 = setupFull();
	let memkey = addMember(ps16.mgrkey, ps16.grpkey, ps16.gml);
	let sig = jsgroupsig.sign("Hello, World!", memkey, ps16.grpkey);
	let b = jsgroupsig.verify(sig, "Hello, World!", ps16.grpkey);
	assert.equal(b, true);
    });

    it('a WRONG string signature is rejected.', function() {
	let ps16 = setupFull();
	let memkey = addMember(ps16.mgrkey, ps16.grpkey, ps16.gml);
	let sig = jsgroupsig.sign("Hello, World!", memkey, ps16.grpkey);
	let b = jsgroupsig.verify(sig, "Hello, World2!", ps16.grpkey);
	assert.equal(b, false);
    });

    it('correctly opens a signature.', function() {
	let ps16 = setupFull();
	let memkey = addMember(ps16.mgrkey, ps16.grpkey, ps16.gml);
	let memkey2 = addMember(ps16.mgrkey, ps16.grpkey, ps16.gml);
	let sig = jsgroupsig.sign("Hello, World!", memkey2, ps16.grpkey);
	let { index, proof } = jsgroupsig.open(sig, ps16.grpkey, ps16.mgrkey, ps16.gml);
	assert.equal(index, 1);
	let b = jsgroupsig.open_verify(proof, sig, ps16.grpkey);
	assert.equal(b, true);
    });

});

