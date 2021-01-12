let chai = require('chai');
const expect = require('chai').expect;
let assert = require('assert');

const jsgroupsig = require('../lib/index.js');

function setupFull() {
    /* Note: for testing we run all the setup calls within this function.
       In the real world, the first call to setup should be done by the issuer,
       the second by the converter. See the repository documentation for more
       info. */
    jsgroupsig.init(jsgroupsig.BBS04);
    let bbs04 = jsgroupsig.get_groupsig_from_code(jsgroupsig.BBS04);
    let grpkey = jsgroupsig.grp_key_init(jsgroupsig.BBS04);
    let mgrkey = jsgroupsig.mgr_key_init(jsgroupsig.BBS04);
    let gml = jsgroupsig.gml_init(jsgroupsig.BBS04);
    jsgroupsig.setup(jsgroupsig.BBS04, grpkey, mgrkey, gml);
    return {
	'grpkey': grpkey,
	'mgrkey': mgrkey,
	'gml': gml
    };
}

function addMember(mgrkey, grpkey, gml) {
    let memkey = jsgroupsig.mem_key_init(jsgroupsig.BBS04);
    let msg1 = jsgroupsig.join_mgr(0, mgrkey, grpkey, null, gml);
    let msg2 = jsgroupsig.join_mem(1, memkey, grpkey, msg1);
    
    return memkey;
}

describe('BBS04 Group key operations', function() {

    it('initializes a group key.', function() {
	jsgroupsig.init(jsgroupsig.BBS04, 0);	
	let grpkey = jsgroupsig.grp_key_init(jsgroupsig.BBS04);
	assert.notEqual(grpkey, null);
    });

    it('exports and imports a group key.', function() {
	let bbs04 = setupFull();
	let str = jsgroupsig.grp_key_export(bbs04.grpkey);
	let grpkey = jsgroupsig.grp_key_import(jsgroupsig.BBS04, str);
	assert.notEqual(grpkey, null);
    });

});

describe('BBS04 Manager key operations', function() {

    it('initializes a manager key.', function() {
	jsgroupsig.init(jsgroupsig.BBS04, 0);	
	let mgrkey = jsgroupsig.mgr_key_init(jsgroupsig.BBS04);
	assert.notEqual(mgrkey, null);
    });

    it('exports and imports a manager key.', function() {
	let bbs04 = setupFull();
	let str = jsgroupsig.mgr_key_export(bbs04.mgrkey);
	let mgrkey = jsgroupsig.mgr_key_import(jsgroupsig.BBS04, str);
	assert.notEqual(mgrkey, null);
    });


});

describe('BBS04 Member key operations', function() {

    it('initializes a member key.', function() {
	jsgroupsig.init(jsgroupsig.BBS04, 0);	
	let memkey = jsgroupsig.mem_key_init(jsgroupsig.BBS04);
	assert.notEqual(memkey, null);
    });

    it('exports and imports a member key.', function() {
	let bbs04 = setupFull();
	let memkey = addMember(bbs04.mgrkey, bbs04.grpkey, bbs04.gml);
	let str = jsgroupsig.mem_key_export(memkey);
	let memkey2 = jsgroupsig.mem_key_import(jsgroupsig.BBS04, str);
	assert.notEqual(memkey2, null);
    });    

});

describe('BBS04 Signature operations', function() {

    it('initializes a signature.', function() {
	jsgroupsig.init(jsgroupsig.BBS04, 0);
	let sig = jsgroupsig.signature_init(jsgroupsig.BBS04);
	assert.notEqual(sig, null);
    });

    it('exports and imports a signature.', function() {
	let bbs04 = setupFull();
	let memkey = addMember(bbs04.mgrkey, bbs04.grpkey, bbs04.gml);
	let sig = jsgroupsig.sign("Hello, World!", memkey, bbs04.grpkey);
	let str = jsgroupsig.signature_export(sig);
	let sig2 = jsgroupsig.signature_import(jsgroupsig.BBS04, str);
	let b = jsgroupsig.verify(sig2, "Hello, World!", bbs04.grpkey);
	assert.equal(b, true);
    });      
    
});

describe('BBS04 Group operations', function() {
    
    it('sets up group and manager keys.', function() {
	let bbs04 = setupFull();
	assert.notEqual(bbs04.grpkey, null);
	assert.notEqual(bbs04.mgrkey, null);
    });

    it('the manager starts the join protocol', function() {
	let s = jsgroupsig.get_joinstart(jsgroupsig.BBS04);
	assert.equal(s, 0);
    });

    it('the join protocol has 1 messages', function() {
	let s = jsgroupsig.get_joinseq(jsgroupsig.BBS04);
	assert.equal(s, 1); // start counting in 0
    });

    it('adds a new group member.', function() {
	let bbs04 = setupFull();
	let memkey = addMember(bbs04.mgrkey, bbs04.grpkey, bbs04.gml);
	assert.notEqual(memkey, null);
    });

    it('a VALID string signature is accepted.', function() {
	let bbs04 = setupFull();
	let memkey = addMember(bbs04.mgrkey, bbs04.grpkey, bbs04.gml);
	let sig = jsgroupsig.sign("Hello, World!", memkey, bbs04.grpkey);
	let b = jsgroupsig.verify(sig, "Hello, World!", bbs04.grpkey);
	assert.equal(b, true);
    });

    it('a WRONG string signature is rejected.', function() {
	let bbs04 = setupFull();
	let memkey = addMember(bbs04.mgrkey, bbs04.grpkey, bbs04.gml);
	let sig = jsgroupsig.sign("Hello, World!", memkey, bbs04.grpkey);
	let b = jsgroupsig.verify(sig, "Hello, World2!", bbs04.grpkey);
	assert.equal(b, false);
    });

    it('a VALID bytes signature is accepted.', function() {
	let bbs04 = setupFull();
	let memkey = addMember(bbs04.mgrkey, bbs04.grpkey, bbs04.gml);
	let array = new Uint8Array(10);
	for (let i = 0; i < 10; ++i) array[i] = i;
	let sig = jsgroupsig.sign(array.buffer, memkey, bbs04.grpkey);
	let b = jsgroupsig.verify(sig, array.buffer, bbs04.grpkey);
	assert.equal(b, true);
    });

    it('a WRONG bytes signature is rejected.', function() {
	let bbs04 = setupFull();
	let memkey = addMember(bbs04.mgrkey, bbs04.grpkey, bbs04.gml);
	let array = new Uint8Array(10);
	for (let i = 0; i < 10; ++i) array[i] = i;
	let sig = jsgroupsig.sign(array.buffer, memkey, bbs04.grpkey);
	let array2 = new Uint8Array(10);
	for (let i = 0; i < 10; ++i) array2[i] = i+1;	
	let b = jsgroupsig.verify(sig, array2.buffer, bbs04.grpkey);
	assert.equal(b, false);
    });    

    it('correctly opens a signature.', function() {
	let bbs04 = setupFull();
	let memkey = addMember(bbs04.mgrkey, bbs04.grpkey, bbs04.gml);
	let memkey2 = addMember(bbs04.mgrkey, bbs04.grpkey, bbs04.gml);
	let sig = jsgroupsig.sign("Hello, World!", memkey2, bbs04.grpkey);
	let { index, proof } = jsgroupsig.open(sig, bbs04.grpkey, bbs04.mgrkey, bbs04.gml);
	assert.equal(index, 1);
    });

});

