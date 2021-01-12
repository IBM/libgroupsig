let chai = require('chai');
const expect = require('chai').expect;
let assert = require('assert');

const jsgroupsig = require('../lib/index.js');

function setupFull() {
    /* Note: for testing we run all the setup calls within this function.
       In the real world, the first call to setup should be done by the issuer,
       the second by the converter. See the repository documentation for more
       info. */
    jsgroupsig.init(jsgroupsig.GL19);
    let gl19 = jsgroupsig.get_groupsig_from_code(jsgroupsig.GL19);
    let grpkey = jsgroupsig.grp_key_init(jsgroupsig.GL19);
    let isskey = jsgroupsig.mgr_key_init(jsgroupsig.GL19);
    let cnvkey = jsgroupsig.mgr_key_init(jsgroupsig.GL19);
    jsgroupsig.setup(jsgroupsig.GL19, grpkey, isskey);
    jsgroupsig.setup(jsgroupsig.GL19, grpkey, cnvkey);
    return {
	'grpkey': grpkey,
	'isskey': isskey,
	'cnvkey': cnvkey
    };
}

function addMember(isskey, grpkey) {
    let memkey = jsgroupsig.mem_key_init(jsgroupsig.GL19);
    let msg1 = jsgroupsig.join_mgr(0, isskey, grpkey);
    let msg2 = jsgroupsig.join_mem(1, memkey, grpkey, msg1);
    let msg3 = jsgroupsig.join_mgr(2, isskey, grpkey, msg2);
    jsgroupsig.join_mem(3, memkey, grpkey, msg3);
    
    return memkey;
}

describe('GL19 Group key operations', function() {

    it('initializes a group key.', function() {
	jsgroupsig.init(jsgroupsig.GL19, 0);	
	let grpkey = jsgroupsig.grp_key_init(jsgroupsig.GL19);
	assert.notEqual(grpkey, null);
    });

    it('exports and imports a group key.', function() {
	let gl19 = setupFull();
	let str = jsgroupsig.grp_key_export(gl19.grpkey);
	let grpkey = jsgroupsig.grp_key_import(jsgroupsig.GL19, str);
	assert.notEqual(grpkey, null);
    });

});

describe('GL19 Manager key operations', function() {

    it('initializes a manager key.', function() {
	jsgroupsig.init(jsgroupsig.GL19, 0);	
	let mgrkey = jsgroupsig.mgr_key_init(jsgroupsig.GL19);
	assert.notEqual(mgrkey, null);
    });

    it('exports and imports an issuer key.', function() {
	let gl19 = setupFull();
	let str = jsgroupsig.mgr_key_export(gl19.isskey);
	let isskey = jsgroupsig.mgr_key_import(jsgroupsig.GL19, str);
	assert.notEqual(isskey, null);
    });

    it('exports and imports a converter key.', function() {
	let gl19 = setupFull();
	let str = jsgroupsig.mgr_key_export(gl19.cnvkey);
	let cnvkey = jsgroupsig.mgr_key_import(jsgroupsig.GL19, str);
	assert.notEqual(cnvkey, null);
    });

});

describe('GL19 Member key operations', function() {

    it('initializes a member key.', function() {
	jsgroupsig.init(jsgroupsig.GL19, 0);	
	let memkey = jsgroupsig.mem_key_init(jsgroupsig.GL19);
	assert.notEqual(memkey, null);
    });

    it('exports and imports a member key.', function() {
	let gl19 = setupFull();
	let memkey = addMember(gl19.isskey, gl19.grpkey);
	let str = jsgroupsig.mem_key_export(memkey);
	let memkey2 = jsgroupsig.mem_key_import(jsgroupsig.GL19, str);
	assert.notEqual(memkey2, null);
    });    

});

describe('GL19 Blinding key operations', function() {

    it('initializes a blinding key.', function() {
	jsgroupsig.init(jsgroupsig.GL19, 0);	
	let bldkey = jsgroupsig.bld_key_init(jsgroupsig.GL19);
	assert.notEqual(bldkey, null);
    });

    it('randomly initializes a blinding key.', function() {
	let gl19 = setupFull();	
	let bldkey = jsgroupsig.bld_key_random(gl19.grpkey);
	assert.notEqual(bldkey, null);
    });

    it('exports and imports a full blinding key.', function() {
	let gl19 = setupFull();	
	let bldkey = jsgroupsig.bld_key_random(gl19.grpkey);
	let str = jsgroupsig.bld_key_export(bldkey);
	let bldkey2 = jsgroupsig.bld_key_import(jsgroupsig.GL19, str);
	assert.notEqual(bldkey2, null);
    });

    it('exports and imports the public part of a blinding key.', function() {
	let gl19 = setupFull();	
	let bldkey = jsgroupsig.bld_key_random(gl19.grpkey);
	let str = jsgroupsig.bld_key_export_pub(bldkey);
	let bldkey2 = jsgroupsig.bld_key_import(jsgroupsig.GL19, str);
	assert.notEqual(bldkey2, null);
    });    

});

describe('GL19 Signature operations', function() {

    it('initializes a signature.', function() {
	jsgroupsig.init(jsgroupsig.GL19, 0);
	let sig = jsgroupsig.signature_init(jsgroupsig.GL19);
	assert.notEqual(sig, null);
    });

    it('exports and imports a signature.', function() {
	let gl19 = setupFull();
	let memkey = addMember(gl19.isskey, gl19.grpkey);
	let sig = jsgroupsig.sign("Hello, World!", memkey, gl19.grpkey);
	let str = jsgroupsig.signature_export(sig);
	let sig2 = jsgroupsig.signature_import(jsgroupsig.GL19, str);
	let b = jsgroupsig.verify(sig2, "Hello, World!", gl19.grpkey);
	assert.equal(b, true);
    });      
    
});

describe('GL19 Blinded signature operations', function() {

    it('initializes a blinded signature.', function() {
	jsgroupsig.init(jsgroupsig.GL19, 0);
	let bsig = jsgroupsig.blindsig_init(jsgroupsig.GL19);
	assert.notEqual(bsig, null);
    });

    it('exports and imports a blinded signature.', function() {
	let gl19 = setupFull();
	let memkey = addMember(gl19.isskey, gl19.grpkey);
	let sig = jsgroupsig.sign("Hello, World!", memkey, gl19.grpkey);
	let bldkey = jsgroupsig.bld_key_random(gl19.grpkey);
	let bsig = jsgroupsig.blind(bldkey, gl19.grpkey, sig, "Hello, World!");
	let str = jsgroupsig.blindsig_export(bsig);
	let bsig2 = jsgroupsig.blindsig_import(jsgroupsig.GL19, str);
	assert.notEqual(bsig2, null);
    });
    
});

describe('GL19 Identity operations', function() {

    it('initializes an identity.', function() {
	jsgroupsig.init(jsgroupsig.GL19, 0);
	let id = jsgroupsig.identity_init(jsgroupsig.GL19);
	assert.notEqual(id, null);
    });

    it('can be represented as a string.', function() {
	let gl19 = setupFull();
	let memkey = addMember(gl19.isskey, gl19.grpkey);
	let sig = jsgroupsig.sign("Hello, World!", memkey, gl19.grpkey);
	let bldkey = jsgroupsig.bld_key_random(gl19.grpkey);
	let bsig = jsgroupsig.blind(bldkey, gl19.grpkey, sig, "Hello, World!");
	let csigs = jsgroupsig.convert([bsig], gl19.grpkey, gl19.cnvkey, bldkey);
	let usig = jsgroupsig.unblind(csigs[0], bldkey);
	let nymStr = jsgroupsig.identity_to_string(usig['nym']);
	expect(nymStr).to.be.a('string');
    });

    it('same identity comparison returns 0.', function() {
	let gl19 = setupFull();
	let memkey = addMember(gl19.isskey, gl19.grpkey);
	let sig = jsgroupsig.sign("Hello, World!", memkey, gl19.grpkey);
	let bldkey = jsgroupsig.bld_key_random(gl19.grpkey);
	let bsig = jsgroupsig.blind(bldkey, gl19.grpkey, sig, "Hello, World!");
	let csigs = jsgroupsig.convert([bsig], gl19.grpkey, gl19.cnvkey, bldkey);
	let usig = jsgroupsig.unblind(csigs[0], bldkey);
	let nymStr1 = jsgroupsig.identity_to_string(usig['nym']);
	let nymStr2 = jsgroupsig.identity_to_string(usig['nym']);
	let eq = jsgroupsig.identity_cmp(usig['nym'], usig['nym']);	
	expect(eq).equal(0);
    });

    it('same identity comparison returns != 0.', function() {
	let gl19 = setupFull();
	let memkey1 = addMember(gl19.isskey, gl19.grpkey);
	let memkey2 = addMember(gl19.isskey, gl19.grpkey);
	let sig1 = jsgroupsig.sign("Hello, World!", memkey1, gl19.grpkey);
	let sig2 = jsgroupsig.sign("Hello, World!", memkey2, gl19.grpkey);	
	let bldkey = jsgroupsig.bld_key_random(gl19.grpkey);
	let bsig1 = jsgroupsig.blind(bldkey, gl19.grpkey, sig1, "Hello, World!");
	let bsig2 = jsgroupsig.blind(bldkey, gl19.grpkey, sig2, "Hello, World!");
	let csigs = jsgroupsig.convert([bsig1, bsig2], gl19.grpkey, gl19.cnvkey, bldkey);
	let usig1 = jsgroupsig.unblind(csigs[0], bldkey);
	let usig2 = jsgroupsig.unblind(csigs[1], bldkey);	
	let nymStr1 = jsgroupsig.identity_to_string(usig1['nym']);
	let nymStr2 = jsgroupsig.identity_to_string(usig2['nym']);
	let eq = jsgroupsig.identity_cmp(usig1['nym'], usig2['nym']);	
	expect(eq).not.equal(0);
    });    
    
});


describe('GL19 Group operations', function() {
    
    it('sets up group, issuer and converter keys.', function() {
	let gl19 = setupFull();
	assert.notEqual(gl19.grpkey, null);
	assert.notEqual(gl19.isskey, null);
	assert.notEqual(gl19.cnvkey, null);
    });

    it('sets up group, issuer and converter keys.', function() {
	let gl19 = setupFull();
	assert.notEqual(gl19.grpkey, null);
	assert.notEqual(gl19.isskey, null);
	assert.notEqual(gl19.cnvkey, null);
    });

    it('the manager starts the join protocol', function() {
	let s = jsgroupsig.get_joinstart(jsgroupsig.GL19);
	assert.equal(s, 0);
    });

    it('the join protocol has 4 messages', function() {
	let s = jsgroupsig.get_joinseq(jsgroupsig.GL19);
	assert.equal(s, 3); // start counting in 0
    });

    it('adds a new group member.', function() {
	let gl19 = setupFull();
	let memkey = addMember(gl19.isskey, gl19.grpkey);
	assert.notEqual(memkey, null);
    });

    it('a VALID string signature is accepted.', function() {
	let gl19 = setupFull();
	let memkey = addMember(gl19.isskey, gl19.grpkey);
	let sig = jsgroupsig.sign("Hello, World!", memkey, gl19.grpkey);
	let b = jsgroupsig.verify(sig, "Hello, World!", gl19.grpkey);
	assert.equal(b, true);
    });

    it('a WRONG string signature is rejected.', function() {
	let gl19 = setupFull();
	let memkey = addMember(gl19.isskey, gl19.grpkey);
	let sig = jsgroupsig.sign("Hello, World!", memkey, gl19.grpkey);
	let b = jsgroupsig.verify(sig, "Hello, World2!", gl19.grpkey);
	assert.equal(b, false);
    });

    it('a VALID bytes signature is accepted.', function() {
	let gl19 = setupFull();
	let memkey = addMember(gl19.isskey, gl19.grpkey);
	let array = new Uint8Array(10);
	for (let i = 0; i < 10; ++i) array[i] = i;
	let sig = jsgroupsig.sign(array.buffer, memkey, gl19.grpkey);
	let b = jsgroupsig.verify(sig, array.buffer, gl19.grpkey);
	assert.equal(b, true);
    });

    it('a WRONG bytes signature is rejected.', function() {
	let gl19 = setupFull();
	let memkey = addMember(gl19.isskey, gl19.grpkey);
	let array = new Uint8Array(10);
	for (let i = 0; i < 10; ++i) array[i] = i;
	let sig = jsgroupsig.sign(array.buffer, memkey, gl19.grpkey);
	let array2 = new Uint8Array(10);
	for (let i = 0; i < 10; ++i) array2[i] = i+1;	
	let b = jsgroupsig.verify(sig, array2.buffer, gl19.grpkey);
	assert.equal(b, false);
    });    

    it('correctly links (blind-convert-unblind) two signatures by the same member.',
       function() {
	   let gl19 = setupFull();
	   let memkey = addMember(gl19.isskey, gl19.grpkey);
	   let sig1 = jsgroupsig.sign("Hello, World!", memkey, gl19.grpkey);
	   let sig2 = jsgroupsig.sign("Hello, World2!", memkey, gl19.grpkey);
	   let bldkey = jsgroupsig.bld_key_random(gl19.grpkey);
	   let bsig1 = jsgroupsig.blind(bldkey, gl19.grpkey, sig1, "Hello, World!");
	   let bsig2 = jsgroupsig.blind(bldkey, gl19.grpkey, sig2, "Hello, World2!");	 
	   let csigs = jsgroupsig.convert([bsig1, bsig2], gl19.grpkey, gl19.cnvkey, bldkey);
	   let usig1 = jsgroupsig.unblind(csigs[0], bldkey);
	   let usig2 = jsgroupsig.unblind(csigs[1], bldkey); 
	   let nymStr1 = jsgroupsig.identity_to_string(usig1['nym']);
	   let nymStr2 = jsgroupsig.identity_to_string(usig2['nym']);
	   assert.equal(nymStr1, nymStr2);
       });

    it('non-transitivity for signatures converted in separate queries.',
       function() {
	   let gl19 = setupFull();
	   let memkey = addMember(gl19.isskey, gl19.grpkey);
	   let sig1 = jsgroupsig.sign("Hello, World!", memkey, gl19.grpkey);
	   let sig2 = jsgroupsig.sign("Hello, World2!", memkey, gl19.grpkey);
	   let bldkey = jsgroupsig.bld_key_random(gl19.grpkey);
	   let bsig1 = jsgroupsig.blind(bldkey, gl19.grpkey, sig1, "Hello, World!");
	   let bsig2 = jsgroupsig.blind(bldkey, gl19.grpkey, sig2, "Hello, World2!");	 
	   let csigs1 = jsgroupsig.convert([bsig1], gl19.grpkey, gl19.cnvkey, bldkey);
	   let csigs2 = jsgroupsig.convert([bsig2], gl19.grpkey, gl19.cnvkey, bldkey);	   
	   let usig1 = jsgroupsig.unblind(csigs1[0], bldkey);
	   let usig2 = jsgroupsig.unblind(csigs2[0], bldkey); 
	   let nymStr1 = jsgroupsig.identity_to_string(usig1['nym']);
	   let nymStr2 = jsgroupsig.identity_to_string(usig2['nym']);
	   assert.notEqual(nymStr1, nymStr2);
       });

    it('two signatures by different members are not linked (blind-convert-unblind).',
       function() {
	   let gl19 = setupFull();
	   let memkey1 = addMember(gl19.isskey, gl19.grpkey);	
	   let memkey2 = addMember(gl19.isskey, gl19.grpkey);   
	   let sig1 = jsgroupsig.sign("Hello, World!", memkey1, gl19.grpkey);
	   let sig2 = jsgroupsig.sign("Hello, World2!", memkey2, gl19.grpkey);
	   let bldkey = jsgroupsig.bld_key_random(gl19.grpkey);
	   let bsig1 = jsgroupsig.blind(bldkey, gl19.grpkey, sig1, "Hello, World!");
	   let bsig2 = jsgroupsig.blind(bldkey, gl19.grpkey, sig2, "Hello, World2!");	 
	   let csigs = jsgroupsig.convert([bsig1, bsig2], gl19.grpkey, gl19.cnvkey, bldkey);
	   let usig1 = jsgroupsig.unblind(csigs[0], bldkey);
	   let usig2 = jsgroupsig.unblind(csigs[1], bldkey); 
	   let nymStr1 = jsgroupsig.identity_to_string(usig1['nym']);
	   let nymStr2 = jsgroupsig.identity_to_string(usig2['nym']);
	   assert.notEqual(nymStr1, nymStr2);
       });    

});

