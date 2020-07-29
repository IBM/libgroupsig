import 'dotenv/config';

let chai = require('chai');
let chaiHttp = require('chai-http');
const expect = require('chai').expect;
let assert = require('assert');

const jsgroupsig = require('jsgroupsig');

chai.use(chaiHttp);

// These variables will be set during the tests.
let grpkey = null;
let memkey = null;
let challenge = null;
jsgroupsig.init(jsgroupsig.GL19, 0);

describe('Groups CRUD', function() {
    
    describe ('Get all groups', function() {
	
        it('is initially empty', function(done) {
            chai.request('http://localhost:'+process.env.PORT)
		.get('/'+process.env.API_VERSION+'/group')
		.end(function(error, response) {
		    expect(response.statusCode).to.equal(200);
		    expect(response.body).to.be.instanceof(Array);
		    expect(response.body).to.have.length(0);		    
		    done();
		});
        });

    });
    
    describe ('Get a specific group', function() {

        it('fails to get an inexistent group', function(done) {
            chai.request('http://localhost:'+process.env.PORT)
		.get('/'+process.env.API_VERSION+'/group/1')
		.end(function(error, response) {
		    expect(response.statusCode).to.equal(200);
		    expect(response.body).to.be.empty;
		    done();
		});
        });
	
    });

    describe ('Create one group', function() {

        it('creates the group successfully', function(done) {

	    /* First request to issuer */
            chai.request('http://localhost:'+process.env.PORT_ISSUER)
		.post('/'+process.env.API_VERSION+'/group')
	    	.send({ code: 3, seq: 1 })
		.end(function(error, response) {
		    expect(response.statusCode).to.equal(200);
		    expect(response.body).to.be.an('object');
		    expect(response.body).to.have.property("id");
		    expect(response.body).to.have.property("code");
		    expect(response.body).to.have.property("grpkey");

		    let sgrpkeytmp = response.body.grpkey;

		    /* Request to converter */
		    chai.request('http://localhost:'+process.env.PORT_CONVERTER)
			.post('/'+process.env.API_VERSION+'/group')
	    		.send({ code: 3, seq: 2, grpkey: sgrpkeytmp })
			.end(function(error, response) {
			    expect(response.statusCode).to.equal(200);
			    expect(response.body).to.be.an('object');
			    expect(response.body).to.have.property("id");
			    expect(response.body).to.have.property("code");
			    expect(response.body).to.have.property("grpkeyfull");
			    expect(response.body).to.have.property("grpkeytmp");

			    let sgrpkeyfull = response.body.grpkeyfull;

			    /* Final request to issuer */
			    chai.request('http://localhost:'+process.env.PORT_ISSUER)
				.post('/'+process.env.API_VERSION+'/group')
	    			.send({
				    code: 3,
				    seq: 3,
				    grpkeytmp: sgrpkeytmp,
				    grpkeyfull: sgrpkeyfull
				})
				.end(function(error, response) {
				    expect(response.statusCode).to.equal(200);
				    expect(response.body).to.be.an('object');
				    expect(response.body).to.have.property("id");
				    expect(response.body).to.have.property("code");
				    expect(response.body).to.have.property("grpkey");
				    done();				    
				});
		    
			});
		});
	});
	
        it('gets the group successfully', function(done) {
            chai.request('http://localhost:'+process.env.PORT)
		.get('/'+process.env.API_VERSION+'/group/1')
		.end(function(error, response) {
		    expect(response.statusCode).to.equal(200);
		    expect(response.body).to.be.an('object');
		    expect(response.body).to.have.property("id");
		    expect(response.body).to.have.property("code");
		    expect(response.body).to.have.property("grpkey");
		    try {
			grpkey = jsgroupsig.grp_key_import(
			    jsgroupsig.GL19,
			    response.body.grpkey
			);
		    } catch(e) {
			if (e instanceof TypeError) {
			    assert.fail('Internal TypeError thrown.');
			} else {
			    assert.fail('Internal Error thrown.');
			}
		    }
		    done();
		});
        });	
	
    });

    // Delete group

});

describe('Member creation', function() {

    describe ('Adds a member to an existing group', function() {

        it('successfully answers the initial request', function(done) {
	    
            chai.request('http://localhost:'+process.env.PORT)
		.post('/'+process.env.API_VERSION+'/group/1/member')
		.end(function(error, response) {
		    expect(response.statusCode).to.equal(200);
		    expect(response.body).to.be.an('object');
		    expect(response.body).to.have.property("challenge");
		    challenge = response.body.challenge;
		    done();
		});
        });

	it('successfully answers the second request', function(done) {

	    /* Run the (first) member part of the join */
	    let response = null;
	    try {
		memkey = jsgroupsig.mem_key_init(jsgroupsig.GL19);
		let msgin = jsgroupsig.message_from_stringb64(challenge);
		let msgout = jsgroupsig.join_mem(1, memkey, grpkey, msgin);
		response = jsgroupsig.message_to_stringb64(msgout);
	    } catch (e) {
		if (e instanceof TypeError) {
		    assert.fail('Internal TypeError thrown.');
		} else {
		    assert.fail('Internal Error thrown.');
		}		
	    }
	    
	    chai.request('http://localhost:'+process.env.PORT)
		.put('/'+process.env.API_VERSION+'/group/1/member/2')
		.send({
		    challenge : challenge,
		    response : response
		})
		.end(function(error, response) {
		    expect(response.statusCode).to.equal(200);
		    expect(response.body).to.be.an('object');
		    expect(response.body).to.have.property("seq");
		    expect(response.body.seq).to.be.equal(3);
		    expect(response.body).to.have.property("result");

		    /* Complete memkey generation process */
		    try {
			let msgin = jsgroupsig.message_from_stringb64(
			    response.body.result
			);
			jsgroupsig.join_mem(3, memkey, grpkey, msgin);
		    } catch(e) {
			if (e instanceof TypeError) {
			    assert.fail('Internal TypeError thrown.');
			} else {
			    assert.fail('Internal Error thrown.');
			}			
		    }
		    
		    done();
		});
	    
	});

	/* Fails to use a consumed challenge */
	it('fails to reuse a consumed challenge', function(done) {

	    /* Run the (first) member part of the join */
	    let response = null;
	    try {
		let memkey2 = jsgroupsig.mem_key_init(jsgroupsig.GL19);
		let msgin = jsgroupsig.message_from_stringb64(challenge);
		let msgout = jsgroupsig.join_mem(1, memkey2, grpkey, msgin);
		response = jsgroupsig.message_to_stringb64(msgout);
	    } catch (e) {
		if (e instanceof TypeError) {
		    assert.fail('Internal TypeError thrown.');
		} else {
		    assert.fail('Internal Error thrown.');
		}		
	    }

	    /* Note: here, challenge has been used by the previous test */
	    chai.request('http://localhost:'+process.env.PORT)
		.put('/'+process.env.API_VERSION+'/group/1/member/2')
		.send({
		    challenge : challenge,
		    response : response
		})
		.end(function(error, response) {
		    expect(response.statusCode).to.equal(405);	    
		    done();
		});
	    
	});	
	
    });
    
});


describe('Signature processing', function() {

    describe ('Verification', function() {

	it('Successfully verifies a valid signature', function(done) {

	    let msg = "Hello, World!";
	    let sigStr = null;
	    try {
		let sig = jsgroupsig.sign(msg, memkey, grpkey);
		sigStr = jsgroupsig.signature_to_string(sig);
	    } catch (e) {
		if (e instanceof TypeError) {
		    assert.fail('Internal TypeError thrown.');
		} else {
		    assert.fail('Internal Error thrown.');
		}		
	    }
	    
            chai.request('http://localhost:'+process.env.PORT)
		.post('/'+process.env.API_VERSION+'/group/1/signature/verify')
		.send({
		    message: msg,
		    signature: sigStr,
		})
		.end(function(error, response) {
		    expect(response.statusCode).to.equal(200);
		    expect(response.body).to.be.an('object');
		    expect(response.body).to.have.property("result");
		    expect(response.body.result).to.be.true;
		    done();
		});	
	    
	});

	it('Rejects an invalid signature', function(done) {

	    let msg = "Hello, World!";
	    let sigStr = null;
	    try {
		let sig = jsgroupsig.sign(msg, memkey, grpkey);
		sigStr = jsgroupsig.signature_to_string(sig);
	    } catch (e) {
		if (e instanceof TypeError) {
		    assert.fail('Internal TypeError thrown.');
		} else {
		    assert.fail('Internal Error thrown.');
		}		
	    }
	    
            chai.request('http://localhost:'+process.env.PORT)
		.post('/'+process.env.API_VERSION+'/group/1/signature/verify')
		.send({
		    message: "Hello, Worlds!",
		    signature: sigStr,
		})
		.end(function(error, response) {
		    expect(response.statusCode).to.equal(200);
		    expect(response.body).to.be.an('object');
		    expect(response.body).to.have.property("result");
		    expect(response.body.result).to.be.false;
		    done();
		});	
	    
	});

    });

    describe ('Conversion', function() {

	it('Links a set of signatures issued by the same member',
	   function(done) {

	       /* Generate two signatures by the same member */
	       let msg1 = "Hello, World1!";
	       let msg2 = "Hello, World2!";
	       let sig1 = jsgroupsig.sign(msg1, memkey, grpkey);
	       let sig2 = jsgroupsig.sign(msg2, memkey, grpkey);

	       /* Generate a random blinding key and export the public part */
	       let bldkey = jsgroupsig.bld_key_random(grpkey);

	       let bldkeyStr = jsgroupsig.bld_key_export_pub(bldkey);

	       /* Blind the signatures */
	       let blindsig1 = jsgroupsig.blind(bldkey, grpkey, sig1, msg1);
	       let blindsig2 = jsgroupsig.blind(bldkey, grpkey, sig2, msg2);

	       /* Export the blinded signatures to strings */
	       let blindsigStr1 = jsgroupsig.blindsig_export(blindsig1);
	       let blindsigStr2 = jsgroupsig.blindsig_export(blindsig2);

	       /* Make the convert request */
	       chai.request('http://localhost:'+process.env.PORT_CONVERTER)
		   .post('/'+process.env.API_VERSION+'/group/1/signature/convert')
		   .send({
		       bldkey: bldkeyStr,
		       blindedSignatures: [ blindsigStr1, blindsigStr2 ]
		   })
		   .end(function(error, response) {
		       expect(response.statusCode).to.equal(200);
		       expect(response.body).to.be.an('object');
		       expect(response.body).to.have.property("result");
		       expect(response.body.result).to.be.instanceof(Array);
		       expect(response.body.result).to.have.length(2);

		       /* Import the converted signatures from the 
			  received strings */

		       let csig1 = jsgroupsig.blindsig_import(
			   jsgroupsig.GL19,
			   response.body.result[0]
		       );

		       let csig2 = jsgroupsig.blindsig_import(
			   jsgroupsig.GL19,
			   response.body.result[1]
		       );	       

		       /* Unblind the converted signatures */
		       let sig1 = jsgroupsig.unblind(csig1, bldkey);
		       let sig2 = jsgroupsig.unblind(csig2, bldkey);
		       
		       /* Export the nyms to strings to compare them */
		       let nymStr1 = jsgroupsig.identity_to_string(sig1['nym']);
		       let nymStr2 = jsgroupsig.identity_to_string(sig2['nym']);
		       
		       /* Both strings must match */
		       expect(nymStr1).to.equal(nymStr2);
		       done();
		   });
	       
	   });

	it('Links the same (repeated) signature by the same member',
	   function(done) {

	       /* Generate two signatures by the same member */
	       let msg = "Hello, World!";
	       let sig = jsgroupsig.sign(msg, memkey, grpkey);

	       /* Generate a random blinding key */
	       let bldkey = jsgroupsig.bld_key_random(grpkey);
	       let bldkeyStr = jsgroupsig.bld_key_export_pub(bldkey);

	       /* Blind the signatures */
	       let blindsig = jsgroupsig.blind(bldkey, grpkey, sig, msg);

	       /* Export the blinded signatures to strings */
	       let blindsigStr = jsgroupsig.blindsig_to_string(blindsig);

	       /* Make the convert request */
	       chai.request('http://localhost:'+process.env.PORT_CONVERTER)
		   .post('/'+process.env.API_VERSION+'/group/1/signature/convert')
		   .send({
		       bldkey: bldkeyStr,
		       blindedSignatures: [ blindsigStr, blindsigStr ]
		   })
		   .end(function(error, response) {
		       expect(response.statusCode).to.equal(200);
		       expect(response.body).to.be.an('object');
		       expect(response.body).to.have.property("result");
		       expect(response.body.result).to.be.instanceof(Array);
		       expect(response.body.result).to.have.length(2);

		       /* Import the converted signatures from the 
			  received strings */
		       let csig1 = jsgroupsig.blindsig_import(
			   jsgroupsig.GL19,
			   response.body.result[0]
		       );

		       let csig2 = jsgroupsig.blindsig_import(
			   jsgroupsig.GL19,
			   response.body.result[1]
		       );	       
		       
		       /* Unblind the converted signatures */
		       let sig1 = jsgroupsig.unblind(csig1, bldkey);
		       let sig2 = jsgroupsig.unblind(csig2, bldkey);
		       
		       /* Export the nyms to strings to compare them */
		       let nymStr1 = jsgroupsig.identity_to_string(sig1['nym']);
		       let nymStr2 = jsgroupsig.identity_to_string(sig2['nym']);
		       
		       /* Both strings must match */
		       expect(nymStr1).to.equal(nymStr2);
		       done();
		   });
	       
	   });	

	it('Does not link signatures by different users', function(done) {

	    /* Create a second test member */
	    let memkey2 = null;
	    let challenge2 = null;
	    let response2 = null;
	    chai.request('http://localhost:'+process.env.PORT)
		.post('/'+process.env.API_VERSION+'/group/1/member')
		.end(function(error, response) {

		    /* Check the response to the first message */
		    expect(response.statusCode).to.equal(200);
		    expect(response.body).to.be.an('object');
		    expect(response.body).to.have.property("challenge");
		    challenge2 = response.body.challenge;

		    memkey2 = jsgroupsig.mem_key_init(jsgroupsig.GL19);

		    let msgin = jsgroupsig.message_from_stringb64(challenge2);
		    let msgout = jsgroupsig.join_mem(1, memkey2, grpkey, msgin);
		    response2 = jsgroupsig.message_to_stringb64(msgout);

		    /* Send the second message -- @TODO There must be a more 
		       NodeJSy way to do this... */
		    chai.request('http://localhost:'+process.env.PORT)
			.put('/'+process.env.API_VERSION+'/group/1/member/2')
			.send({
			    challenge : challenge2,
			    response : response2
			})
			.end(function(error, response) {
			    
			    /* Check the response to the second message */
			    expect(response.statusCode).to.equal(200);
			    expect(response.body).to.be.an('object');
			    expect(response.body).to.have.property("seq");
			    expect(response.body.seq).to.be.equal(3);
			    expect(response.body).to.have.property("result");

			    /* Complete the member join process */
			    let msgin2 = jsgroupsig.message_from_stringb64(
				response.body.result
			    );
			    jsgroupsig.join_mem(3, memkey2, grpkey, msgin2);

			    /* Generate two signatures by different members */
			    let msg1 = "Hello, World1!";
			    let msg2 = "Hello, World2!";
			    let sig1 = jsgroupsig.sign(msg1, memkey, grpkey);
			    let sig2 = jsgroupsig.sign(msg2, memkey2, grpkey);
			    
			    /* Generate a random blinding key */
			    let bldkey = jsgroupsig.bld_key_random(grpkey);
			    let bldkeyStr = jsgroupsig.bld_key_export_pub(bldkey);
			    
			    /* Blind the signatures */
			    let blindsig1 = jsgroupsig.blind(bldkey, grpkey, sig1, msg1);
			    let blindsig2 = jsgroupsig.blind(bldkey, grpkey, sig2, msg2);
			    
			    /* Export the blinded signatures to strings */
			    let blindsigStr1 = jsgroupsig.blindsig_to_string(blindsig1);
			    let blindsigStr2 = jsgroupsig.blindsig_to_string(blindsig2);
			    
			    /* Make the convert request */
			    chai.request('http://localhost:'+process.env.PORT_CONVERTER)
				.post('/'+process.env.API_VERSION+'/group/1/signature/convert')
				.send({
				    bldkey: bldkeyStr,
				    blindedSignatures: [ blindsigStr1, blindsigStr2 ]
				})
				.end(function(error, response) {
				    expect(response.statusCode).to.equal(200);
				    expect(response.body).to.be.an('object');
				    expect(response.body).to.have.property("result");
				    expect(response.body.result).to.be.instanceof(Array);
				    expect(response.body.result).to.have.length(2);
				    
				    /* Import the converted signatures from the 
				       received strings */
				    let csig1 = jsgroupsig.blindsig_import(
					jsgroupsig.GL19,
					response.body.result[0]
				    );

				    let csig2 = jsgroupsig.blindsig_import(
					jsgroupsig.GL19,
					response.body.result[1]
				    );	       
				    
				    /* Unblind the converted signatures */
				    let sig1 = jsgroupsig.unblind(csig1, bldkey);
				    let sig2 = jsgroupsig.unblind(csig2, bldkey);
				    
				    /* Export the nyms to strings to compare them */
				    let nymStr1 = jsgroupsig.identity_to_string(sig1['nym']);
				    let nymStr2 = jsgroupsig.identity_to_string(sig2['nym']);
				    
				    /* Both strings must not match */
				    expect(nymStr1).to.not.equal(nymStr2);

				    
				    done();
				});	    

			});		    
		  
		});
	    
	});

	it('Does not link signatures by the same user in separate queries',
	   function(done) {

	       /* Generate two signatures by the same member */
	       let msg1 = "Hello, World1!";
	       let msg2 = "Hello, World2!";
	       let sig1 = jsgroupsig.sign(msg1, memkey, grpkey);
	       let sig2 = jsgroupsig.sign(msg2, memkey, grpkey);

	       /* Generate a random blinding key */
	       let bldkey = jsgroupsig.bld_key_random(grpkey);
	       let bldkeyStr = jsgroupsig.bld_key_export_pub(bldkey);

	       /* Blind the signatures */
	       let blindsig1 = jsgroupsig.blind(bldkey, grpkey, sig1, msg1);
	       let blindsig2 = jsgroupsig.blind(bldkey, grpkey, sig2, msg2);

	       /* Export the blinded signatures to strings */
	       let blindsigStr1 = jsgroupsig.blindsig_to_string(blindsig1);
	       let blindsigStr2 = jsgroupsig.blindsig_to_string(blindsig2);

	       /* Make the first convert request */
	       chai.request('http://localhost:'+process.env.PORT_CONVERTER)
		   .post('/'+process.env.API_VERSION+'/group/1/signature/convert')
		   .send({
		       bldkey: bldkeyStr,
		       blindedSignatures: [ blindsigStr1 ]
		   })
		   .end(function(error, response) {
		       expect(response.statusCode).to.equal(200);
		       expect(response.body).to.be.an('object');
		       expect(response.body).to.have.property("result");
		       expect(response.body.result).to.be.instanceof(Array);
		       expect(response.body.result).to.have.length(1);

		       /* Import the converted signature from the 
			  received string */
		       let csig1 = jsgroupsig.blindsig_import(
			   jsgroupsig.GL19,
			   response.body.result[0]
		       );		       

		       /* Make the second convert request */
		       chai.request('http://localhost:'+process.env.PORT_CONVERTER)
			   .post('/'+process.env.API_VERSION+'/group/1/signature/convert')
			   .send({
			       bldkey: bldkeyStr,
			       blindedSignatures: [ blindsigStr2 ]
			   })
			   .end(function(error, response) {
			       expect(response.statusCode).to.equal(200);
			       expect(response.body).to.be.an('object');
			       expect(response.body).to.have.property("result");
			       expect(response.body.result).to.be.instanceof(Array);
			       expect(response.body.result).to.have.length(1);

			       /* Import the converted signature from the 
				  received string */
			       let csig2 = jsgroupsig.blindsig_import(
				   jsgroupsig.GL19,
				   response.body.result[0]
			       );	       
			       
			       /* Unblind the converted signatures */
			       let sig1 = jsgroupsig.unblind(csig1, bldkey);
			       let sig2 = jsgroupsig.unblind(csig2, bldkey);
			       
			       /* Export the nyms to strings to compare them */
			       let nymStr1 = jsgroupsig.identity_to_string(sig1['nym']);
			       let nymStr2 = jsgroupsig.identity_to_string(sig2['nym']);
		       
			       /* Both strings must match */
			       expect(nymStr1).to.not.equal(nymStr2);
			       done();
			   });
		       
		   });

	   });	
	
    });    
    
});

