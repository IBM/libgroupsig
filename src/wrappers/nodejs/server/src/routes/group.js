import { Router } from 'express';
const jsgroupsig = require('jsgroupsig');

const router = Router();
const axios = require('axios');

async function checkPKICert(certificate, signature, message, apikey) {
    try {
	
	const options = {
	    'headers': {
		'X-API-KEY': apikey
	    }
	};

	const response = await axios.post(process.env.PKI_ENDPOINT,
					  {
					      cert: certificate,
					      sign: signature,
					      message: message
					  },
					  options);

	if (response.status == 200) {
	    if(response.data.status === 'ok' &&
	       response.data.reason === 'valid_signature') {
		return true;
	    }
	}
	
	return false;
	
    } catch(error) {
	return false;
    }
}

/** Group requests **/

/* Create a new group */
router.post('/', async (req, res, next) => {

    try {

	let code = Number(req.body.code);

	/* Init groupsig */
	jsgroupsig.init(code, 0);

	/* Setup. Need to differentiate between schemes */
	if (code == jsgroupsig.GL19) {

	    /* In GL19, setup is turned into a 3-step process */
	    let seq = Number(req.body.seq);

	    switch(seq) {
		
	    case 1: /* Initial Issuer setup. Expect no more parameters. */

		/* Init grp_key */

		let grpkey1 = jsgroupsig.grp_key_init(code);
		
		/* Init mgr_key. The manager key in this case is the issuer's. */
		let mgrkey1 = jsgroupsig.mgr_key_init(code);		

		/* Run the setup */
		jsgroupsig.setup(code, grpkey1, mgrkey1);

		/* Export the keys to string to store them in the DB */
		let sgrpkey1 = jsgroupsig.grp_key_export(grpkey1);
		let smgrkey1 = jsgroupsig.mgr_key_export(mgrkey1);    
		const group1 = await req.context.models.Group.create({
		    code: code,
		    grpkey: sgrpkey1,
		    mgrkey: smgrkey1,
		});

		return res.status(200).send({
		    "id": group1.id,
		    "code": group1.code,
		    "grpkey": sgrpkey1
		});
		
		break;

	    case 2: /* Converter setup. Expect partial group public key. */

		let sgrpkey2 = req.body.grpkey;

		let grpkey2 = jsgroupsig.grp_key_import(
		    jsgroupsig.GL19,
		    sgrpkey2
		);

		/* Init mgr_key. The manager key in this case is the converter's */
		let mgrkey2 = jsgroupsig.mgr_key_init(code);

		/* Run the setup */
		jsgroupsig.setup(code, grpkey2, mgrkey2);

		/* Export the keys to string to store them in the DB */
		let sgrpkeyfull2 = jsgroupsig.grp_key_export(grpkey2);
		let smgrkey2 = jsgroupsig.mgr_key_export(mgrkey2);    

		const group2 = await req.context.models.Group.create({
		    code: code,
		    grpkey: sgrpkeyfull2,
		    mgrkey: smgrkey2,
		});
		
		return res.status(200).send({
		    "id": group2.id,
		    "code": group2.code,
		    "grpkeyfull": sgrpkeyfull2,
		    "grpkeytmp": sgrpkey2
		});
		
		break;

	    case 3: /* Final Issuer setup. Expect full group public key. */

		let sgrpkeyfull3 = req.body.grpkeyfull;
		let grpkey3 = jsgroupsig.grp_key_import(
		    jsgroupsig.GL19,
		    sgrpkeyfull3
		);

		/* In this case, we only need to update the group public key
		   (the received one contains the converter's public key).
		   @TODO: Some check should be done here to ensure that a 
		   malicious Converter does not change the group key. */

		/* Find the group by "grpkeytmp" */
		const group3 = await req.context.models.Group
		      .findByGroupKey(req.body.grpkeytmp);
		if (!group3) {
		    setImmediate( () => {
			next({
			    status: 405,
			    message: "Wrong group."
			});
		    });
		    return;
		}

		/* Update the group key for the found group */
		group3.update({ grpkey: sgrpkeyfull3 })
		    .then(() => {
			res.status(200).send({
			    "id": group3.id,
			    "code": group3.code,
			    "grpkey": sgrpkeyfull3
			});
			next();
			return;
		    })
		    .catch((error) => {
			setImmediate( () => {
			    next({
				status: 500,
				message: error
			    });
			    return;
			});
		    });
		
		break;

	    default: /* Error */
		setImmediate( () => {
		    next({
			status: 405,
			message: "Wrong setup sequence."
		    });
		    return;
		});
		break;
	    }
	    
	} else {

	    /* Init grp_key */
	    let grpkey = jsgroupsig.grp_key_init(code);
	    jsgroupsig.setup(code, grpkey, mgrkey);

	    /* Export the keys to string to store them in the DB */
	    let sgrpkey = jsgroupsig.grp_key_export(grpkey);
	    let smgrkey = jsgroupsig.mgr_key_export(mgrkey);    
	    
	    const group = await req.context.models.Group.create({
		code: code,
		grpkey: sgrpkey,
		mgrkey: smgrkey,
	    });
	    
	    return res.status(200).send({
		"id": group.id,
		"code": group.code,
		"grpkey": grpkey
	    });
	    
	}
	
    } catch (e) {
	let status = 500;
	if (e instanceof TypeError) {
	    status = 405;
	}
	setImmediate( () => {
	    next({
		status: status,
		message: e.toString()
	    });
	    return;
	});
    }
	
});

/* Fetch all the existing groups */
router.get('/', async (req, res, next) => {
    try {
	const groups = await req.context.models.Group.findAll();
	return res.status(200).send(groups);
    } catch (e) {
	let status = 500;
	if (e instanceof TypeError) {
	    status = 405;
	} 
	setImmediate( () => {
	    next({
		status: status,
		message: e.toString()
	    });
	    return;
	});
	
    }
});
 
router.get('/:groupId', async (req, res, next) => {
  const group = await req.context.models.Group.findByPk(
      req.params.groupId,
  );
    return res.status(200).send(group);
});

/* Delete an existing group */
router.delete('/:groupId', async (req, res, next) => {
    try {
	const result = await req.context.models.Group.destroy({
	    where: { id: req.params.groupId },
	});
	
	return res.status(200).send(true);
    } catch (e) {
	let status = 500;
	if (e instanceof TypeError) {
	    status = 405;
	}
	setImmediate( () => {
	    next({
		status: status,
		message: e.toString()
	    });
	    return;
	});
    }
});

/** Member requests **/

/* Request to initiate a (join,issue) process */
router.post('/:groupId/member', async (req, res, next) => {

    try {
	/* Fetch the group from DB */
	const group = await req.context.models.Group.findByPk(
	    req.params.groupId,
	);
	
	/* Init groupsig */
	jsgroupsig.init(group.code, 0);

	/* Load group key */
	let grpkey = jsgroupsig.grp_key_import(
	    group.code,
	    group.grpkey
	);

	/* Load manager key */
	let mgrkey = jsgroupsig.mgr_key_import(
	    group.code,
	    group.mgrkey
	);

	/* In protocols where the prospective member is the initiator, d = true. */
	/* In that case, the caller needs to use the /:groupId/member/:seq endpoint,
	   with seq = 0 and setting the request body to the necessary data */
	let d = jsgroupsig.get_joinstart(group.code);
	if (d == true) {
	    setImmediate( () => {
		next({
		    status: 405,
		    message: "Missing data for first request."
		});
		return;
	    });
	}

	/* The manager sends the "first" message */
	let mout = jsgroupsig.join_mgr(0, mgrkey, grpkey);

	/* mout contains the challenge */
	let ch = jsgroupsig.message_to_stringb64(mout);

	/* Store the returned message in a temporary table */
	const member = await req.context.models.Member.create({
	    groupId: group.id,
	    seq: 0,
	    challenge: ch
	});

	return res.status(200).send({ "challenge": ch });

    } catch (e) {
	let status = 500;
	if (e instanceof TypeError) {
	    status = 405;
	}
	setImmediate( () => {
	    next({
		status: status,
		message: e.toString()
	    });
	    return;
	});
    }
    
});



/* Request to continue a (join,issue) process */
router.put('/:groupId/member/:seq', async (req, res, next) => {

    try {

	let seq = Number(req.params.seq);

	/* Fetch the group from DB */
	const group = await req.context.models.Group.findByPk(
	    req.params.groupId,
	);
	
	/* Init groupsig */
	jsgroupsig.init(group.code, 0);

	/* Load group key */
	let grpkey = jsgroupsig.grp_key_import(
	    group.code,
	    group.grpkey
	);

	/* Load manager key */
	let mgrkey = jsgroupsig.mgr_key_import(
	    group.code,
	    group.mgrkey
	);

	/* If member sends first message, then we may receive
	   data in the body of the POST request */
	let d = jsgroupsig.get_joinstart(group.code);

	/* Get the number of messages to be exchanged in the join process */
	let steps = jsgroupsig.get_joinseq(group.code);

	/* if d is true and seq is even, client error */
	/* if d is false and seq is odd, client error */
	if ((d == true && !(seq % 2)) || (d == false && (seq % 2))) {
	    setImmediate( () => {
		next({
		    status: 405,
		    message: "Unexpected message sequence."
		});
	    });
	    return;	    
	}

	/* Check that this challenge exists in the Member table */
	const member = await req.context.models.Member
	      .findByChallenge(req.body.challenge);
	if (!member) {
	    setImmediate( () => {
		next({
		    status: 405,
		    message: "Wrong challenge."
		});
	    });
	    return;
	}

	/* Check that the challenge has not been consumed */
	if (member.seq > seq) {
	    setImmediate( () => {
		next({
		    status: 405,
		    message: "Consumed challenge."
		});
	    });
	    return;
	}

	/* If the server requires validating control of a PKI-based identity, 
	   forward the request to the appropriate service. If the result is
	   different than "true", means the requester has not proved owning
	   a valid PKI-based identity. */
	if (process.env.PKI_CHECK == "true") {
	    result = await checkPKICert(req.body.certificate,
					req.body.signature,
					req.body.challenge,
					process.env.PKI_APIKEY);
	    if (result == false) {
		setImmediate( () => {
		    next({
			status: 405,
			message: "Invalid PKI certificate."
		    });
		    return;		    
		});
	    }
	}

	/* Parse the received data into a jslibgroupsig message object */
	let min = jsgroupsig.message_from_stringb64(req.body.response);

	/* Run the manager side of the protocol */
	let mout = jsgroupsig.join_mgr(seq, mgrkey, grpkey, min);
	
	/* Convert the result to a string and return */
	let result = jsgroupsig.message_to_stringb64(mout);

	/* Update the sequence number associated to this join process */
	member.update({ seq: seq+1 })
	    .then(() => {
		res.status(200).send({
		    "seq": seq+1,
		    "result": result
		});
		next();
		return;
	    })
	    .catch((error) => {
		setImmediate( () => {
		    next({
			status: 500,
			message: error
		    });
		    return;
		});
	    });
	
	

    } catch (e) {
	let status = 500;
	if (e instanceof TypeError) {
	    status = 405;
	} 
	setImmediate( () => {
	    next({
		status: status,
		message: e.toString()
	    });
	    return;
	});
	
    }
    
});


/** Signature requests **/

/* Request for verifying a signature */
router.post('/:groupId/signature/verify', async (req, res, next) => {

    try {

	/* Fetch the group from DB */
	const group = await req.context.models.Group.findByPk(
	    req.params.groupId,
	);
	
	/* Init groupsig */
	jsgroupsig.init(group.code, 0);

	/* Load group key */
	let grpkey = jsgroupsig.grp_key_import(
	    group.code,
	    group.grpkey
	);

	/* Load manager key */
	let mgrkey = jsgroupsig.mgr_key_import(
	    group.code,
	    group.mgrkey
	);

	let str_sig = req.body.signature;
	let str_msg = req.body.message;

	/* Import signature */
	let sig = jsgroupsig.signature_import(group.code,
					      str_sig);

	/* Verify signature */
	let b = jsgroupsig.verify(sig, str_msg, grpkey);
	
	return res.status(200).send({"result": b});

    } catch (e) {
	let status = 500;
	if (e instanceof TypeError) {
	    status = 405;
	}
	setImmediate( () => {
	    next({
		status: status,
		message: e.toString()
	    });
	    return;
	});
    }
    
});


/* Request for converting a set of signatures */
router.post('/:groupId/signature/convert', async (req, res, next) => {

    try {

	/* Fetch the group from DB */
	const group = await req.context.models.Group.findByPk(
	    req.params.groupId,
	);

	/* Init groupsig */
	jsgroupsig.init(group.code, 0);

	/* Load group key */
	let grpkey = jsgroupsig.grp_key_import(
	    group.code,
	    group.grpkey
	);

	/* Load manager key */
	let mgrkey = jsgroupsig.mgr_key_import(
	    group.code,
	    group.mgrkey
	);

	/* Import the blinding key */
	let bldkey = jsgroupsig.bld_key_import(group.code,
					       req.body.bldkey);

	/* Import the received string of blinded signatures into an array of blinded
	   signatures */
	let bsigsStr = req.body.blindedSignatures;
	let bsigs = [];

	bsigsStr.forEach( (bsigStr) => {
	    let bsig = jsgroupsig.blindsig_import(group.code,
						  bsigStr);
	    bsigs.push(bsig);
	});

	/* Convert */
	let csigs = jsgroupsig.convert(bsigs, grpkey, mgrkey, bldkey);

	/* Export the converted signatures to an array of strings */
	let csigsStr = [];
	csigs.forEach( (csig) => {
	    let csigStr = jsgroupsig.blindsig_export(csig);
	    csigsStr.push(csigStr);
	});

	return res.status(200).send({"result": csigsStr});

    } catch (e) {
	let status = 500;
	if (e instanceof TypeError) {
	    status = 405;
	}
	setImmediate( () => {
	    next({
		status: status,
		message: e.toString()
	    });
	    return;
	});	
    }
    
});

export default router;
