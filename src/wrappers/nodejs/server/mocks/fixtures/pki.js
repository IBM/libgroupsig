// mocks/fixtures/pki.js

const TEST_CERT_AND_SIGN = [
    {
	cert: "sample-cert",
	sign: "sample-signature",
	message: "sample-message"
    }
];

const verifyCert = {
    id: "verify-cert",
    url: "/cert/verify",
    method: "POST",
    response: (req, res) => {
	const reqCert = req.body.cert;
	const reqSig = req.body.sign;
	const reqMsg = req.body.message;
	const cert = TEST_CERT_AND_SIGN.find(data => data.cert == reqCert);
	if (cert && cert.cert == reqCert  && reqSig == cert.sign) {
	    res.status(200);
	    res.send(true);
	} else {
	    res.status(200);
	    res.send(false);
	}
    }
};

module.exports = {
    verifyCert
};
