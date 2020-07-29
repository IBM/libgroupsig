package com.ibm.jgroupsig.executable;

import com.ibm.jgroupsig.GS;
import com.ibm.jgroupsig.BBS04;
import com.ibm.jgroupsig.Signature;
import com.ibm.jgroupsig.MemKey;

import java.io.UnsupportedEncodingException;
import java.lang.IllegalArgumentException;

public class SignBBS04 {
    
    public static void main (String args[]) {

	try {
	    /* 
	       Instantiate and setup the group. 
	       To simulate a real setting, we use three different 
	       "environments", issuer (who controls the issuing key),
	       converter (who controls the converter key), and user
	       (who controls a member key)
	    */
	    BBS04 issuer = new BBS04();
	    BBS04 user = new BBS04();

	    issuer.setup();
	    user.setGrpKey(issuer.getGrpKey());

	    /* Simulate adding one member */
	    MemKey memkey = new MemKey(GS.BBS04_CODE);	
	    long mout1 = issuer.joinMgr(0, 0);
	    long mout2 = issuer.joinMem(memkey, 1, mout1);
	
	    /* Create sample signatures */
	    Signature sig = user.sign("Hello, World!", memkey);
	    boolean b = user.verify(sig, "Hello, World!");

	    if (b == true) {
		System.out.println("VALID signature.");
	    } else {
		System.out.println("WRONG signature.");
	    }

	    issuer.finalize();
	    user.finalize();

	    return;

	} catch(UnsupportedEncodingException |
		IllegalArgumentException e) {
	    e.printStackTrace();
	} catch(Exception e) {
	    e.printStackTrace();
	}
	
    }

}
