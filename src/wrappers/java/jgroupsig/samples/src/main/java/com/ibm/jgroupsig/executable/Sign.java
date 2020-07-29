package com.ibm.jgroupsig.executable;

import com.ibm.jgroupsig.GS;
import com.ibm.jgroupsig.GL19;
import com.ibm.jgroupsig.Signature;
import com.ibm.jgroupsig.MemKey;

import java.io.UnsupportedEncodingException;
import java.lang.IllegalArgumentException;

public class Sign {
    
    public static void main (String args[]) {

	try {
	    /* 
	       Instantiate and setup the group. 
	       To simulate a real setting, we use three different 
	       "environments", issuer (who controls the issuing key),
	       converter (who controls the converter key), and user
	       (who controls a member key)
	    */
	    GL19 issuer = new GL19();
	    GL19 converter = new GL19();
	    GL19 user = new GL19();

	    issuer.setup();
	    converter.setup(issuer.getGrpKey());
	    issuer.setup(converter.getGrpKey());
	    user.setGrpKey(issuer.getGrpKey());

	    /* Simulate adding one member */
	    MemKey memkey = new MemKey(GS.GL19_CODE);	
	    long mout1 = issuer.joinMgr(0, 0);
	    long mout2 = issuer.joinMem(memkey, 1, mout1);
	    long mout3 = issuer.joinMgr(2, mout2);
	    issuer.joinMem(memkey, 3, mout3);
	
	    /* Create sample signatures */
	    Signature sig = user.sign("Hello, World!", memkey);
	    boolean b = user.verify(sig, "Hello, World!");

	    if (b == true) {
		System.out.println("VALID signature.");
	    } else {
		System.out.println("WRONG signature.");
	    }

	    issuer.finalize();
	    converter.finalize();
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
