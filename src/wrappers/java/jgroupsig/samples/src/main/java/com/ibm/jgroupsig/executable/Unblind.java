package com.ibm.jgroupsig.executable;

import com.ibm.jgroupsig.*;

import java.io.UnsupportedEncodingException;
import java.lang.IllegalArgumentException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.FileWriter;
import java.io.FileReader;
import java.io.BufferedReader;

public class Unblind {

    /* Credit to https://stackoverflow.com/a/13006907 */
    private static String byteArrayToHex(byte[] a) {
	StringBuilder sb = new StringBuilder(a.length * 2);
	for(byte b: a)
	    sb.append(String.format("%02x", b));
	return sb.toString();
    }    

    /* Credit to https://stackoverflow.com/a/4716623 */
    private static String file2String(String fileName) {
	try(BufferedReader br = new BufferedReader(new FileReader(fileName))) {
	    StringBuilder sb = new StringBuilder();
	    String line = br.readLine();

	    while (line != null) {
		sb.append(line);
		sb.append(System.lineSeparator());
		line = br.readLine();
	    }
	    String everything = sb.toString();
	    return everything;
	} catch(FileNotFoundException fnfe) {
	    System.out.println(fnfe);
	} catch(IOException ioe) {
	    System.out.println(ioe);
	}       
	return null;
    } 
    
    public static void main(String args[]) {

	if (args.length != 2) {
	    System.out.println("Usage: java Unblind <blinding key str> <blinded signature str>");
	    return;
	}
	
	try {

	    GL19 user = new GL19();

	    /* Import bldkey from the first string in the command line args */
	    String bldstr = file2String(args[0]);
	    BldKey bldkey = new BldKey(GS.GL19_CODE, bldstr);

	    /* Import converted signature from the second string in the command
	       line args */
	    String sigstr = file2String(args[1]);	    
	    BlindSignature cSig = new BlindSignature(GS.GL19_CODE, sigstr);

     	    /* Unblind */
	    Identity id = user.unblind(cSig, bldkey);

	    /* Print result */
	    System.out.println("ID: "+id.toStr()+
			       "\nMessage hash: 0x"+byteArrayToHex(id.getMsg()).substring(0,32)+"...");
	    
	} catch (UnsupportedEncodingException uee) {
	    System.out.println(uee);
	} catch (IllegalArgumentException iae) {
	    System.out.println(iae);
	} catch (Exception e) {
	    System.out.println(e);
	}

	return;
    }

}
