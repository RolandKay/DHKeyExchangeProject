import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

/*
* This program executes the Diffie-Hellman key agreement protocol between
* 3 parties: Alice, Bob, and Carol using a shared 2048-bit DH parameter.
*/
public class DHKeyAgreement3 {
	
    public static void main(String args[]) throws Exception {
    	
    	// Alice creates her own DH key pair
    	System.out.println("ALICE: Generate DH keypair ...");
//        KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
//        aliceKpairGen.initialize(2048);
//        KeyPair aliceKpair = aliceKpairGen.generateKeyPair();
    	KeyPair aliceKpair = DHUtils.generateKeyPair(null);
        
	    // This DH parameters can also be constructed by creating a
	    // DHParameterSpec object using agreed-upon values
        DHParameterSpec dhParamShared = ((DHPublicKey)aliceKpair.getPublic()).getParams();
        
        // Bob creates his own DH key pair using the same params
        System.out.println("BOB: Generate DH keypair ...");
//        KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
//        bobKpairGen.initialize(dhParamShared);
//        KeyPair bobKpair = bobKpairGen.generateKeyPair();
        KeyPair bobKpair = DHUtils.generateKeyPair(dhParamShared);
        
        // Carol creates her own DH key pair using the same params
        System.out.println("CAROL: Generate DH keypair ...");
//        KeyPairGenerator carolKpairGen = KeyPairGenerator.getInstance("DH");
//        carolKpairGen.initialize(dhParamShared);
//        KeyPair carolKpair = carolKpairGen.generateKeyPair();
        KeyPair carolKpair = DHUtils.generateKeyPair(dhParamShared);
        
        // Alice initialize
        System.out.println("ALICE: Initialize ...");
//        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
//        aliceKeyAgree.init(aliceKpair.getPrivate());
        KeyAgreement aliceKeyAgree = DHUtils.initializeKeyAgreement(aliceKpair);
    
        // Bob initialize
        System.out.println("BOB: Initialize ...");
//        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
//        bobKeyAgree.init(bobKpair.getPrivate());
        KeyAgreement bobKeyAgree = DHUtils.initializeKeyAgreement(bobKpair);
        
        // Carol initialize
        System.out.println("CAROL: Initialize ...");
//        KeyAgreement carolKeyAgree = KeyAgreement.getInstance("DH");
//        carolKeyAgree.init(carolKpair.getPrivate());
        KeyAgreement carolKeyAgree = DHUtils.initializeKeyAgreement(carolKpair);
        
        // Alice uses Carol's public key
        Key ac = aliceKeyAgree.doPhase(carolKpair.getPublic(), false);
        
        // Bob uses Alice's public key
        Key ba = bobKeyAgree.doPhase(aliceKpair.getPublic(), false);
        
        // Carol uses Bob's public key
        Key cb = carolKeyAgree.doPhase(bobKpair.getPublic(), false);
        
        // Alice uses Carol's result from above
        aliceKeyAgree.doPhase(cb, true);
        
        // Bob uses Alice's result from above
        bobKeyAgree.doPhase(ac, true);
        
        // Carol uses Bob's result from above
        carolKeyAgree.doPhase(ba, true);
        
        // Alice, Bob and Carol compute their secrets
        byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
        System.out.println("Alice secret: " + DHUtils.byteArrayToHexString(aliceSharedSecret));
        byte[] bobSharedSecret = bobKeyAgree.generateSecret();
        System.out.println("Bob secret: " + DHUtils.byteArrayToHexString(bobSharedSecret));
        byte[] carolSharedSecret = carolKeyAgree.generateSecret();
        System.out.println("Carol secret: " + DHUtils.byteArrayToHexString(carolSharedSecret));
        // Compare Alice and Bob
        if (!java.util.Arrays.equals(aliceSharedSecret, bobSharedSecret))
            throw new Exception("Secret keys of Alice and Bob differ");
        System.out.println("Secret keys of Alice and Bob are the same");
        // Compare Bob and Carol
        if (!java.util.Arrays.equals(bobSharedSecret, carolSharedSecret))
            throw new Exception("Secret keys of Bob and Carol differ");
        System.out.println("Secret keys of Bob and Carol are the same");

        /*
         * Now let's create a SecretKey object using the shared secret.
         * Generate SecretKeys for the "AES" algorithm (based on the raw shared secret data) 
         * and compare them
         */
        System.out.println("Use shared secret as SecretKey object ...");
        SecretKeySpec bobAesKey = new SecretKeySpec(bobSharedSecret, 0, 16, "AES");
        SecretKeySpec aliceAesKey = new SecretKeySpec(aliceSharedSecret, 0, 16, "AES");
        SecretKeySpec carolAesKey = new SecretKeySpec(carolSharedSecret, 0, 16, "AES");

        if(aliceAesKey.equals(bobAesKey) && bobAesKey.equals(carolAesKey)) {
        	System.out.println("Secret keys are the same");
        }else {
        	System.out.println("Secret keys are different");
        }
    }
}
