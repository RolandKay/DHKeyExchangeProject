import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

/*
* This program executes the Diffie-Hellman key agreement protocol between
* 2 parties: Alice and Bob using a shared 2048-bit DH parameter.
*/
public class DHKeyAgreement2 {
	
    public static void main(String args[]) throws Exception {
        
        //Alice creates her own DH key pair
        System.out.println("ALICE: Generate DH keypair ...");
        KeyPair aliceKpair = DHUtils.generateKeyPair(null);
        
        // Alice creates and initializes her DH KeyAgreement object
        System.out.println("ALICE: Initialization ...");
        KeyAgreement aliceKeyAgree = DHUtils.initializeKeyAgreement(aliceKpair);
        
        // Alice encodes her public key, and sends it over to Bob.
        byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded();
        
        /*
         * Bob receives Alice's public key in encoded format.
         * He instantiates a DH public key from the encoded key material.
         */
        PublicKey alicePubKey = DHUtils.generatePublicKey(alicePubKeyEnc);

        /*
         * Bob gets the DH parameters associated with Alice's public key.
         * He must use the same parameters when he generates his own key
         * pair.
         */
        DHParameterSpec dhParamFromAlicePubKey = ((DHPublicKey)alicePubKey).getParams(); // contains the Prime P and Generator G

        // Bob creates his own DH key pair
        System.out.println("BOB: Generate DH keypair ...");
        KeyPair bobKpair = DHUtils.generateKeyPair(dhParamFromAlicePubKey);

        // Bob creates and initializes his DH KeyAgreement object
        System.out.println("BOB: Initialization ...");
        KeyAgreement bobKeyAgree = DHUtils.initializeKeyAgreement(bobKpair);

        // Bob encodes his public key, and sends it over to Alice.
        byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded();

        /*
         * Alice uses Bob's public key for the first (and only) phase of her version of the DH protocol.
         * Before she can do so, she has to instantiate a DH public key
         * from Bob's encoded key material.
         */    
        PublicKey bobPubKey = DHUtils.generatePublicKey(bobPubKeyEnc);
        
        System.out.println("ALICE: Execute PHASE1 ...");
        
        //doPhase(Key key, boolean lastPhase)
        //Executes the next phase of this key agreement with the given key that was received from one of the other parties involved in this key agreement.
        aliceKeyAgree.doPhase(bobPubKey, true);

        /*
         * Bob uses Alice's public key for the first (and only) phase of his version of the DH protocol.
         */
        System.out.println("BOB: Execute PHASE1 ...");
        bobKeyAgree.doPhase(alicePubKey, true);

        /*
         * At this stage, both Alice and Bob have completed the DH key agreement protocol.
         * Both generate the (same) shared secret.
         */
        byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
        byte[] bobSharedSecret = bobKeyAgree.generateSecret();

        System.out.println("Alice secret: " +
                DHUtils.byteArrayToHexString(aliceSharedSecret));
        System.out.println("Bob secret: " +
        		DHUtils.byteArrayToHexString(bobSharedSecret));
        if (!java.util.Arrays.equals(aliceSharedSecret, bobSharedSecret))
            throw new Exception("Shared secrets differ");
        System.out.println("Shared secrets are the same");

        /*
         * Now let's create a SecretKey object using the shared secret.
         * Generate SecretKeys for the "AES" algorithm (based on the raw shared secret data) 
         * and compare them
         */
        System.out.println("Use shared secret as SecretKey object ...");
        SecretKeySpec bobAesKey = new SecretKeySpec(bobSharedSecret, 0, 16, "AES");
        SecretKeySpec aliceAesKey = new SecretKeySpec(aliceSharedSecret, 0, 16, "AES");

        if(aliceAesKey.equals(bobAesKey)) {
        	System.out.println("Secret keys are the same");
        }else {
        	System.out.println("Secret keys are different");
        }
    }
}