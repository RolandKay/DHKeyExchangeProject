import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

public class DHUtils {
	
	/**
	 * creates DH key pair
	 * @param dhParamFromAlicePubKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static KeyPair generateKeyPair(DHParameterSpec dhParamFromAlicePubKey) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");  // Blowfish, HmacSHA256
		if(dhParamFromAlicePubKey != null) {
			keyPairGen.initialize(dhParamFromAlicePubKey);
		} else {
			keyPairGen.initialize(2048); // creates DH key pair with 2048-bit key size
		}
		
	    KeyPair keypair = keyPairGen.generateKeyPair(); // Generate a privateKey and a publicKey
	    return keypair;
	}
	
	/**
	 * creates and initializes her DH KeyAgreement object
	 * @param kp
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static KeyAgreement initializeKeyAgreement(KeyPair kp) throws NoSuchAlgorithmException, InvalidKeyException {
		KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
		keyAgreement.init(kp.getPrivate());
        return keyAgreement;
	}
	
	/**
	 * Instantiates a DH public key from an encoded key
	 * @param publicKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static PublicKey generatePublicKey (byte[] encodedKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory keyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(encodedKey);
        PublicKey publicKey = keyFactory.generatePublic(x509KeySpec);
        return publicKey;
	}
	
		
    //Converts a byte array to hex string
    public static String byteArrayToHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
        int len = block.length;
        for (int i = 0; i < len; i++) {
        	byteToHex(block[i], buf);
            if (i < len-1) {
                buf.append(":");
            }
        }
        return buf.toString();
    }
    
	//Converts a byte to hex digit and writes to the supplied buffer
	private static void byteToHex(byte b, StringBuffer buf) {
	    char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
	            '9', 'A', 'B', 'C', 'D', 'E', 'F' };
	    int high = ((b & 0xf0) >> 4);
	    int low = (b & 0x0f);
	    buf.append(hexChars[high]);
	    buf.append(hexChars[low]);
	}
}
