package com.jgsudhakar.crypto.util;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class AESencrp {
    
     private static final String ALGO = "AES";
    private static final byte[] keyValue = new byte[] { 'T', 'h', 'e', 'B', 'e', 's', 't','S', 'e', 'c', 'r','e', 't', 'K', 'e', 'y' };

	public static String encrypt(String Data) throws Exception {
	        Key key = generateKey();
	        Cipher c = Cipher.getInstance(ALGO);
	        c.init(Cipher.ENCRYPT_MODE, key);
	        byte[] encVal = c.doFinal(Data.getBytes());
	        String encryptedValue = new BASE64Encoder().encode(encVal);
	        return encryptedValue;
	    }


	/**
	 * Hex string to byte array.
	 *
	 * @param s the s
	 * @return the byte[]
	 */
	public static byte [] hexStringToByteArray ( String s )
	{
	    int len = s.length ();
	    byte [] data = new byte[len / 2];
	    for ( int i = 0; i < len; i += 2 )
	    {
	        data[i / 2] = (byte) ( ( Character.digit ( s.charAt ( i ), 16 ) << 4 ) + Character.digit ( s.charAt ( i + 1 ), 16 ) );
	    }
	    return data;
	}

	public static String decryptAESEncryptWithSaltAndIV ( String encryptedData, String key, String salt, String iv ) throws Exception
	{
    byte [] saltBytes = hexStringToByteArray ( salt );
    byte [] ivBytes = hexStringToByteArray ( iv );
    IvParameterSpec ivParameterSpec = new IvParameterSpec ( ivBytes );
    SecretKeySpec sKey = (SecretKeySpec) generateKeyFromPasswordWithSalt ( key, saltBytes );

    Cipher c = Cipher.getInstance ("AES/CBC/PKCS5Padding");
    c.init ( Cipher.DECRYPT_MODE, sKey, ivParameterSpec );
    byte [] decordedValue = new BASE64Decoder ().decodeBuffer ( encryptedData );
    byte [] decValue = c.doFinal ( decordedValue );
    String decryptedValue = new String ( decValue );

    return decryptedValue;
	}

    public static String decrypt(String encryptedData) throws Exception {
        Key key = generateKey();
        Cipher c = Cipher.getInstance(ALGO);
        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decordedValue = new BASE64Decoder().decodeBuffer(encryptedData);
        byte[] decValue = c.doFinal(decordedValue);
        String decryptedValue = new String(decValue);
        return decryptedValue;
    }
    
    public static SecretKey generateKeyFromPasswordWithSalt ( String password, byte [] saltBytes ) throws GeneralSecurityException
    {
        KeySpec keySpec = new PBEKeySpec ( password.toCharArray (), saltBytes, 100, 128 );
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance ("PBKDF2/HMAC/SHA1");
        SecretKey secretKey = keyFactory.generateSecret ( keySpec );

        return new SecretKeySpec (secretKey.getEncoded (), ALGO);
    }
    public static Key generateKey() throws Exception {
        Key key = new SecretKeySpec(keyValue, ALGO);
        return key;
}
    
    public static String generateSecret () 
    {
        return "1234455553dsfdfdsfdsf";   //generate always random number and send for each request
    }

}