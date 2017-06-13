/**
 * 
 */
package com.jgsudhakar.crypto.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

/**
 * @author sudhakar
 *
 */
public class RSAGenerateKeysTest {
	private KeyPairGenerator keyGen;
	private KeyPair pair;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private Cipher cipher;

	public RSAGenerateKeysTest(int keylength) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		this.keyGen = KeyPairGenerator.getInstance("RSA");
		this.keyGen.initialize(keylength);
		this.cipher = Cipher.getInstance("RSA");
	}

	public void createKeys() {
		this.pair = this.keyGen.generateKeyPair();
		this.privateKey = pair.getPrivate();
		this.publicKey = pair.getPublic();
	}

	public PrivateKey getPrivateKey() {
		return this.privateKey;
	}

	public PublicKey getPublicKey() {
		return this.publicKey;
	}

	public void writeToFile(String path, byte[] key) throws IOException {
		File f = new File(path);
		f.getParentFile().mkdirs();

		FileOutputStream fos = new FileOutputStream(f);
		fos.write(key);
		fos.flush();
		fos.close();
	}
	
	public static PrivateKey getPrivate(String filename) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

	public static PublicKey getPublic(String filename) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}

	public void encryptFile(byte[] input, File output, PrivateKey key)
		throws IOException, GeneralSecurityException {
		this.cipher.init(Cipher.ENCRYPT_MODE, key);
		writeToFile(output, this.cipher.doFinal(input));
	}

	public void decryptFile(byte[] input, File output, PublicKey key)
		throws IOException, GeneralSecurityException {
		this.cipher.init(Cipher.DECRYPT_MODE, key);
		writeToFile(output, this.cipher.doFinal(input));
	}

	private void writeToFile(File output, byte[] toWrite)
			throws IllegalBlockSizeException, BadPaddingException, IOException {
		FileOutputStream fos = new FileOutputStream(output);
		fos.write(toWrite);
		fos.flush();
		fos.close();
	}

	public String encryptText(String msg, PublicKey key)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			UnsupportedEncodingException, IllegalBlockSizeException,
			BadPaddingException, InvalidKeyException {
		this.cipher.init(Cipher.ENCRYPT_MODE, key);
		return Base64.encodeBase64String(cipher.doFinal(msg.getBytes("UTF-8")));
	}

	public String decryptText(String msg, PrivateKey key)
			throws InvalidKeyException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException {
		this.cipher.init(Cipher.DECRYPT_MODE, key);
		return new String(cipher.doFinal(Base64.decodeBase64(msg)), "UTF-8");
	}

	public byte[] getFileInBytes(File f) throws IOException {
		FileInputStream fis = new FileInputStream(f);
		byte[] fbytes = new byte[(int) f.length()];
		fis.read(fbytes);
		fis.close();
		return fbytes;
	}
	
	public static Map<String, String> getPublicKeyComponents(){
		Map<String, String> publicKeys = new HashMap<String, String>();
		try {
			// getting keys
			PublicKey publicKey = getPublic("KeyPair/publicKey");
			
			RSAPublicKey key = (RSAPublicKey)publicKey;
			System.out.println(key.getModulus().toString(16));
			System.out.println(key.getPublicExponent().toString(16));
			
			
			
			publicKeys.put("module", key.getModulus().toString(16));
			publicKeys.put("exponent", key.getPublicExponent().toString(16));
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return publicKeys;
	}

	public static void main(String[] args) throws Exception {
		RSAGenerateKeysTest gk;
		try {
			// creating keys
			gk = new RSAGenerateKeysTest(1024);
			gk.createKeys();
			gk.writeToFile("KeyPair/publicKey", gk.getPublicKey().getEncoded());
			gk.writeToFile("KeyPair/privateKey", gk.getPrivateKey().getEncoded());
			
			// getting keys
			PrivateKey privateKey = getPrivate("KeyPair/privateKey");
			PublicKey publicKey = getPublic("KeyPair/publicKey");
			
			/*RSAPublicKey key = (RSAPublicKey)publicKey;
			System.out.println(key.getModulus().toString(16));
			System.out.println(key.getPublicExponent().toString(16));
			
			RSAPrivateKey key1 = (RSAPrivateKey)privateKey;
			System.out.println(key1.getModulus().toString(16));
			System.out.println(key1.getPrivateExponent().toString(16));*/
			
			String msg = "52051ecf14cc10802893c2c14fc4ea78@@@084e52342af60166789a66ccffeb0eaa@@@123456@@@1000@@@128";
			String encrypted_msg = gk.encryptText(msg, publicKey);
			System.out.println(encrypted_msg);
			String decrypted_msg = gk.decryptText(encrypted_msg, privateKey);
			System.out.println("Original Message: " + msg +
				"\nEncrypted Message: " + encrypted_msg
				+ "\nDecrypted Message: " + decrypted_msg);
			
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			System.err.println(e.getMessage());
		} catch (IOException e) {
			System.err.println(e.getMessage());
		}catch (Exception e) {
			System.err.println(e.getMessage());
		}

	}

}
