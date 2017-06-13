/**
 * 
 */
package com.jgsudhakar.rsa.util;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

/**
 * @author sudhakar
 *
 */
public class RSACryptoUtil {


	
	//hard coded public key
	static final String PUBLIC_KEY	= "009B20A3837C0D51E0A40C68D2885D37C7C562736D98783F4E9CDFC0FFFCB5B697FDCAC9090747B5ED7AC9E8EF5B063BBBCCDD5813ED64A9746FF46BEF257A9004F6DE670309C6982D40C200DB65431B252B7C974922AF278D96827E978FDADA31E419C9FADCF8051DBAD7E73FE4A0B6E43DF40416BF0746C33261FAAA189F2013";

	static final String PRIVATE_KEY	= "009B20A3837C0D51E0A40C68D2885D37C7C562736D98783F4E9CDFC0FFFCB5B697FDCAC9090747B5ED7AC9E8EF5B063BBBCCDD5813ED64A9746FF46BEF257A9004F6DE670309C6982D40C200DB65431B252B7C974922AF278D96827E978FDADA31E419C9FADCF8051DBAD7E73FE4A0B6E43DF40416BF0746C33261FAAA189F2013#010001#7A92E7A0D53C911DB78236B1641E841CCDD264F28C2F37969E4E0EEA367C3EB30A4E595B50ED50CB3CE29DB3C370C1723B060ABA7431BDD3CB428EA6802EBFEC6DBBBF1B876913349766FB3228E95575646C259BEEAD270E2304F4E2C75FE447DCE9265E5C27F2959E435EB6F7CD7D385E4347036C7881474ED858B8E4684DC1#00E7CF77FC891256D1A0855A982CD1DA13D7752344714221277461D6778F83754791E8074FF9F69AAE3B618AF49FB43202314CC08444CE96B8F9D68803B4F477D5#00AB50ADF896BFE8C7A91E24F8BAC73DD4BAE35FE336A9268933F2E62DB42831BD819BC659164F0E74F392B145E5DDA9D50F675DCCAD19F82373D4894E2B805447#71A67B1A3A0DDEB8E9ED578C523514A933B23F7737DC072B33D91FF00051A03755A69FA72B53276512C1F1019C2719798FB8248EF4B92096520F4722221ED57D#1FEC24BED1B868F3EB7B868022ADC5C3C21F645ABE70BE918A70949BA79A65CA5E405CB1750ABE32E4C04CF02D6924A063026BE41BCD5F039C2DDA780A7B1B39#266BE6D75F7CB1D272FAF34B84B4BD883B9F3490B37CB3760B442A269C6F05B40B3A21554CC2A689E5DCCB6F26B2C151F021BD3A76F359A1A160ED067F978629";

	
	private static RSAPrivateCrtKeyParameters vprivKeyParam=null;
	
	private static void loadPrivateKeyForAdminPass() throws Exception {
		  try {
			  
			  				
			 
			  String vprivKey=PRIVATE_KEY;
			  
			  ArrayList<String> vkeyList=new ArrayList<String>();
			  StringTokenizer vstrTok=new StringTokenizer(vprivKey,"#");
			  while(vstrTok.hasMoreTokens()) {
				  vkeyList.add(vstrTok.nextToken());
			  }
			  
			  BigInteger vprivKeyMod=new BigInteger(HexStringToByteArray((String)vkeyList.get(0)));
			  BigInteger vprivKeyPublicExp=new BigInteger(HexStringToByteArray((String)vkeyList.get(1)));
			  BigInteger vprivKeyExp=new BigInteger(HexStringToByteArray((String)vkeyList.get(2)));
			  BigInteger vprivKeyP=new BigInteger(HexStringToByteArray((String)vkeyList.get(3)));
			  BigInteger vprivKeyQ=new BigInteger(HexStringToByteArray((String)vkeyList.get(4)));
			  BigInteger vprivKeyDP=new BigInteger(HexStringToByteArray((String)vkeyList.get(5)));
			  BigInteger vprivKeyDQ=new BigInteger(HexStringToByteArray((String)vkeyList.get(6)));
			  BigInteger vprivKeyQInv=new BigInteger(HexStringToByteArray((String)vkeyList.get(7)));
			  vprivKeyParam=new RSAPrivateCrtKeyParameters(vprivKeyMod,vprivKeyPublicExp,vprivKeyExp,vprivKeyP,vprivKeyQ,vprivKeyDP,vprivKeyDQ,vprivKeyQInv);
			  
			  
			  
		  } catch(Exception e) {
			  e.printStackTrace();
		  }
	  }
	
	public static byte[] HexStringToByteArray(String strHex) {
		byte bytKey[] = new byte[(strHex.length() / 2)];
		int y = 0;
		String strbyte;
		for (int x = 0; x < bytKey.length; x++) {
			strbyte = strHex.substring(y, (y + 2));
			if (strbyte.equals("FF")) {
				bytKey[x] = (byte) 0xFF;
			}
			else {
				bytKey[x] = (byte) Integer.parseInt(strbyte, 16);
			}
			y = y + 2;
		}
		return bytKey;
	}
	
	public static String decryptWebPIN(String pencSessionkey) throws Exception {
		  AsymmetricBlockCipher engine=null;
		  byte[] vinBytes,opBytes=null;
		  try { 
			  
			  loadPrivateKeyForAdminPass(); 
			  
			  engine=new RSAEngine();
			  System.out.println("pkcs coding");
			  engine = new PKCS1Encoding(engine);			  
			  engine.init(false, vprivKeyParam);
			  			  
			  
			  vinBytes=HexStringToByteArray(pencSessionkey); 
			  
			  			  
			  opBytes=engine.processBlock(vinBytes,0,vinBytes.length);
			  
			  
			  return new String(opBytes);
			  
		  } catch(Exception e) {
			  e.printStackTrace();
		  } finally {
			  vprivKeyParam=null;engine=null;
			  vinBytes=null;opBytes=null;   
		  }
		  
		  return null;
	  }
	
	public static Map<String, String> getPublicKeyComponents(){
		Map<String, String> publicKeys = new HashMap<String, String>();
		publicKeys.put("module", PUBLIC_KEY);
		publicKeys.put("exponent", "010001");
		return publicKeys;
	}
	
}
