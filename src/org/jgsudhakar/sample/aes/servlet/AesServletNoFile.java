package org.jgsudhakar.sample.aes.servlet;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jgsudhakar.sample.aes.AesUtil;

import com.jgsudhakar.rsa.util.RSACryptoUtil;

@WebServlet( "/aesnofile" )
public class AesServletNoFile extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
        int keySize= 0,iterationCount=0;
        String salt ="",passphrase="",iv="",plainTextArea="",secretKeys="",sampleText="";
        
        // getting the  input parameters
        sampleText = request.getParameter("sampleText");
        
        plainTextArea = request.getParameter("plainTextArea");
		
        // getting the secret keys values and decrypting with RSA 
        secretKeys = request.getParameter("secretKeys");
        
        try {
			secretKeys = RSACryptoUtil.decryptWebPIN(secretKeys);
		} catch (Exception e) {
			e.printStackTrace();
		}
        
        String[] dataAry = secretKeys.split("@@@"); 
		keySize = Integer.valueOf(dataAry[4]);
		iterationCount = Integer.valueOf(dataAry[3]);
		salt = String.valueOf(dataAry[0]);
		iv = String.valueOf(dataAry[1]);
		passphrase = String.valueOf(dataAry[2]);
		
		System.out.println(plainTextArea);
		System.out.println(sampleText);
		
        AesUtil aesUtil = new AesUtil(keySize, iterationCount);
        sampleText = aesUtil.decrypt(salt, iv, passphrase, sampleText);
        plainTextArea = aesUtil.decrypt(salt, iv, passphrase, plainTextArea);
        
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().print(plainTextArea+sampleText);
    }
}
