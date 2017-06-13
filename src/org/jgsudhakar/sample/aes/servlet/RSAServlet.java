package org.jgsudhakar.sample.aes.servlet;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.gson.Gson;
import com.jgsudhakar.rsa.util.RSACryptoUtil;

@WebServlet( "/rsa" )
public class RSAServlet extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		Map<String, String> rsaKeysMap = new HashMap<String, String>();
		rsaKeysMap = RSACryptoUtil.getPublicKeyComponents();
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().print(new Gson().toJson(rsaKeysMap));
    }
}
