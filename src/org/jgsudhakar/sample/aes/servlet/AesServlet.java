package org.jgsudhakar.sample.aes.servlet;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.io.FileUtils;
import org.jgsudhakar.sample.aes.AesUtil;

import com.jgsudhakar.rsa.util.RSACryptoUtil;

@WebServlet( "/aes" )
public class AesServlet extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	// location to store file uploaded
    private static final String UPLOAD_DIRECTORY = "image_upload";
    // upload settings
    private static final int MEMORY_THRESHOLD = 1024 * 1024 * 3;  // 3MB
//    private static final int MAX_FILE_SIZE = 1024 * 1024 * 40; // 40MB
    //private static final int MAX_REQUEST_SIZE = 1024 * 1024 * 50; // 50MB

	@Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		 // configures upload settings
        DiskFileItemFactory factory = new DiskFileItemFactory();
        // sets memory threshold - beyond which files are stored in disk
        factory.setSizeThreshold(MEMORY_THRESHOLD);
        // sets temporary location to store files
        factory.setRepository(new File(System.getProperty("java.io.tmpdir")));

        ServletFileUpload upload = new ServletFileUpload(factory);
        
        
        // constructs the directory path to store upload file
        // this path is relative to application's directory
        String uploadPath = getServletContext().getRealPath("") + File.separator + UPLOAD_DIRECTORY;
        // creates the directory if it does not exist
        File uploadDir = new File(uploadPath);
        if (!uploadDir.exists()) {
            uploadDir.mkdir();
        }
        int keySize= 0,iterationCount=0;
        String salt ="",passphrase="",ciphertext="",iv="",fileData="",Cdata="",plainTextArea1="";
        List<FileItem> formItems;
        String fileName ="";
		try {
			formItems = upload.parseRequest(request);
			for (FileItem item : formItems) {
			    // processes only fields that are not form fields
			    if (!item.isFormField()) {
			        fileName = new File(item.getName()).getName();
			        try {
						fileData = item.getString();
					} catch (Exception e) {
						e.printStackTrace();
					}
			    } else {
			        //here...
			        String fieldname = item.getFieldName();
			        String fieldvalue = item.getString();
			        
			        if (fieldname.equals("passphrase")) {
			        	passphrase = fieldvalue;
			        } else if (fieldname.equals("plainTextArea")) {
			        	ciphertext = fieldvalue;
			        }else if (fieldname.equals("plainTextArea1")) {
			        	plainTextArea1 = fieldvalue;
			        }else if (fieldname.equals("secretKeys")) {
			        	Cdata = fieldvalue;
			        }
			    }
			}
		} catch (FileUploadException e) {
			e.printStackTrace();
		}
        
		try {
			System.out.println(Cdata);
			String keysData = RSACryptoUtil.decryptWebPIN(Cdata);
			System.out.println(keysData);
			String[] dataAry = keysData.split("@@@"); 
			keySize = Integer.valueOf(dataAry[4]);
			iterationCount = Integer.valueOf(dataAry[3]);
			salt = String.valueOf(dataAry[0]);
			iv = String.valueOf(dataAry[1]);
			passphrase = String.valueOf(dataAry[2]);
		}catch (Exception e) {
	        response.setStatus(HttpServletResponse.SC_OK);
	        response.getWriter().print("Security keys tampered!");
		}
				
	        AesUtil aesUtil = new AesUtil(keySize, iterationCount);
	        String plaintext = aesUtil.decrypt(salt, iv, passphrase, ciphertext);
	        String fileDataIs = aesUtil.decrypt(salt, iv, passphrase, fileData);
	        String replaceStr = "";
	        if(fileName.endsWith(".txt"))
	        	replaceStr ="data:text/plain;base64,";
	        else if(fileName.endsWith(".js"))
	        	replaceStr ="data:application/javascript;base64,";
	        else if(fileName.endsWith(".jpeg") || fileName.endsWith(".jpg")  )
	        	replaceStr="data:image/jpeg;base64,";
	        else if(fileName.endsWith(".png"))
	        	replaceStr="data:image/png;base64,";
	        
	        
	        if(!fileName.endsWith(".jpeg") && !fileName.endsWith(".jpg") && !fileName.endsWith(".png"))
	        FileUtils.writeStringToFile(new File(uploadPath+File.separator+fileName), new String(Base64.decodeBase64(fileDataIs.replaceAll(replaceStr, "").getBytes())));
	        else{
	        	byte[] data = Base64.decodeBase64(fileDataIs.replaceAll(replaceStr, ""));
	        try (OutputStream stream = new FileOutputStream("D:/sudhakar/eclipse-jee-luna-R-win32-x86_64/eclipse/workspace/.metadata/.plugins/org.eclipse.wst.server.core/tmp0/wtpwebapps/Encryption/image_upload/"+fileName)) {
	        		stream.write(data);
	        	}
	        }
        
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().print(plaintext+":"+plainTextArea1);
    }
}
