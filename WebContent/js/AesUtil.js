var data;
var rsaExponent ="";
var rsaModules ="";
var iterationCount = 1000;
var keySize = 128;
var passphrase = "";
var AesUtil = function(keySize, iterationCount) {
  this.keySize = keySize / 32;
  this.iterationCount = iterationCount;
};

AesUtil.prototype.generateKey = function(salt, passPhrase) {
  var key = CryptoJS.PBKDF2(
      passPhrase, 
      CryptoJS.enc.Hex.parse(salt),
      { keySize: this.keySize, iterations: this.iterationCount });
  return key;
};

AesUtil.prototype.encrypt = function(salt, iv, passPhrase, plainText) {
  var key = this.generateKey(salt, passPhrase);
  var encrypted = CryptoJS.AES.encrypt(
      plainText,
      key,
      { iv: CryptoJS.enc.Hex.parse(iv) });
  return encrypted.ciphertext.toString(CryptoJS.enc.Base64);
};

AesUtil.prototype.decrypt = function(salt, iv, passPhrase, cipherText) {
  var key = this.generateKey(salt, passPhrase);
  var cipherParams = CryptoJS.lib.CipherParams.create({
    ciphertext: CryptoJS.enc.Base64.parse(cipherText)
  });
  var decrypted = CryptoJS.AES.decrypt(
      cipherParams,
      key,
      { iv: CryptoJS.enc.Hex.parse(iv) });
  return decrypted.toString(CryptoJS.enc.Utf8);
};


function sendRequest(curElem){
	var body = $('body');
	 var plaintext = $('#plaintext').val();
	 passphrase = $('#passphrase').val();
    var fileData = document.getElementById('fileData').files;
    if (!fileData.length) {
        alert('Please select a file!');
        return;
      }
    
    var iv = CryptoJS.lib.WordArray.random(128/8).toString(CryptoJS.enc.Hex);
    var salt = CryptoJS.lib.WordArray.random(128/8).toString(CryptoJS.enc.Hex);
    
    var aesUtil = new AesUtil(keySize, iterationCount);
    
    var ciphertext = aesUtil.encrypt(salt, iv, passphrase, plaintext);
    
    var file = fileData[0];
    
    var reader = new FileReader();
    
    
    // load RSA Keys from server
    getRSAPublicKeys();
    
    loadFIle(reader, file,body,salt,iv,passphrase,aesUtil,ciphertext,iterationCount,keySize);
    
    
}

function sendRequestNoFile(curElem){
   
   callAjaxWithoutMultipartData(curElem);
   
}

function sendRequestwithFile(curElem){
	var plaintext = $('#plaintext').val();
	 passphrase = $('#passphrase').val();
   var fileData = document.getElementById('fileData').files;
   if (!fileData.length) {
       alert('Please select a file!');
       return;
     }
   
   var iv = CryptoJS.lib.WordArray.random(128/8).toString(CryptoJS.enc.Hex);
   var salt = CryptoJS.lib.WordArray.random(128/8).toString(CryptoJS.enc.Hex);
   
   var aesUtil = new AesUtil(keySize, iterationCount);
   
   var file = fileData[0];
   
   var reader = new FileReader();
   
    callAjaxMultipartData(reader, file,salt,iv,passphrase,aesUtil,iterationCount,keySize,curElem);
}

function getRSAPublicKeys() {
	 $.ajax({ 
		 	async: false ,
	    	url: './rsa',
	        type: 'POST',
	        data : "",
	        dataType : "json",
	        success: function(responseText) {
	        	rsaExponent = responseText.exponent;
	        	rsaModules = responseText.module;
	        }
		 });
}

/**
 * encrypting the form data with AES before submission ignoring the type submit and image and file 
 * as non multipart form will not be having those. 
 * Note : If there is any multipart data do not call this function
 * */
function callAjaxWithoutMultipartData(curElem){
	// getting the form object
	var formData =   $(curElem).closest("form");
	// encrypting the form data with AES before submission ignoring the type submit and image and file 
	// as non multipart form will not be having those. 
    var $inputs = formData.find("input,textarea,select").not("[type=submit],[type=button],[type=image],[type=file]");
    var iv = CryptoJS.lib.WordArray.random(128/8).toString(CryptoJS.enc.Hex);
    var salt = CryptoJS.lib.WordArray.random(128/8).toString(CryptoJS.enc.Hex);
    var aesUtil = new AesUtil(keySize, iterationCount);
    var jsonData = {};
    $inputs.each(function (i, el) {
    	jsonData[el.name] = aesUtil.encrypt(salt, iv, passphrase, $(el).val());
   });
    // finally appending the secret keys in the formdata
    var Cdata = encryptSecretKeysWithRSA(salt, iv, passphrase, iterationCount, keySize, "@@@");
    jsonData['secretKeys'] = Cdata;
    $.ajax({ 
	 	async: false ,
    	url: "./aesnofile",
        type: "POST",
        data : jsonData,
        dataType : "html",
        success: function(responseText) {
        	alert(responseText);
        }
});
}

/**
 * encrypting the form data with AES before submission here we will reading the files or image data  and only ignoring the type submit 
 * Note : If there is any multipart data only call this function otherwise call callAjaxWithoutMultipartData
 * */
function callAjaxMultipartData(reader, file,salt,iv,passphrase,aesUtil,iterationCount,keySize,curElem) {
		reader.onloadstart = function(e){
			console.log('in load onloadstart ');
		};
		
		reader.onprogress = function(e){
			console.log('in load onprogress ');
		};
		
		
		reader.onabort = function(e){
			console.log('in load onabort ');
		};
		
		reader.onerror = function(e){
			console.log('in load onerror ');
		};
		
	// Encrypt the file!
		reader.onload = function(e){
			console.log('in load onload ');
			// Use the CryptoJS library and the AES cypher to encrypt the 
			// contents of the file, held in e.target.result, with the password
			data =  aesUtil.encrypt(salt, iv, passphrase ,e.target.result);
			var formData = new FormData();
			formData.append('file', new File([new Blob([data])], file.name));
			
			var encrptedSecretKeyData = encryptSecretKeysWithRSA(salt, iv, passphrase, iterationCount, keySize, "@@@");
			
			formData.append('secretKeys',encrptedSecretKeyData);
			
			
			// getting the form object
			var formDataIs =   $(curElem).closest("form");
			// encrypting the form data with AES before submission ignoring the type submit and image and file 
			// as non multipart form will not be having those. 
		    var $inputs = formDataIs.find("input,textarea,select").not("[type=submit],[type=button],[type=image],[type=file]");
		    $inputs.each(function (i, el) {
		    	if(el.type != "file")
		    	formData.append(el.name,aesUtil.encrypt(salt, iv, passphrase, $(el).val()));
		   });
			
			 $.ajax({ 
		    	url: './aes',
		        type: 'POST',
		        data : formData,
		       processData: false,
		       contentType: false,
		        dataType : "html",
		        success: function(responseText) {
		        	 alert('Plaintext: ' + responseText);
		        }
			 });
		};
		
		reader.onloadend = function(e){
			console.log('in load onloadend ');
		};
		
		reader.readAsDataURL(file);

}

function readAndEncryptFile(fileObj,formData,salt, iv, passphrase,aesUtil){
	
	var reader = new FileReader();
	reader.onloadstart = function(e){
			console.log('in load onloadstart ');
		};
		
		reader.onprogress = function(e){
			console.log('in load onprogress ');
		};
		
		reader.onabort = function(e){
			console.log('in load onabort ');
		};
		
		reader.onerror = function(e){
			console.log('in load onerror ');
		};
		// Encrypt the file!
		reader.onload = function(e){
			console.log('in load onload ');
			var data =  aesUtil.encrypt(salt, iv, passphrase ,e.target.result);
			formData[fileObj.name] = new File([new Blob([data])], fileObj.files[0].name);
			return formData;
		};
		
		reader.onloadend = function(e){
			console.log('in load onloadend ');
		};
			
		reader.readAsDataURL(fileObj.files[0]);
}

/**
 * Encrypting the secreat keys with RSA algorithm , the same need to decrypt in server side before using the keys. 
 */
function encryptSecretKeysWithRSA(salt,iv,passphrase,iterationCount,keySize,splitter){
	var rsaExponent= "";
	var rsaModules = "";
	// getting the RSA keys from server
	 $.ajax({ 
		 	async: false ,
	    	url: './rsa',
	        type: 'POST',
	        data : "",
	        dataType : "json",
	        success: function(responseText) {
	        	rsaExponent = responseText.exponent;
	        	rsaModules = responseText.module;
	        }
		 });
	 
	 if(rsaExponent.trim() == '' || rsaExponent == undefined || rsaModules.trim() == '' || rsaModules == undefined ){
		 console.log('RSA Keys not found');
		 alert("Invalid RSA Keys!");
		 return false;
	 }else{
		 var secretKeysData = salt+splitter+iv+splitter+passphrase+splitter+iterationCount+splitter+keySize;
		 return encrypt_rsa(secretKeysData, rsaExponent , rsaModules, '');
	 }
}

/**
 * Reading happens asynchronously. So we need to provide a custom onload callback that defines what should happen when the read completes:
 * */
function readFile(file, onLoadCallback){
    var reader = new FileReader();
    reader.onload = onLoadCallback;
    reader.readAsDataURL(file);
}



