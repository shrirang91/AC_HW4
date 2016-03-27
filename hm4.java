import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.security.cert.*;

public class hm4{
		public static void main(String[] args){
			
			//initialize variables for public and private key for Raghu and CA
			String raghuCertificate = "Raghupub.cer";
			String raghuPrivateKey = "Raghupri.pfx";
			String temp = "";
			char[] raghuPassword ="raghu".toCharArray();
			String caCertificate = "Trustcenter.cer";
			
			try{
				CertificateFactory certFact = CertificateFactory.getInstance("X.509");
				
				//------------>raghu's certificate 
				System.out.println("1. -------------------Print the certificate-------------------");
			    FileInputStream raghuFIS = new FileInputStream(raghuCertificate);
			    java.security.cert.Certificate raghuC = certFact.generateCertificate(raghuFIS);
			    System.out.println(raghuC.toString());
			    
			    //------------>raghu's public key 
			    System.out.println("\n2.------------------ Print Raghu’s public and private key----------------------\n");
			    PublicKey raghuPubKey = raghuC.getPublicKey();
			    System.out.println();
			    System.out.println("PUBLIC KEY-->"+raghuPubKey.toString()+"\n");
			    
			    //------------> raghu's private key
			    KeyStore kStore = KeyStore.getInstance("pkcs12");
			    kStore.load(new FileInputStream(raghuPrivateKey),raghuPassword);
		  	  	temp = kStore.aliases().nextElement(); 
		  	  	PrivateKey raghuPriKey = (PrivateKey)kStore.getKey(temp, raghuPassword); 
		  	  	System.out.println("PRIVATE KEY-->"+javax.xml.bind.DatatypeConverter.printHexBinary(raghuPriKey.getEncoded()));
		  	  
		  	  	//-----------> CA's public key
		  	  	System.out.println("\n3.------------------- Print the public Key of Certification Authority ------------------\n");
		  	    FileInputStream caFIS = new FileInputStream(caCertificate);
			    java.security.cert.Certificate caC = certFact.generateCertificate(caFIS);
			    PublicKey caPubKey = caC.getPublicKey();
			    System.out.println(caPubKey.toString());
			    
			    //------------> Sign raghu's certificate
			    System.out.println("\n4.------------------ Print the signature on Raghu’s certificate---------------------- \n");
			    X509Certificate certificateX = (X509Certificate)raghuC;
			    System.out.println("Signature-->"+new BigInteger(certificateX.getSignature()).toString(16));
				
				//---------> encrypt the string using raghu's public key
				System.out.println("\n5. ------------------ENCRYPTION using raghu's certificate----------------");
			    String plainText = "Our names are Prajakta Belavade and Shrirang Adgaonkar.We are enrolled in CSE 539.";
	    	    System.out.println("\nTEXT TO ENCRYPT-->  "+plainText);
	    	    
	    	    //check if raghu's certificate is valid or not?
	    	    System.out.println("\nValidate Raghu's certificate:\t\t");
	    	    try{
					raghuC.verify(caPubKey);
					System.out.println("VALID");
				  }
				catch(Exception e){
					  System.out.println("INVALID");
				  }
	    	    
	    	    
	    	    Cipher c = Cipher.getInstance("RSA");
	    	    c.init(Cipher.ENCRYPT_MODE,raghuPubKey);
	            byte sm[] = c.doFinal(plainText.getBytes());
	            System.out.println("\nThe Cipher Text is: "+new String(sm));
	            
	            //---------> encrypt the string using raghu's public key
	            System.out.println("\n6. ------------------DECRYPTION using raghu's private key--------------------");
	            c.init(Cipher.DECRYPT_MODE, raghuPriKey);
	            byte[] encoder = c.doFinal(sm);
	            System.out.println("\nThe Plaintext is: "+new String(encoder, "UTF8"));
			}
			
			//------------->handling all the exceptions
			catch (Exception ex){
				System.out.println("Exception is :"+ ex);
				return;
			}
			
		}
}

	          

		
			
			
			
		