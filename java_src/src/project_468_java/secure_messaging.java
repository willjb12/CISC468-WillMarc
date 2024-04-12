package project_468_java;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.math.BigInteger;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.jmdns.*;
import javax.net.ssl.*;
import javax.security.auth.x500.X500Principal;
import java.util.concurrent.ThreadLocalRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.NoSuchElementException;
import org.bouncycastle.*;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.*;

import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;



public class secure_messaging {
	public static boolean receiveFile(String id, byte[] file) {
		System.out.println("Recevied file from: "+id);
		
		String projectDirectory = System.getProperty("user.dir"); // Get the project directory
		String contactDir = projectDirectory + File.separator + "lib" + File.separator + "inbox"  +File.separator + id +File.separator;
		File contactDirFile = new File(contactDir);
		int fileNumber = 1;
		File[] files = contactDirFile.listFiles();
		for (File fileI : files) {
			String fileIname = fileI.getName();
			try {
				fileIname = fileIname.substring(4);
				int fileNumI = Integer.valueOf(fileIname);
				if (fileNumI >= fileNumber) {
					fileNumber = fileNumI+1;
				}
			}catch(Exception e) {
				;
			}
		}
		String newFilePath=(contactDir+"file"+fileNumber);
		try {
            Files.write(Paths.get(newFilePath), file);
            System.out.println("File has been written successfully");
        } catch (IOException e) {
            System.out.println("An error occurred while writing the file.");
            e.printStackTrace();
        }
				
	
		
		return true;
	}
	public static boolean revokeMyself() throws IOException {
		//make directory with name as 
		LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss");
        String formattedTimestamp = now.format(formatter);
        
        String projectDirectory = System.getProperty("user.dir");
		String revokedCertDirPath = (projectDirectory+File.separator+"lib"+File.separator+"oldCerts"+File.separator+formattedTimestamp+File.separator);
		
		File revokedCertDir = new File(revokedCertDirPath);
		if (revokedCertDir.exists()) {
			System.out.println("Error making revoked cert dir: Exists");
		}
		else {
			revokedCertDir.mkdirs();
		}
		
		
		//inside put textfile with list of all contacts with this time stamp of certificate
		String toUpdatePath = (revokedCertDirPath+"toUpdate.txt"+File.separator);
		File toUpdate = new File(toUpdatePath);
		toUpdate.createNewFile();
		String contactsFilePath = System.getProperty("user.dir") + File.separator + "lib" + File.separator + "contacts.txt";
		
        // Create a Path object representing the file
        Path conPath = Paths.get(contactsFilePath);
            
        // Read all lines from the file into a List<String>
        List<String> lines = Files.readAllLines(conPath);
            // Print each line
        String[] ids = new String[lines.size()];
        int i = 0;
        for (String line : lines) {
        	String[] contact = line.split(" ");
        	ids[i] = contact[0];
        	i++;
        }
        
        try (BufferedWriter toUpdateWriter = new BufferedWriter(new FileWriter(toUpdatePath, false))) { // Set true for append mode
            for (String id : ids) {
                toUpdateWriter.write(id);
                toUpdateWriter.newLine(); // Adds a newline character
            }
            
        } catch (IOException e) {
            // Handle possible I/O errors
            e.printStackTrace();
        }
        
		//store current certificate 
        String oldCertPath = (revokedCertDirPath+"oldCert.txt"+File.separator);
        File oldCert = new File(oldCertPath);
        oldCert.createNewFile();
        
        String storedCertPath = projectDirectory + File.separator + "lib" + File.separator + "cert.txt";
        fileCopy(storedCertPath, oldCertPath);
        

    
        
        //store keys
        String oldPrivPath = (revokedCertDirPath+"oldPriv.txt"+File.separator);
        File oldPriv = new File(oldPrivPath);
        oldPriv.createNewFile();
        
        String storedPrivPath = projectDirectory + File.separator + "lib" + File.separator + "privatekey.txt";
        fileCopy(storedPrivPath, oldPrivPath);
        
        String oldPubPath = (revokedCertDirPath+"oldPub.txt"+File.separator);
        File oldPub = new File(oldPubPath);
        oldPub.createNewFile();
        
        String storedPubPath = projectDirectory + File.separator + "lib" + File.separator + "publickey.txt";
        fileCopy(storedPubPath, oldPubPath);
		
        clearFile(storedCertPath);
        clearFile(storedPubPath);
        clearFile(storedPrivPath);
        
		
	
		
		return true;
	}
	public static void clearFile(String filePath) throws IOException {
		FileWriter fw = new FileWriter(filePath);
		fw.close();
	}
	public static boolean revokeContact(String id, X509Certificate newCert) throws CertificateEncodingException {
		String projectDirectory = System.getProperty("user.dir"); // Get the project directory
		String certDirFilePath = projectDirectory + File.separator + "lib" + File.separator + "certs"+File.separator;

		
		try {
            // Create a File object representing the file
            File file = new File(certDirFilePath+id+".txt");
            
            // Check if the file already exists
            if (file.exists()) {
            
                

            	
            	byte[] certBytes = newCert.getEncoded();


            	FileOutputStream certWriter = new FileOutputStream(certDirFilePath+id+".txt");
            	certWriter.write(certBytes);
            	certWriter.close();
            	
            	String contactsFilePath = projectDirectory + File.separator + "lib" + File.separator +"contacts.txt";
            	List<String> newLines = new ArrayList<>();

            	BufferedReader br = new BufferedReader(new FileReader(contactsFilePath));
            	String line;
            	while ((line = br.readLine()) != null) {
            		if(line.contains(" OLD")) {
            			line = line.replaceAll(" OLD", " NEW");
            		}
            		
            		newLines.add(line);

            	}
            	br.close();

            	BufferedWriter bw = new BufferedWriter(new FileWriter(contactsFilePath));
            	for (String newLine : newLines) {
            		
            		bw.write(newLine);
            		bw.newLine();
            	}
            	
            	bw.close();
            	
            	return true;
            } else {
            	System.out.println("File doesnt exist.");
            	return false;
            }
        } catch (IOException e) {
            // Handle any IOException that might occur
            e.printStackTrace();
            return false;
        }
		
		
		
		
		
	}
	public static void updateContacts(JmDNS jmdns) throws IOException, KeyManagementException, CertificateException, NoSuchAlgorithmException, InterruptedException {
		//find online contacts
		//
		queryResults results = query(jmdns);
		ArrayList<String> idsOnline = results.getInfos();
		ArrayList<String> names = results.getNames();
		ArrayList<InetAddress[]> addresses = results.getAddresses();
		//for directory in oldcerts
		File oldCerts = new File(System.getProperty("user.dir") + File.separator + "lib" + File.separator + "oldCerts" + File.separator);
		File[] outerlistOfFiles = oldCerts.listFiles();
		if (outerlistOfFiles.length == 0){
			;
		}
		else if (outerlistOfFiles != null) {
			for (File outerfile : outerlistOfFiles) {
				String timestamp = outerfile.getName();
				String outerDirPath = (System.getProperty("user.dir") + File.separator + "lib" + File.separator + "oldCerts" + File.separator + timestamp + File.separator);
				File toUpdateFile = new File(outerDirPath+"toUpdate.txt");




				List<String> idsToUpdate = Files.readAllLines(toUpdateFile.toPath());
				if (idsToUpdate.size() == 0) {
					
					File[] files2Delete = outerfile.listFiles();
					for (File del : files2Delete) {
						del.delete();
					}
					outerfile.delete();
					
				}	
				else {

					for (String id : idsToUpdate) {

						for (int i = 0; i < idsOnline.size();i++) {


							if (idsOnline.get(i).equals(id)) {


								String privkeyFilePath = outerDirPath+"oldPriv.txt"; 
								String pubkeyFilePath = outerDirPath+"oldPub.txt"; 
								String certPath = outerDirPath+"oldCert.txt"; 
								String ipString = addresses.get(i)[0].toString().replaceAll("/","");
								int Port = 6969;
								SSLSocket revocationClient = createCustomTLSSocket(privkeyFilePath,pubkeyFilePath,certPath,ipString,Port);
								SendRevocationSignal(revocationClient);
								removeLine(toUpdateFile.toPath().toString(),id);
							}

						}

					}
					//remake inner file
				}

			}
		}
		else {
			System.out.println("old cert directory is not a directory");
		}
			
	}
	public static void removeLine(String filePath, String lineToRemove) {
        List<String> lines = new ArrayList<>();
        
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.equals(lineToRemove)) {
                	
                }
                else {
                	lines.add(line);
                }
                
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        try (BufferedWriter bw = new BufferedWriter(new FileWriter(filePath))) {
            for (String line : lines) {
                bw.write(line);
                bw.newLine();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
	public static void SendRevocationSignal(SSLSocket socketClient) throws IOException {
		socketClient.startHandshake();
		PrintWriter out = null;
		BufferedReader in = null;
		
		out = new PrintWriter(

				new BufferedWriter(

						new OutputStreamWriter(

								socketClient.getOutputStream())));
		in = new BufferedReader(

				new InputStreamReader(

						socketClient.getInputStream()));
		


		
			while (true) {
			
				
				char message = '\u0005';
				out.println(message);
				out.flush();
			
				if(message == ('\u0007')) {
					String certFilePath = System.getProperty("user.dir") + File.separator + "lib" + File.separator + "cert.txt";	
					try {
						X509Certificate updatedCert = getCertificate(certFilePath);
						String updatedCertPEM = convertDerToPem(updatedCert.getEncoded());
						
						out.println(updatedCertPEM);
						out.flush();
						
						Thread.sleep(1000);
						break;
					} catch (Exception e) {
						// TODO Auto-generated catch block
						System.out.println("Error retrieving certificate");
						break;
					}
					
					
				}

			


		}
			
		if (socketClient != null) {
			System.out.println("[TLS_CLIENT] Closed revocation connection");
			socketClient.close();

		}

		if (out != null) {

			out.close();

		}

		if (in != null) {

			in.close();
		}
	}
	public static SSLSocket createCustomTLSSocket(String privkeyFilePath, String pubkeyFilePath, String certPath, String ipString, int Port) throws CertificateException, IOException, NoSuchAlgorithmException, KeyManagementException {

		X509Certificate cert = getCertificate(certPath);
		byte[][] keysBytes = null;
		File pubkeyFile = new File(pubkeyFilePath);
		File privkeyFile = new File(privkeyFilePath);

		try {
			keysBytes = getKeys(pubkeyFilePath,privkeyFilePath);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


		
		PublicKey publicKey = null;
		PrivateKey privateKey = null;
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");

			X509EncodedKeySpec keySpecPub = new X509EncodedKeySpec(keysBytes[0]);
			publicKey = keyFactory.generatePublic(keySpecPub);

			PKCS8EncodedKeySpec keySpecPriv = new PKCS8EncodedKeySpec(keysBytes[1]);
			privateKey = keyFactory.generatePrivate(keySpecPriv);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		TrustManager[] trustAllCerts = new TrustManager[]{
				new X509TrustManager() {
					public X509Certificate[] getAcceptedIssuers() {
						return new X509Certificate[0];
					}

					public void checkClientTrusted(X509Certificate[] certs, String authType) throws CertificateException {
						boolean certCheck;
						if (certs.length == 0) {
							throw new CertificateException("Not trusted Client. no cert provided");
							
						}
						else if (certs.length > 1) {
							throw new CertificateException("Not trusted Client. more than one cert provided");
							
						}
						else {
							try {
								certCheck = verifyPeerCert(certs[0]);
								if (certCheck ==true){
	
									return;
								}
								else {
									throw new CertificateException("Not trusted Client. cert verification vfailed");
								}
							} catch (CertificateException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
							
						}
						
						
					}

					public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException {
						
						boolean certCheck;
						if (certs.length == 0) {
							throw new CertificateException("Not trusted server. no cert provided");
							
						}
						else if (certs.length > 1) {
							throw new CertificateException("Not trusted server. more than one cert provided");
							
						}
						else {
							try {
								certCheck = verifyPeerCert(certs[0]);
								if (certCheck ==true){
		
									return;
								}
								else {
									throw new CertificateException("Not trusted server. cert verification vfailed");
								}
							} catch (CertificateException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
							
						}
					}
				}
		};
		KeyManager[] keyManagers = { new CustomKeyManager(privateKey, cert) };
		
		SSLContext sslContext = SSLContext.getInstance("TLS");

		sslContext.init(keyManagers, trustAllCerts, new SecureRandom());
		SSLParameters params = null;
		params = sslContext.getDefaultSSLParameters();
		params.setNeedClientAuth(true);
		params.setWantClientAuth(true);
		params.setProtocols(new String[] {"TLSv1.3"});
		params.setCipherSuites(new String[]{"TLS_AES_128_GCM_SHA256"});
		params.setEndpointIdentificationAlgorithm(null);
		SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
		SSLSocket socketTLSClient = (SSLSocket) sslSocketFactory.createSocket(ipString, Port);
		socketTLSClient.setEnabledProtocols(new String[] {"TLSv1.3"});
		socketTLSClient.setEnabledCipherSuites(new String[]{"TLS_AES_128_GCM_SHA256"});
		socketTLSClient.setEnabledProtocols(new String[] {"TLSv1.3"});
		socketTLSClient.setEnabledCipherSuites(new String[]{"TLS_AES_128_GCM_SHA256"});
		socketTLSClient.setNeedClientAuth(true);
		socketTLSClient.setWantClientAuth(true);
		
		return socketTLSClient;
	}
	
	public static void fileCopy (String sourceFilePath, String destinationFilePath) {

        FileInputStream inputStream = null;
        FileOutputStream outputStream = null;

        try {
            inputStream = new FileInputStream(sourceFilePath);
            outputStream = new FileOutputStream(destinationFilePath);

            // Buffer size can be adjusted according to your needs
            byte[] buffer = new byte[4096];
            int length;

            // Read from the source file and write to the destination file
            while ((length = inputStream.read(buffer)) > 0) {
                outputStream.write(buffer, 0, length);
            }

       
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            // Close the streams to free up resources
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (outputStream != null) {
                try {
                    outputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
	}
	public static void readMessages(String id,String hostname, String password) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
		System.out.println("Messages from "+hostname.replaceFirst("CN=", "")+"[ID: "+id+"]:");
		String projectDirectory = System.getProperty("user.dir"); // Get the project directory
		String inboxTextFilePath = projectDirectory + File.separator + "lib" + File.separator + "inbox"  +File.separator + id +File.separator +id+".txt";
		String contactsFilePath = System.getProperty("user.dir") + File.separator + "lib" + File.separator + "contacts.txt";
		boolean contactNew = false;
		try {
            // Create a Path object representing the file
            Path path = Paths.get(contactsFilePath);
            
            // Read all lines from the file into a List<String>
            List<String> lines = Files.readAllLines(path);
            
            // Print each line
            for (String line : lines) {
            	String[] contact = line.split(" ");
                if ((contact[0].equals(id)) && (contact[1].equals(hostname))) {
                	if (contact[2].equals("NEW")) {
                		System.out.println("WARNING: This contact has revoked and replaced their key-pair/certificate since you have added them.");
                	}
                	
                	
                }
            }
        } catch (IOException e) {
            // Handle any IOException that might occur
            e.printStackTrace();
        }
		
		try (BufferedReader br = new BufferedReader(new FileReader(inboxTextFilePath))) {
            String line;
            // Read each line from the file until reaching the end
            while ((line = br.readLine()) != null) {
                String[] arrayLine = line.split(" ");
                String message = decrypt(arrayLine[2],password);
                System.out.println("["+arrayLine[1]+"] "+message);
            }
         
        } catch (IOException e) {
            e.printStackTrace(); // Handle any IO exceptions (e.g., file not found)
        }
		
		
	}
	
	
	public static String decrypt(String encryptedString, String password) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		PBEKeySpec spec = new PBEKeySpec(password.toCharArray(),new byte[1],65536,128);
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		SecretKey secretKey = factory.generateSecret(spec);
		SecretKeySpec key = new SecretKeySpec(secretKey.getEncoded(), "AES");
		
		byte[] iv = new byte[cipher.getBlockSize()];
		GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
		
		cipher.init(Cipher.DECRYPT_MODE, key,gcmParameterSpec);
		
		byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedString));
        String decryptedString = new String(decryptedBytes, StandardCharsets.UTF_8);
		
		return decryptedString;
	}
	public static String encrypt (String message, String password) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		PBEKeySpec spec = new PBEKeySpec(password.toCharArray(),new byte[1],65536,128);
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		SecretKey secretKey = factory.generateSecret(spec);
		SecretKeySpec key = new SecretKeySpec(secretKey.getEncoded(), "AES");
		
		byte[] iv = new byte[cipher.getBlockSize()];
		GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
		
		cipher.init(Cipher.ENCRYPT_MODE, key,gcmParameterSpec);
		
		byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
		String encryptedString = Base64.getEncoder().encodeToString(encryptedBytes);
	
		
		return encryptedString;
	}
	public static boolean storeFile (File file) {
		return true;
	}
	public static boolean storeMessage(String message, String id) throws IOException {
		String projectDirectory = System.getProperty("user.dir"); // Get the project directory
		String inboxTextFilePath = projectDirectory + File.separator + "lib" + File.separator + "inbox"  +File.separator + id +File.separator +id+".txt";
		FileWriter fileWriter = new FileWriter(inboxTextFilePath,true);
		BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
		bufferedWriter.write(id+" "+LocalDate.now().toString()+" "+message+"\n");
		bufferedWriter.close();
				
		return true;
	}
	public static boolean verifyPeerCert(X509Certificate cert) throws CertificateException, IOException {
		boolean peerCertGood = false;
		String hostname = cert.getSubjectX500Principal().toString();
		Collection<List<?>> SANS = cert.getSubjectAlternativeNames();
		if (SANS == null) {
			System.out.println("[TLS_CONNECTION_ERROR] Peer has no SAN");
			return peerCertGood;
		}else {
			List<?> idList = (List<?>) SANS.toArray()[0];
			String id = (String) idList.get(1);
			if ((findContact(id,hostname) == true) &&(findCert(cert) == true)){
				peerCertGood = true;
			}
		}
		return peerCertGood;
	}
	public static boolean findCert(X509Certificate cert) throws IOException, CertificateException {
		boolean foundCert = false;
		String id = null;
		Collection<List<?>> SANS = cert.getSubjectAlternativeNames();
		if (SANS == null) {
			System.out.println("[TLS_CONNECTION_ERROR] Peer has no SAN");
			return foundCert;
		}else {
			List<?> idList = (List<?>) SANS.toArray()[0];
			id = (String) idList.get(1);
			
		}
		String projectDirectory = System.getProperty("user.dir"); // Get the project directory
		String certDirFilePath = projectDirectory + File.separator + "lib" + File.separator + "certs"+File.separator;;
		File file = new File(certDirFilePath+id+".txt");
		if (file.exists()) {
			FileInputStream certReader;
			try {
				certReader = new FileInputStream(certDirFilePath+id+".txt");
				ByteArrayOutputStream certByteArrayOutputStream = new ByteArrayOutputStream();
				byte[] buffer = new byte[4096]; // You can adjust the buffer size as needed

				int bytesRead;
				while ((bytesRead = certReader.read(buffer)) != -1) {
					certByteArrayOutputStream.write(buffer, 0, bytesRead);
				}
				byte[] certBytes = certByteArrayOutputStream.toByteArray();
				certReader.close();


				CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
				X509Certificate storedCert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certBytes));
				if (cert.equals(storedCert)) {
					foundCert = true;

				}
				
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				System.out.println("[TLS_CONNECTION_ERROR] Could not find cert stored under given id");
				return foundCert;
			}
			
            
        }
		else {
			System.out.println("[TLS_CONNECTION_ERROR] Could not find cert stored under given id");
		}
		
		return foundCert;
	}
	public static boolean findContact(String id, String hostname) {
		String contactsFilePath = System.getProperty("user.dir") + File.separator + "lib" + File.separator + "contacts.txt";
		boolean foundContact = false;
		try {
            // Create a Path object representing the file
            Path path = Paths.get(contactsFilePath);
            
            // Read all lines from the file into a List<String>
            List<String> lines = Files.readAllLines(path);
            
            // Print each line
            for (String line : lines) {
            	String[] contact = line.split(" ");
                if ((contact[0].equals(id)) && (contact[1].equals(hostname))) {
                	foundContact  = true;
                	
                }
            }
        } catch (IOException e) {
            // Handle any IOException that might occur
            e.printStackTrace();
        }
		if (foundContact == false) {
			System.out.println("[TLS_CONNECTION_ERROR] Could not find "+hostname+" "+id+" in contacts");
		}
		return foundContact;
	}
	public static boolean storeCert(X509Certificate cert,String id) throws CertificateEncodingException{
		String projectDirectory = System.getProperty("user.dir"); // Get the project directory
		String certDirFilePath = projectDirectory + File.separator + "lib" + File.separator + "certs"+File.separator;;

		
		try {
            // Create a File object representing the file
            File file = new File(certDirFilePath+id+".txt");
            
            // Check if the file already exists
            if (file.exists()) {
                System.out.println("Error storing certificate: File already exists.");
                return false;
            } else {
                // Create the file
                boolean created = file.createNewFile();
                
                if (created) {
                  
                    byte[] certBytes = cert.getEncoded();

            		
            		FileOutputStream certWriter = new FileOutputStream(certDirFilePath+id+".txt");
            		certWriter.write(certBytes);
            		certWriter.close();
                    
                    return true;
                } else {
                    System.out.println("Failed to create the file.");
                    return false;
                }
            }
        } catch (IOException e) {
            // Handle any IOException that might occur
            e.printStackTrace();
            return false;
        }
		
    }
	
	public static boolean checkIDNew(String id) {
		String contactsFilePath = System.getProperty("user.dir") + File.separator + "lib" + File.separator + "contacts.txt";
		boolean newContact = true;
		try {
            // Create a Path object representing the file
            Path path = Paths.get(contactsFilePath);
            
            // Read all lines from the file into a List<String>
            List<String> lines = Files.readAllLines(path);
            
            // Print each line
            for (String line : lines) {
            	String[] contact = line.split(" ");
                if (contact[0].equals(id)) {
                	newContact = false;
                	
                }
            }
        } catch (IOException e) {
            // Handle any IOException that might occur
            e.printStackTrace();
        }
		return newContact;
	}
	public static boolean addToContacts(String id, String hostname) throws IOException {
		boolean errorcheck = true;
		if (checkIDNew(id) == true){
			String contactsFilePath = System.getProperty("user.dir") + File.separator + "lib" + File.separator + "contacts.txt";
			String inboxFilePath = System.getProperty("user.dir") + File.separator + "lib" + File.separator + "inbox" +File.separator;


			FileWriter fileWriter = new FileWriter(contactsFilePath,true);
			BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);

			bufferedWriter.write(id+" "+hostname+" OLD\n");
			bufferedWriter.close();
			System.out.println("Wrote "+id+" "+hostname+" to contacts");
			File contactInbox = new File(inboxFilePath+id+File.separator);
			if (contactInbox.exists()) {
                System.out.println("Contact file already in inbox");

            } else {
                // Create the file
                contactInbox.mkdirs();
                //continue
                File contactTextFile = new File(inboxFilePath+id+File.separator+id+".txt");
                if (contactTextFile.exists()) {
                    System.out.println("Contact text file already in inbox");

                }
                else {
                	contactTextFile.createNewFile();
                }
            }
			
		}
		else {
			System.out.println("Contact in system already");
			errorcheck = false;
		}
		
		
		return errorcheck;
	}
	public static String convertDerToPem(byte[] derBytes) throws Exception {
        // Generate certificate object from DER byte array
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(derBytes));

        // Convert to Base64 encoded string
        byte[] encoded = cert.getEncoded();
        String pemEncoded = Base64.getEncoder().encodeToString(encoded);

        // Format PEM string
        StringBuilder pemString = new StringBuilder();
        pemString.append("-----BEGIN CERTIFICATE-----\n");
        pemString.append(pemEncoded.replaceAll("(.{64})", "$1\n")); // Ensure 64-character line length
        pemString.append("\n-----END CERTIFICATE-----");

        return pemString.toString();
    }
	
	public static X509Certificate convertPemToX509(String pemString) throws Exception {
        // Remove the PEM headers and footers
        String pem = pemString.replaceAll("-----BEGIN CERTIFICATE-----", "")
                              .replaceAll("-----END CERTIFICATE-----", "")
                              .replaceAll("\\s", ""); // Remove whitespace characters (e.g., newlines, spaces)

        // Decode the Base64 content
        byte[] decoded = Base64.getDecoder().decode(pem);

        // Generate the certificate object
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(decoded));

        return cert;
    }
	
    
	public static queryResults query(JmDNS jmdns) throws InterruptedException {
		

		ServiceInfo [] services = jmdns.list("_securemessaging._udp.local.");
		Thread.sleep(2500);
		System.out.println("[MDNS] Found "+services.length+" Services"); 
		ArrayList<String> names = new ArrayList<>();
		ArrayList<InetAddress[]> addresses = new ArrayList<>();
		ArrayList<String> ids = new ArrayList<>();

		for (ServiceInfo info : services) {

			names.add(info.getName());

			addresses.add(info.getInet4Addresses());
			ids.add(info.getNiceTextString().substring(3));



		}

		return new queryResults(names,addresses,ids);
	}

	public static void setup_chat_with(String ip, Socket socketTCPClient, SSLSocketFactory sslSocketFactory, SSLParameters params, String id, String password) throws Exception {
		try {
			X509Certificate myCert = null;
			try {
				myCert = getCertificate(System.getProperty("user.dir") + File.separator + "lib" + File.separator + "cert.txt");
			} catch (CertificateException e) {
				// TODO Auto-generated catch block
				System.out.println("[TCP_CLIENT] ERROR: Retrieving stored cert");
			}
			byte[] myRawCert = myCert.getEncoded();
			String myPemCert = convertDerToPem(myRawCert);
			
			
			
			socketTCPClient.connect(new InetSocketAddress(ip, 7777), 10000);

			

			DataInputStream dataIn = new DataInputStream(socketTCPClient.getInputStream());
			DataOutputStream dataOut = new DataOutputStream(socketTCPClient.getOutputStream());
			dataOut.writeUTF(id);

			String reply = dataIn.readUTF();
			boolean replyIsCert = false;
			try {
				X509Certificate serverCert = secure_messaging.convertPemToX509(reply);

				
				String serverHostname = serverCert.getIssuerX500Principal().toString();
				System.out.println("[TCP_CLIENT] Server hostname: "+serverHostname);
				Collection<List<?>> SANS = serverCert.getSubjectAlternativeNames();
				if (SANS == null) {
					System.out.println("[TCP_CLIENT] NO SANS");
					dataIn.close();
					dataOut.close();
					socketTCPClient.close();
					return;
				}else {
					List<?> idList = (List<?>) SANS.toArray()[0];
					String serverID = (String) idList.get(1);
					System.out.println("[TCP_CLIENT] Server ID: "+serverID);
					addToContacts(serverID, serverHostname);
					storeCert(serverCert,serverID);
				}
				
				replyIsCert = true;

			} catch (Exception e) {
				// TODO Auto-generated catch block
				
			}
			
			
			if (replyIsCert == true) {
				
				dataOut.writeUTF(myPemCert);
			}
			else {
				if ((reply.length() < 4) || (reply.length() <= 6)){
				}
				else {
					System.out.println("[TCP_CLIENT] Reply was invalid ID: "+reply+" with length: "+reply.length());
					dataIn.close();
					dataOut.close();
					socketTCPClient.close();
					return;
				}

			}
			
			

			
		
			dataIn.close();
			dataOut.close();
			socketTCPClient.close();
			SSLSocket socketTLSClient = (SSLSocket) sslSocketFactory.createSocket(ip, 6969);
			socketTLSClient.setEnabledProtocols(new String[] {"TLSv1.3"});
			socketTLSClient.setEnabledCipherSuites(new String[]{"TLS_AES_128_GCM_SHA256"});
			socketTLSClient.setEnabledProtocols(new String[] {"TLSv1.3"});
			socketTLSClient.setEnabledCipherSuites(new String[]{"TLS_AES_128_GCM_SHA256"});
			socketTLSClient.setNeedClientAuth(true);
			socketTLSClient.setWantClientAuth(true);
			socketTLSClient.setSSLParameters(params);
			tlsConnect(ip,socketTLSClient,password);

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return;
	}
	public static void tlsConnect(String ip, SSLSocket socketTLSClient,String password) throws IOException {
		
		//new
		String endMessage = "end";
		char endChar = '\u0004';
		
		char fileChar = '\u0007';
		//new
		
		socketTLSClient.startHandshake();
		
		
		System.out.println("[TLS_CLIENT] Connected to "+ip+":"+socketTLSClient.getPort());
		Thread clientHandler = new Thread(new TLSClientHandler(socketTLSClient, password));
	
		clientHandler.start();
		PrintWriter out = null;
		
		out = new PrintWriter(

				new BufferedWriter(

						new OutputStreamWriter(

								socketTLSClient.getOutputStream())));
		
		Scanner sc = new Scanner(System.in); //System.in is a standard input stream  
		//new
		String projectDirectory = System.getProperty("user.dir"); // Get the project directory 
		String fileDirPath = projectDirectory + File.separator + "lib" + File.separator + "files" + File.separator; 
		//new
		while (true) {
			
			//new
			System.out.println("[TLS_CLIENT] Enter Message OR enter sendfile 'filename' to send file: ");
			System.out.println("[TLS_CLIENT] Enter end to close the connection.");
			String message = sc.nextLine();
			//new
			//new
			String [] messageSplit = message.split(" ");
			if (messageSplit[0].equals("sendfile")) {
				
				String fileName = messageSplit[1];
				String filePath = fileDirPath+fileName;
				try {
					FileInputStream fileInputStream = new FileInputStream(filePath);
					File file = new File(filePath);
					out.println(fileChar);
					out.flush();
					byte[] buffer = new byte[Math.toIntExact(file.length())];
					int bytesRead;
					OutputStream oStream = socketTLSClient.getOutputStream();
					while ((bytesRead = fileInputStream.read(buffer)) != -1) {
						
						
						oStream.write(buffer, 0, bytesRead);
						System.out.println(bytesRead);
					}
					oStream.close();
				}
				catch(Exception e){
					System.out.println("could not find file");
				}
				
				
				
				
				
			}
			//new
			else {
				if(message.equals("end")) {
					out.println(endChar);
					out.flush();
					clientHandler.interrupt();
					break;
				}
				
				else {
					out.println(message);
					out.flush();
				}

				
			}
			


		}
		if (socketTLSClient != null) {
			System.out.println("[TLS_CLIENT] CONNECTION CLOSED");
			socketTLSClient.close();

		}

		if (out != null) {

			out.close();

		}

		

	}
public static void tlsConnectExisting(String ip, SSLSocket socketTLSClient,String password) throws IOException {



		
		String endMessage = "end";
		char fileChar = '\u0007';
		
		char endChar = '\u0004';
		
		
		System.out.println("[TLS_CLIENT] Connected to "+ip+":"+socketTLSClient.getPort());
		;
		PrintWriter out = null;
		
		out = new PrintWriter(

				new BufferedWriter(

						new OutputStreamWriter(

								socketTLSClient.getOutputStream())));
		
		Scanner sc = new Scanner(System.in); //System.in is a standard input stream  

		//new
		String projectDirectory = System.getProperty("user.dir"); // Get the project directory 
		String fileDirPath = projectDirectory + File.separator + "lib" + File.separator + "files" + File.separator; 
		//new
		while (true) {
			
			//new
			
			System.out.println("[TLS_CLIENT] Enter Message OR enter sendfile 'filename' to send file: ");
			System.out.println("[TLS_CLIENT] Enter end to close the connection.");

			String message = sc.nextLine();
			
			String [] messageSplit = message.split(" ");
			if (messageSplit[0].equals("sendfile")) {
				
				String fileName = messageSplit[1];
				String filePath = fileDirPath+fileName;
				try {
					FileInputStream fileInputStream = new FileInputStream(filePath);
					File file = new File(filePath);
					out.println(fileChar);
					out.flush();
					byte[] buffer = new byte[Math.toIntExact(file.length())];
					int bytesRead;
					OutputStream oStream = socketTLSClient.getOutputStream();
					while ((bytesRead = fileInputStream.read(buffer)) != -1) {
						
						oStream.write(buffer, 0, bytesRead);
					}
				}
				catch(Exception e){
					System.out.println("could not find file");
				}
				
				
				
				
				
			}
			else if(message.equals("end")) {
				out.println(endChar);
				out.flush();
				break;
			}
			else {
				out.println(message);
				out.flush();

				
				
			}
			

			


		}
		if (socketTLSClient != null) {
			System.out.println("[TLS_CLIENT] CONNECTION CLOSED");
			socketTLSClient.close();

		}

		if (out != null) {

			out.close();

		}
		

		

	}
	public static String createID(String idFilePath) {
		int max = 9;
		int min = 0;
		String id = "";
		for (int i = 0; i < 6; i++){
			int randomNum = ThreadLocalRandom.current().nextInt(min, max + 1);
			id+=randomNum;
		}
		FileWriter passWriter;
		try {
			passWriter = new FileWriter(idFilePath);
			passWriter.write(id);
			passWriter.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return id;
	}
	public static String getID(File idFile) throws FileNotFoundException {

		String id = null;
		Scanner idReader = new Scanner(idFile);
		id = idReader.nextLine();



		idReader.close();
		return id;
	}
	public static String hashString(String password) {
		String generatedPassword = null;
        try {
            // Create MessageDigest instance for MD5
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            // Add password bytes to digest
            md.update(password.getBytes());
            // Get the hash's bytes
            byte[] bytes = md.digest();
            // Convert byte array into signum representation
            StringBuilder sb = new StringBuilder();
            for (byte aByte : bytes) {
                sb.append(Integer.toString((aByte & 0xff) + 0x100, 16).substring(1));
            }
            // Get complete hashed password in hex format
            generatedPassword = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return generatedPassword;
	}
	public static String createPassword(String passwordFilePath) {
		//write a password
		Scanner passInput = new Scanner(System.in);
		String password = null;
		while (true) {
			System.out.println("Create a password: ");
			String enteredPass1 = passInput.nextLine();
			System.out.println("Confirm a password: ");
			String enteredPass2 = passInput.nextLine();
			if (enteredPass1.equals(enteredPass2)) {
				try {
					FileWriter passWriter = new FileWriter(passwordFilePath);
					String passHash = hashString(enteredPass1);
					System.out.println("STORING: "+passHash);
					passWriter.write(passHash);
					passWriter.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				System.out.println("Password set.");
				password = enteredPass2;
				break;
			}
			else {
				System.out.println("Password does not match");
			}
		}
		return password;
	}
	public static String enterPassword(File passwordFile) throws FileNotFoundException {
		//compare 

		String password = null;
		Scanner passReader = new Scanner(passwordFile);
		String storedPass = passReader.nextLine();
		Scanner passInput = new Scanner(System.in);
		while (true) {
			System.out.println("Enter password: ");
			String attempt = passInput.nextLine();
			String hashAttempt = hashString(attempt);
			if (hashAttempt.equals(storedPass)) {
				System.out.println("Welcome");
				password = attempt;
				break;
			}else {
				System.out.println("Incorrect password");
			}

		}

		passReader.close();
		return password;
	}

	public static KeyPair keyPairGen() throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}
	public static byte[][] createKeys(String pubkeyFilePath, String privkeyFilePath) throws IOException {
		byte[][] keys = new byte[2][];
		try {
			KeyPair keyPair = keyPairGen();
			byte[] privateKey = keyPair.getPrivate().getEncoded();
			byte[] publicKey = keyPair.getPublic().getEncoded();;
			keys[0] = publicKey;
			keys[1] = privateKey;

			System.out.println("Writing public key");
			FileOutputStream pubkeyWriter = new FileOutputStream(pubkeyFilePath);
			pubkeyWriter.write(publicKey);
			pubkeyWriter.close();

			System.out.println("Writing private key");
			FileOutputStream privkeyWriter = new FileOutputStream(privkeyFilePath);
			privkeyWriter.write(privateKey);
			privkeyWriter.close();

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return keys;
	}

	public static byte[][] getKeys(String pubkeyFilePath, String privkeyFilePath) throws IOException{
		byte[][] keys = new byte[2][];

		FileInputStream pubkeyReader = new FileInputStream(pubkeyFilePath);
		ByteArrayOutputStream pubkeyByteArrayOutputStream = new ByteArrayOutputStream();
		byte[] buffer = new byte[4096]; // You can adjust the buffer size as needed

		int bytesRead;
		while ((bytesRead = pubkeyReader.read(buffer)) != -1) {
			pubkeyByteArrayOutputStream.write(buffer, 0, bytesRead);
		}
		byte[] publicKey = pubkeyByteArrayOutputStream.toByteArray();
		pubkeyReader.close();

		FileInputStream privkeyReader = new FileInputStream(privkeyFilePath);
		ByteArrayOutputStream privkeyByteArrayOutputStream = new ByteArrayOutputStream();

		while ((bytesRead = privkeyReader.read(buffer)) != -1) {
			privkeyByteArrayOutputStream.write(buffer, 0, bytesRead);
		}
		byte[] privateKey = privkeyByteArrayOutputStream.toByteArray();
		privkeyReader.close();

		keys[0] = publicKey;
		keys[1] = privateKey;




		return keys;
	}
	public static X509Certificate certificateGen(PublicKey pubkey,PrivateKey privkey, String id)throws Exception {
		InetAddress host = InetAddress.getLocalHost();
		String hostname = ("CN="+host.getHostName().toString());

		X500Principal x500HostName = new X500Principal(hostname);
		//X500Principal x500id = new X500Principal(id);

		// Use Bouncy Castle for content signing
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		// Create a content signer
		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(privkey);

		// Set certificate attributes
		Date startDate = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24); // Yesterday
		Date endDate = new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 365 * 10); // 10 years

		// Build the certificate
		JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
				x500HostName,
				BigInteger.valueOf(System.currentTimeMillis()),
				startDate,
				endDate,
				x500HostName, //this will be id
				pubkey
				);
		// Add Subject Alternative Name extension
		GeneralName[] generalNames = new GeneralName[1];

		generalNames[0] = new GeneralName(GeneralName.dNSName, id);

		GeneralNames subjectAltNames = new GeneralNames(generalNames);

		certBuilder.addExtension(Extension.subjectAlternativeName, true, subjectAltNames);

		// Set Basic Constraints extension to mark as CA certificate

		certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));



		// Generate the certificate
		X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner));

		return cert;
	}

	public static X509Certificate createCertificate(String certFilePath,PublicKey pubkey, PrivateKey privkey, String id) throws Exception {
		System.out.println("Generating Certificate");
		X509Certificate cert = certificateGen(pubkey,privkey,id);
		byte[] certBytes = cert.getEncoded();

		System.out.println("Writing cert");
		FileOutputStream certWriter = new FileOutputStream(certFilePath);
		certWriter.write(certBytes);
		certWriter.close();
		//write bytes

		return cert;
	}
	public static X509Certificate getCertificate(String certFilePath) throws IOException, CertificateException {
		

		FileInputStream certReader = new FileInputStream(certFilePath);
		ByteArrayOutputStream certByteArrayOutputStream = new ByteArrayOutputStream();
		byte[] buffer = new byte[4096]; // You can adjust the buffer size as needed

		int bytesRead;
		while ((bytesRead = certReader.read(buffer)) != -1) {
			certByteArrayOutputStream.write(buffer, 0, bytesRead);
		}
		byte[] certBytes = certByteArrayOutputStream.toByteArray();
		certReader.close();


		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certBytes));

		return cert;
	}

	public static X509Certificate byteToCert(byte[] byteCert) {
		return null;
	}





	public static void main(String[] args) throws InterruptedException {
		//System.setProperty("javax.net.debug", "ssl,handshake");
		System.out.println("Start");
		
		
		
		


		
		String projectDirectory = System.getProperty("user.dir"); // Get the project directory
		String passwordFilePath = projectDirectory + File.separator + "lib" + File.separator + "password.txt"; 
		
		String pubkeyFilePath = projectDirectory + File.separator + "lib" + File.separator + "publickey.txt";		
		String privkeyFilePath = projectDirectory + File.separator + "lib" + File.separator + "privatekey.txt";	
		String idFilePath = projectDirectory + File.separator + "lib" + File.separator + "id.txt";	
		String certFilePath = projectDirectory + File.separator + "lib" + File.separator + "cert.txt";	
		
		//get id
		File idFile = new File(idFilePath);
		String id = null;
		if (idFile.length() == 0){
			id = createID(idFilePath);
			System.out.println("ID is: "+id);

		}
		else {
			try {
				id = getID(idFile);
				System.out.println("ID is: "+id);
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} 

		}
		
		//PASSWORD HANDLING
		//open password
		File passwordFile = new File(passwordFilePath);
		String password = null;
		if (passwordFile.length() == 0){
			password = createPassword(passwordFilePath);

		}
		else {
			try {
				password = enterPassword(passwordFile);
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		

		//key
		byte[][] keysBytes = null;
		File pubkeyFile = new File(pubkeyFilePath);
		File privkeyFile = new File(privkeyFilePath);
		if (privkeyFile.length() == 0) {
			// no keys
			System.out.println("Generating Keys: ");
			try {
				keysBytes = createKeys(pubkeyFilePath,privkeyFilePath);
				System.out.println("Public key: "+keysBytes[0]);
				System.out.println("Private key: "+keysBytes[1]);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}


		}
		else {
			//has keys

			try {
				System.out.println("Found Keys");
				keysBytes = getKeys(pubkeyFilePath,privkeyFilePath);
				//System.out.println("Public key: "+keysBytes[0]);
				//System.out.println("Private key: "+keysBytes[1]);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}


		}

		//key handling
		PublicKey publicKey = null;
		PrivateKey privateKey = null;
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");

			X509EncodedKeySpec keySpecPub = new X509EncodedKeySpec(keysBytes[0]);
			publicKey = keyFactory.generatePublic(keySpecPub);

			PKCS8EncodedKeySpec keySpecPriv = new PKCS8EncodedKeySpec(keysBytes[1]);
			privateKey = keyFactory.generatePrivate(keySpecPriv);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		KeyPair keyPair = new KeyPair(publicKey, privateKey);

		//CERTIFICATE AREA
		File certFile = new File(certFilePath);
		X509Certificate cert = null;
		if (certFile.length() == 0){
			try {
				cert = createCertificate(certFilePath,publicKey, privateKey, id);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		else {
			try {
				cert = getCertificate(certFilePath);
			} catch (CertificateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}


		//System.out.println("CERT: "+cert.toString());




		//TCP HANDLING

		ServerSocket socketTCPServer = null;
		try {
			socketTCPServer = new ServerSocket(7777);


			Thread thread = new Thread(new TCPListener(socketTCPServer,id));
			thread.start();



		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("FATAL ERROR: Program already running on host");
			System.exit(0);
	
		}

		//SETUP TLS

		char[] keyPassword = password.toCharArray();
		KeyManager[] keyManagers = { new CustomKeyManager(privateKey, cert) };
		SSLServerSocketFactory sslServerSocketFactory = null;
		SSLSocketFactory sslSocketFactory = null; 
		SSLServerSocket socketTLSServer = null;
		SSLParameters params = null;
		final  X509Certificate testcert = cert;
		try {
			TrustManager[] trustAllCerts = new TrustManager[]{
					new X509TrustManager() {
						public X509Certificate[] getAcceptedIssuers() {
							return new X509Certificate[0];
						}

						public void checkClientTrusted(X509Certificate[] certs, String authType) throws CertificateException {
							boolean certCheck;
							if (certs.length == 0) {
								throw new CertificateException("Not trusted Client. no cert provided");
								
							}
							else if (certs.length > 1) {
								throw new CertificateException("Not trusted Client. more than one cert provided");
								
							}
							else {
								try {
									certCheck = verifyPeerCert(certs[0]);
									if (certCheck ==true){
		
										return;
									}
									else {
										throw new CertificateException("Not trusted Client. cert verification vfailed");
									}
								} catch (CertificateException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								} catch (IOException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}
								
							}
							
							
						}

						public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException {
							
							boolean certCheck;
							if (certs.length == 0) {
								throw new CertificateException("Not trusted server. no cert provided");
								
							}
							else if (certs.length > 1) {
								throw new CertificateException("Not trusted server. more than one cert provided");
								
							}
							else {
								try {
									certCheck = verifyPeerCert(certs[0]);
									if (certCheck ==true){
			
										return;
									}
									else {
										throw new CertificateException("Not trusted server. cert verification vfailed");
									}
								} catch (CertificateException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								} catch (IOException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}
								
							}
						}
					}
			};

			SSLContext sslContext = SSLContext.getInstance("TLS");

			sslContext.init(keyManagers, trustAllCerts, new SecureRandom());

			params = sslContext.getDefaultSSLParameters();
			params.setNeedClientAuth(true);
			params.setWantClientAuth(true);
			params.setProtocols(new String[] {"TLSv1.3"});
			params.setCipherSuites(new String[]{"TLS_AES_128_GCM_SHA256"});
			params.setEndpointIdentificationAlgorithm(null);


			sslServerSocketFactory = sslContext.getServerSocketFactory();
			sslSocketFactory = sslContext.getSocketFactory();




			socketTLSServer = (SSLServerSocket) sslServerSocketFactory.createServerSocket(6969);
			socketTLSServer.setEnabledProtocols(new String[] {"TLSv1.3"});
			socketTLSServer.setEnabledCipherSuites(new String[]{"TLS_AES_128_GCM_SHA256"});
			socketTLSServer.setNeedClientAuth(true);
			socketTLSServer.setWantClientAuth(true);
			socketTLSServer.setSSLParameters(params);





			Thread thread = new Thread(new TLSListener(socketTLSServer, password));
			thread.start();





		} catch(IOException e) {
			System.out.println("FATAL ERROR: Program already running on host");
			System.exit(0);
			
		}
		catch (NoSuchAlgorithmException | KeyManagementException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}




		//JMDNS HANDLING
		JmDNS jmdns = null;
		try {
			jmdns = JmDNS.create(InetAddress.getLocalHost());
			InetAddress host = InetAddress.getLocalHost();
			String hostname = (host.getHostName().toString());
			String info = "Secure Messaging";
			// Register a service
			
			ServiceInfo serviceInfo = ServiceInfo.create("_securemessaging._udp.local.", hostname, 8000, id);
			jmdns.registerService(serviceInfo);
			System.out.println("[MDNS] Service created");
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		

		//contact updater
		try {
			System.out.println("Updating current contacts . . .");
			updateContacts(jmdns);
		} catch (KeyManagementException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		Thread updaterThread = new Thread(new ContactUpdater(jmdns));
		updaterThread.start();
		//MENU
//		
		while (true) {
			System.out.println("-=-=-=-=- MENU -=-=-=-=-");
			System.out.println("Type 1 to find contacts");
			System.out.println("Type 2 to read inbox");
			System.out.println("Type 3 to revoke");	
			System.out.println("Type 4 to exit");
			Scanner scanner = new Scanner(System.in);
			int choice = 0;
			boolean isValidInput = false;



			while (!isValidInput) {
				System.out.println("Enter your choice: ");
				if (scanner.hasNextInt()) {
					choice = scanner.nextInt();
					isValidInput = true; // Break the loop if input is an integer
				} else {
					System.out.println("Invalid input! Please enter an integer.");
					scanner.next(); // Clear the invalid input from the scanner
				}
			}



			switch (choice) {
			//queryz
			case 1:
				System.out.println("Querying: ");
				queryResults results = query(jmdns);
				ArrayList<String> names = results.getNames();
				ArrayList<InetAddress[]> addresses = results.getAddresses();
				ArrayList<String> infos = results.getInfos();
				int length = names.size();
				System.out.println("Choose who to message: ");
				System.out.println("0. Go back");
				for (int i = 0; i <length;i++) {
					System.out.println((i+1)+". "+names.get(i)+" at "+addresses.get(i)[0].toString().replaceAll("/","")+" ID: "+infos.get(i));
				}
				//message
				
				Scanner sc= new Scanner(System.in); //System.in is a standard input stream  
				int a = sc.nextInt()-1;   
				if (a == -1) {
					break;
				}
				if((a <= -1 )||(a >=length)) {
					System.out.println("Invalid person");
					break;
				}
				
				String recipient = names.get(a); 
				String ipString = addresses.get(a)[0].toString().replaceAll("/","");
				InetAddress ip = addresses.get(a)[0];
				String idChoice = infos.get(a);
				
				SSLSocket existing = ConnectionManager.getInstance().getConnection(idChoice);
			
				boolean foundExisting = false;
				if (existing != null) {
					try {
						tlsConnectExisting(idChoice,existing,password);
						foundExisting = true;
						break;
					} catch (IOException e) {
						// TODO Auto-generated catch block
						;
					}
				}
				
				if (foundExisting == false) {
					
				
					Socket socketTCPClient = new Socket();
					System.out.println("TCP Client created");

					//tcp connect


					if (params == null) {
						System.out.println("PARAMS NULL");
					}


					try {
						setup_chat_with(ipString,socketTCPClient,sslSocketFactory,params,id,password);
					} catch (CertificateEncodingException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}



					break;
				}
				
			case 2:
				System.out.println("Choose contact to view messages from: ");
				String contactsFilePath = System.getProperty("user.dir") + File.separator + "lib" + File.separator + "contacts.txt";
				List<String> contacts = new ArrayList<String>();
		        try (BufferedReader br = new BufferedReader(new FileReader(contactsFilePath))) {
		            String line;
		            // Read each line from the file until reaching the end
		            while ((line = br.readLine()) != null) {
		            	contacts.add(line); // Process the line (e.g., print or manipulate it)
		            }
		        } catch (IOException e) {
		            e.printStackTrace(); // Handle any IO exceptions (e.g., file not found)
		        }
		        
		        int contactLength = contacts.size();
				System.out.println("0. Go back");
				for (int i = 0; i <contactLength;i++) {
					String conString = contacts.get(i);
					String[] conArray = conString.split(" ");
					System.out.println(i+1+". "+conArray[1].replaceFirst("CN=", "")+"[ID: "+conArray[0]+"]");
				}
				//message
				Scanner contactScan= new Scanner(System.in); //System.in is a standard input stream  
				int f = contactScan.nextInt()-1;  
				if (f == -1) {
					break;
				}
				if((f <= -1 )||(f >=contactLength)) {
					System.out.println("Invalid Choice");
					break;
				}
				
				String conChoice = contacts.get(f);
				String[] conChoiceArray = conChoice.split(" ");
				String choiceID = conChoiceArray[0];
				String choiceHost = conChoiceArray[1];
				try {
					readMessages(choiceID,choiceHost,password);
				} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
						| IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException
						| InvalidAlgorithmParameterException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				System.out.println("0. Go back");
				while (true) {
					int h = contactScan.nextInt();
					if (h == 0){
						break;
					}
					else {
						System.out.println("Invalid choice. Type 0 to return to main menu");
					}
					
				}
				break;
				//exit
			case 3:
				System.out.println("Revoking key and exiting.");
				try {
					revokeMyself();
					

				} catch (IOException  e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				System.exit(0);
			case 4:

				System.out.println("Exiting");
				// Unregister all services
				jmdns.unregisterAllServices();
				scanner.close();
				System.exit(0);

			default:
				System.out.println("Invalid Choice");
			}






		}

	}
}


class queryResults {
	ArrayList<String> names;
	ArrayList<InetAddress[]> addresses;
	ArrayList<String> infos;

	public queryResults(ArrayList<String> names,ArrayList<InetAddress[]> addresses, ArrayList<String> infos ) {
		this.names = names;
		this.addresses = addresses;
		this.infos = infos;
	}
	public ArrayList<String> getNames(){
		return this.names;
	}
	public ArrayList<InetAddress[]> getAddresses(){
		return this.addresses;
	}
	public ArrayList<String> getInfos() {
		return this.infos;
	}


}
class TCPListener implements Runnable{
	private ServerSocket socketTCPServer;
	private String myID;
	public TCPListener(ServerSocket socketTCPServer,String myID) {
		this.socketTCPServer = socketTCPServer;
		this.myID = myID;
	}

	public void run() {
		try {
			System.out.println("[TCP_LISTENER] Listening for TCP");
			while (true) {
				Socket socketTCPClient = socketTCPServer.accept();
				Thread thread = new Thread(new TCPServerHandler(socketTCPServer, socketTCPClient,myID));
				thread.start();

			}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
class TCPServerHandler implements Runnable{
	private ServerSocket socketTCPServer;
	private Socket socketTCPClient;
	private String myID;
	public TCPServerHandler(ServerSocket socketTCPServer,Socket socketTCPClient, String myID) {
		this.socketTCPServer = socketTCPServer;
		this.socketTCPClient = socketTCPClient;
		this.myID = myID;
	}
	
	
	
	public void run() {
		try {
			String clientSocketIP = socketTCPClient.getInetAddress().toString().replaceAll("/", "");
			int clientSocketPort = socketTCPClient.getPort();

			DataInputStream dataIn = new DataInputStream(socketTCPClient.getInputStream());
			DataOutputStream dataOut = new DataOutputStream(socketTCPClient.getOutputStream());
			
						
			
			String receivedID = dataIn.readUTF();
			
			if ((receivedID.length() < 4 )||receivedID.length() > 6){
				
				System.out.println("[TCP_SERVER] Invalid ID");
				dataIn.close();
				dataOut.close();
				socketTCPClient.close();
			}
			else {
			}
			
			boolean idNew = secure_messaging.checkIDNew(receivedID);
			
			if (idNew == true) {
				X509Certificate myCert = null;
				try {
					myCert = secure_messaging.getCertificate(System.getProperty("user.dir") + File.separator + "lib" + File.separator + "cert.txt");
				} catch (CertificateException e) {
					// TODO Auto-generated catch block
					System.out.println("[TCP_SERVER] ERROR: Retrieving stored cert");
					dataIn.close();
					dataOut.close();
					socketTCPClient.close();
				}
				byte[] myRawCert = myCert.getEncoded();
				String myPemCert = secure_messaging.convertDerToPem(myRawCert);
				dataOut.writeUTF(myPemCert);
				System.out.println("[TCP_SERVER] Sent Cert");
				String clientCertString = dataIn.readUTF();
				X509Certificate clientCert = null;
				
				try {
					clientCert = secure_messaging.convertPemToX509(clientCertString);
					System.out.println("[TCP_SERVER] Received Cert");
					String clientHostname = clientCert.getIssuerX500Principal().toString();
					System.out.println("[TCP_SERVER] Client hostname: "+clientHostname);
					Collection<List<?>> SANS = clientCert.getSubjectAlternativeNames();
					if (SANS == null) {
						System.out.println("[TCP_SERVER] NO SANS");
						dataIn.close();
						dataOut.close();
						socketTCPClient.close();
					}else {
						List<?> idList = (List<?>) SANS.toArray()[0];
						String clientID = (String) idList.get(1);
						System.out.println("[TCP_SERVER] Client ID: "+clientID);
						secure_messaging.addToContacts(clientID,clientHostname);
						secure_messaging.storeCert(clientCert,clientID);
					}
					
				} catch (Exception e) {
					// TODO Auto-generated catch block
					System.out.println("[TCP_SERVER] Response to server cert was not client cert");
					dataIn.close();
					dataOut.close();
					socketTCPClient.close();
				}
							
			
			}
			else {
				dataOut.writeUTF(myID);
			}
			
			dataIn.close();
			dataOut.close();
			socketTCPClient.close();





		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
class TLSListener implements Runnable{

	private SSLServerSocket socketTLSServer;
	private String password;
	public TLSListener(SSLServerSocket socketTLSServer, String password) {
		this.socketTLSServer = socketTLSServer;
		this.password = password;
	}
	public void run() {
		try {
			
			System.out.println("[TLS_LISTENER] Listening for TLS");
			while (true) {
				SSLSocket socketTLSClient = (SSLSocket) socketTLSServer.accept();
				
				Thread thread = new Thread(new TLSServerHandler(socketTLSServer, socketTLSClient, password));
				thread.start();

			}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
class TLSServerHandler implements Runnable{
	private SSLServerSocket socketTLSServer;
	private SSLSocket socketTLSClient;
	private String password;

	public TLSServerHandler(SSLServerSocket socketTLSServer,SSLSocket socketTLSClient, String password) {
		this.socketTLSServer = socketTLSServer;
		this.socketTLSClient = socketTLSClient;
		this.password = password;
	}
	public void run() {
		try {
			char endChar = '\u0004'; 
			char revoChar = '\u0005';

			char fileChar = '\u0007';

			String clientSocketIP = socketTLSClient.getInetAddress().toString().replaceAll("/", "");
			int clientSocketPort = socketTLSClient.getPort();
			System.out.println("[TLS_SERVER] Connected to "+clientSocketIP+":"+clientSocketPort);

			BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(socketTLSClient.getInputStream()));
			PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(socketTLSClient.getOutputStream()), true);
			X509Certificate peerCert = (X509Certificate) socketTLSClient.getSession().getPeerCertificates()[0];
			Collection<List<?>> SANS;
			String id = null;
			try {
				SANS = peerCert.getSubjectAlternativeNames();
				if (SANS == null) {
					System.out.println("[TLS_SERVER] Messaging Storage Error: Peer has no SAN");
				}else {
					List<?> idList = (List<?>) SANS.toArray()[0];
					id = (String) idList.get(1);
					
				}
			} catch (CertificateParsingException e) {
				
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			
			ConnectionManager.getInstance().addConnection(id, socketTLSClient);
			String message;

			while ((message = bufferedReader.readLine()) != null) {
				System.out.println("[TLS_SERVER] Received: " + message);
				System.out.flush();
				
				if (message.toCharArray()[0] == (endChar)) {
					break;
				}
				
				else if (message.toCharArray()[0] == (fileChar)) {
					System.out.println("[TLS_SERVER]Incoming file");
					byte[] buffer = new byte[8192];
					try {
						
						InputStream inputStream = socketTLSClient.getInputStream();
						String projectDirectory = System.getProperty("user.dir"); // Get the project directory
						String passwordFilePath = projectDirectory + File.separator + "lib" + File.separator + "password.txt"; 
						ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
						int bytesRead;
						
						while ((bytesRead = inputStream.read(buffer)) != -1) {
				            byteArrayOutputStream.write(buffer, 0, bytesRead);
				            System.out.println(bytesRead);
				            
				        }
						
					    byte[] fileData = byteArrayOutputStream.toByteArray();
					    secure_messaging.receiveFile(id, fileData);
						
					}catch(Exception e) {
						System.out.println("error receiving file");
					}
					
				}
				else if (message.toCharArray()[0] == revoChar){
					StringBuilder pemBuilder = new StringBuilder();
					String line;
					while ((line = bufferedReader.readLine()) != null) {
					    // Add the line to the StringBuilder
					    pemBuilder.append(line);
					    pemBuilder.append('\n'); // Append a newline character to preserve the PEM format

					    // Check if the current line indicates the end of the PEM content
					    if (line.contains("-----END CERTIFICATE-----")) {
					        break; // Exit the loop as we've reached the end of the certificate
					   
					    }
					}
					String newCertString = pemBuilder.toString();
					try {
						X509Certificate newCert = secure_messaging.convertPemToX509(newCertString);
						secure_messaging.revokeContact(id, newCert);
					} catch (Exception e) {
						// TODO Auto-generated catch block
						System.out.println("Second revocation message received was not certificate ");
					}
					
					break;
				}
				else {
					try {
						String encryptedMessage = secure_messaging.encrypt(message, password);
						secure_messaging.storeMessage(encryptedMessage, id);
					} catch (InvalidKeyException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (NoSuchAlgorithmException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (NoSuchPaddingException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (IllegalBlockSizeException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (BadPaddingException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (InvalidKeySpecException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (InvalidAlgorithmParameterException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					
				}
			}



			System.out.println("[TLS_SERVER] CONNECTION CLOSED");
			ConnectionManager.getInstance().removeConnection(id);
			socketTLSClient.close();
			printWriter.close();
			bufferedReader.close();





		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}


class TLSClientHandler implements Runnable{
	private SSLSocket socketTLSClient;
	private String password;
	
	public TLSClientHandler(SSLSocket socketTLSClient, String password) {
		this.socketTLSClient = socketTLSClient;
		this.password = password;
	}
	public void run() {
		BufferedReader in = null;
		char endChar = '\u0004'; 
		char fileChar = '\u0007';

		
		
		

		try {
			X509Certificate peerCert = (X509Certificate) socketTLSClient.getSession().getPeerCertificates()[0];
			Collection<List<?>> SANS;
			String id = null;
			SANS = peerCert.getSubjectAlternativeNames();
			if (SANS == null) {
				System.out.println("[TLS_SERVER] Messaging Storage Error: Peer has no SAN");
			}
			else {
				List<?> idList = (List<?>) SANS.toArray()[0];
				id = (String) idList.get(1);

			}
			

			in = new BufferedReader(new InputStreamReader(socketTLSClient.getInputStream()));
			
			String message = null;
			try {
				while (in.readLine()!=null){
					message = in.readLine();
					System.out.println("[TLS_CLIENT] Received: " + message);
					System.out.flush();
					

					if (message.toCharArray()[0] == (endChar)) {
						break;
					}
					else if (message.toCharArray()[0] == (fileChar)) {
						System.out.println("[TLS_SERVER]Incoming file");
						byte[] buffer = new byte[8192];
						try {
							InputStream inputStream = socketTLSClient.getInputStream();
							String projectDirectory = System.getProperty("user.dir"); // Get the project directory
							String passwordFilePath = projectDirectory + File.separator + "lib" + File.separator + "password.txt"; 
							
							int bytesRead;
						    while ((bytesRead = inputStream.read(buffer)) != -1) {
						        ;
						    }
						    secure_messaging.receiveFile(id, buffer);
							
						}catch(Exception e) {
							System.out.println("error receiving file");
						}
					}

					else {
						try {
							String encryptedMessage = secure_messaging.encrypt(message, password);
							secure_messaging.storeMessage(encryptedMessage, id);
						} catch (InvalidKeyException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (NoSuchAlgorithmException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (NoSuchPaddingException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (IllegalBlockSizeException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (BadPaddingException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (InvalidKeySpecException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (InvalidAlgorithmParameterException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					}


					break;
				}
			}
			catch(SocketException e){
				;
			}
			if (in != null) {

				in.close();
			}
		} catch (IOException | CertificateParsingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
}

class ContactUpdater implements Runnable{
	JmDNS jmdns;

	public ContactUpdater(JmDNS jmdns) {
		this.jmdns = jmdns;
	}
	public void run() {
		while (true) {
			
			try {
				Thread.sleep(60000);
				secure_messaging.updateContacts(jmdns);
			} catch (KeyManagementException | CertificateException | NoSuchAlgorithmException | IOException | InterruptedException e) {
				// TODO Auto-generated catch block
				System.out.println("ERROR UPDATING CONTACTS:\n "+e);
			}
			
		}
		
	}
}
class ConnectionManager{
	private static final ConnectionManager instance = new ConnectionManager();
	private final Map<String, SSLSocket> connections;
	private ConnectionManager() {
		connections = Collections.synchronizedMap(new HashMap<>());
	}
	public static ConnectionManager getInstance() {
        return instance;
    }

    public void addConnection(String id, SSLSocket socketTLSClient) {
        connections.put(id, socketTLSClient);
    }

    public SSLSocket getConnection(String id) {
    	try {
    		SSLSocket client = connections.get(id);
    		return client;
    	}catch(Exception e){
    		return null;
    	}
        
    }

    public void removeConnection(String id) {
        connections.remove(id);
    }

    public Map<String, Object> getAllConnections() {
        return new HashMap<>(connections); // Return a copy to avoid modification of the internal map.
    }
}


class CustomKeyManager implements X509KeyManager {
	private final PrivateKey privateKey;
	private final X509Certificate certificate;

	public CustomKeyManager(PrivateKey privateKey, X509Certificate certificate) {
		this.privateKey = privateKey;
		this.certificate = certificate;
	}

	@Override
	public String[] getClientAliases(String keyType, Principal[] issuers) {
		return new String[]{"client"}; // Provide a client alias for client-side
	}

	@Override
	public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
		return "client"; // Choose the client alias for client-side
	}

	@Override
	public String[] getServerAliases(String keyType, Principal[] issuers) {
		return new String[]{"server"}; // Provide a server alias for server-side
	}

	@Override
	public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
		return "server"; // Choose the server alias for server-side
	}

	@Override
	public X509Certificate[] getCertificateChain(String alias) {
		return new X509Certificate[] { certificate };
	}

	@Override
	public PrivateKey getPrivateKey(String alias) {
		return privateKey;
	}
}