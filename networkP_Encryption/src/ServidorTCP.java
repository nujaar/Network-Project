/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package servidor;

import static cliente.ClienteTCP.encrypt;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author juan
 */
public class ServidorTCP {

    private static int SERVER_PORT = 9898;
    static String start;
    private static HashSet<PrintWriter> writers = new HashSet<PrintWriter>();

    public static void main(String[] args) throws Exception {
        System.out.println("The server is running.");
        ServerSocket listener = new ServerSocket(SERVER_PORT);
        try {
            while (true) {
                new serverT(listener.accept()).start();
            }
        } finally {
            listener.close();
        }
    }

    private static class serverT extends Thread {

        private Socket socket;
        private String client;

        public serverT(Socket socket) {
            this.socket = socket;
            log("New connection at " + socket);
        }
        public void run() {
            try {
                BufferedReader in = new BufferedReader(
                new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                String input = "";
                // enviamos un welcome al cliente.
                InputStream inS = socket.getInputStream();
                OutputStream outS = socket.getOutputStream();
                out.println("Hello client");
                KeyPair keyPair = null;
                keyPair = buildKeyPair();
                PublicKey pubKey = keyPair.getPublic();
                PrivateKey privateKey = keyPair.getPrivate();
                start = in.readLine();
                if (start.equals("1")) {
                    System.out.println(pubKey);
                    byte[] buff = new byte[2048];
                    //intercambio de claves
                    inS.read(buff);
                    outS.write(pubKey.getEncoded());
                    //recuperacion clave publica del cliente
                    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(buff);
                    //decodifica los bytes de la clave publica
                    KeyFactory f = KeyFactory.getInstance("RSA");
                    PublicKey key = f.generatePublic(pubKeySpec);
                    System.out.println(key);
                    //recibe el mensaje
                    byte[] mess = new byte[256];
                    inS.read(mess);
                    byte[] rep = decrypt(privateKey, mess);
                    System.out.println(new String(rep));
                    while (true) {
                        if (inS.read(mess) != -1) {
                            //inS.read(mess);
                            rep = decrypt(privateKey, mess);
                            input = new String(rep);
                            if (input == null) {
                                break;
                            }
                            log(input);
                            String answer = input.toUpperCase();
                            byte[] m = encrypt(key, answer);
                            outS.write(m);
                        } else {
                            inS.close();
                            outS.close();
                            System.exit(0);
                        }
                    }
                } else if (start.equals("2")) {
                    out.println("ACCEPTED");
                    writers.add(out);
                    while (true) {
                        String input2 = in.readLine(); 
                        if (input2 == null) {
                            return;
                        }
                        for (PrintWriter writer : writers) {
                            writer.println("MESSAGE " + input2.toUpperCase());
                        }
                    }
                }

            } catch (IOException e) {
                log("Error handling client: " + e);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(ServidorTCP.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeySpecException ex) {
                Logger.getLogger(ServidorTCP.class.getName()).log(Level.SEVERE, null, ex);
            } catch (Exception ex) {
                Logger.getLogger(ServidorTCP.class.getName()).log(Level.SEVERE, null, ex);
            } finally {
                try {
                    socket.close();
                } catch (IOException e) {
                    log("Couldn't close a socket, what's going on?");
                }
                log("Connection with client closed");
            }
        }
        private void log(String message) {
            System.out.println(message);
        }
    }

    public static KeyPair buildKeyPair() throws NoSuchAlgorithmException {
        final int keySize = 2048;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.genKeyPair();
    }

    public static byte[] encrypt(PublicKey publicKey, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(message.getBytes());
    }

    public static byte[] decrypt(PrivateKey privateKey, byte[] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return cipher.doFinal(encrypted);
    }
}
