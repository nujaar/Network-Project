package cliente;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.xml.bind.DatatypeConverter;
import static servidor.ServidorTCP.decrypt;

public class ClienteTCP {

    BufferedReader in;
    PrintWriter out;
    String actionMessage;
    boolean bool = false;
    static String start;
    
    JFrame frame = new JFrame("Messages");
    JTextField textField = new JTextField(40);
    JTextArea messageArea = new JTextArea(8, 40);
    
    public void run2() throws IOException{
        // escribimos la ip del servidor
        String serverAddress = getServerAddress();   
        // creamos el socket y nos conectamos al servidor
        Socket socket = new Socket(serverAddress, 9898);
        in = new BufferedReader(new InputStreamReader(
            socket.getInputStream()));
        out = new PrintWriter(socket.getOutputStream(), true);
        // enviamos la opcion para la conexion si es encriptado o sin encriptar
        out.println(start);
        // Escribimos el primer mensaje del servidor
        for (int i = 0; i < 1; i++) {
            System.out.println(in.readLine() + "\n");
        }
        System.out.println("Connected to: " + socket.getInetAddress() + "\n");
        out.println("comunication started without encryption");

        //mensajes
        while (true) {
            String line = in.readLine();
            if (line.startsWith("ACCEPTED")) {
                textField.setEditable(true);
            } else if (line.startsWith("MESSAGE")) {
                messageArea.append(line.substring(8) + "\n");
                if(line.contains("END")){
                in.close();
                out.close();
                socket.close();
                System.exit(0);
                }
            } 
        }
    }
    
    public void run() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, Exception {
        // Escribimos la ip del servidor
        String serverAddress = getServerAddress();
        // creamos el socket y nos conectamos.
        Socket socket = new Socket(serverAddress, 9898);
        InputStream inS;
        OutputStream outS;
        inS = socket.getInputStream();
        outS = socket.getOutputStream();
        in = new BufferedReader(new InputStreamReader(inS));
        out = new PrintWriter(outS, true);
        // enviamos la opcion para la conexion si es encriptado o sin encriptar
        out.println(start);

        // Escribimos el primer mensaje del servidor
        for (int i = 0; i < 1; i++) {
            System.out.println(in.readLine() + "\n");
        }
        System.out.println("Connected to: " + socket.getInetAddress() + "\n");       
        //Generamos las llaves
        PublicKey pubKey, key;
        PrivateKey privateKey;
        KeyPair keyPair = buildKeyPair();
        pubKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
        //imprimimos la llave publica del cliente
        System.out.println(pubKey);
        //enviamos la llave publica del cliente
        outS.write(pubKey.getEncoded());
        byte[] fk = new byte[2048];
        //recibimos la llave publica del servidor
        inS.read(fk);
        //decodificamos la llave publica del servidor
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(fk);
        KeyFactory f = KeyFactory.getInstance("RSA");
        key = f.generatePublic(pubKeySpec);
        System.out.println(key);
        //enviamos un mensaje al servidor
        String message = "Hello server";
        byte[] m = encrypt(key, message);
        outS.write(m);
        message = "Comunication started with encryption";
        m = encrypt(key, message);
        outS.write(m);
        byte[] mess = new byte[256];
        //recibimos el mensaje enviado pero en mayusculas
        inS.read(mess);
        byte[] rep = decrypt(privateKey, mess);
        messageArea.append(new String(rep) + "\n");       
        while (true) {
            String line = new String(rep);
            if (line.startsWith("END")) {
                inS.close();
                outS.close();
                in.close();
                out.close();
                socket.close();
                System.exit(0);
            }else{               
                textField.setEditable(true);
                if(!bool){
                }else{
                message = actionMessage;
                m = encrypt(key, message);
                outS.write(m);
                mess = new byte[256];
                inS.read(mess);
                rep = decrypt(privateKey, mess);
                System.out.println(new String(rep));
                line = new String(rep);
                messageArea.append(line + "\n");
                bool = false;
                }      
            }
        }
    }
    
    public ClienteTCP(){
        frame.setLocationRelativeTo(null);
        textField.setEditable(false);
        messageArea.setEditable(false);
        frame.getContentPane().add(textField, "North");
        frame.getContentPane().add(new JScrollPane(messageArea), "Center");
        frame.pack();
        
        
        textField.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if(start.equals("1")){
                actionMessage = textField.getText(); 
                bool = true;
                textField.setText("");
                }else if(start.equals("2")){
                out.println(textField.getText());
                textField.setText("");
                }

            }
        });
    }

    public static void main(String[] args) throws Exception {
        start = JOptionPane.showInputDialog("Ingrese 2 para comunicacion sin encriptacion, "
                + "ingrese 1 para comunicacion con encriptacion");
        if(start.equals("1")){
        ClienteTCP cliente = new ClienteTCP();
        cliente.frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        cliente.frame.setVisible(true);
        cliente.run();
        }else if (start.equals("2")){
        ClienteTCP cliente = new ClienteTCP();
        cliente.frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        cliente.frame.setVisible(true);
        cliente.run2();
        }else{
            
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
    private String getServerAddress() {
        return JOptionPane.showInputDialog(
            frame,
            "Enter IP Address of the Server:",
            JOptionPane.QUESTION_MESSAGE);
    }

}
