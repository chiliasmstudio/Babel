package com.chiliasmstudio.Babel.client;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.*;
import java.io.*;
import java.net.SocketException;
import java.security.*;
import java.security.cert.CertificateException;

public class SocketClient extends Thread{
    private PrintWriter clientWriter;
    public boolean isConnect = false;
    public String userName = "anonymous";
    public SocketClient(String userName) throws Exception{
        this.userName = userName;
    }

    public void run(){
        try {
            //System.setProperty("javax.net.debug", "ssl:handshake");
            Security.addProvider(new BouncyCastleProvider());

            // 載入信任的憑證
            KeyStore trustKeyStore = KeyStore.getInstance("PKCS12");
            trustKeyStore.load(new FileInputStream(".\\Xtemp\\Xtrust.pfx"), "".toCharArray());
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustKeyStore);
            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();


            // 載入憑證和私鑰
            KeyStore clientKeyStore = KeyStore.getInstance("PKCS12");
            clientKeyStore.load(new FileInputStream(".\\Xtemp\\client.pfx"), "".toCharArray());

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(clientKeyStore, "".toCharArray());

            KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

            // 建立 SSLContext，並設定 TrustManager 和 KeyManager
            SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
            sslContext.init(keyManagers, trustManagers, null);

            // 建立 SSLSocketFactory
            SSLSocketFactory socketFactory = sslContext.getSocketFactory();

            // 建立 SSLSocket
            SSLSocket socket = (SSLSocket) socketFactory.createSocket("127.0.0.1", 81);

            // Connected to server, notify the main class.
            System.out.println("Connect!");
            isConnect = true;
            synchronized (this){
                notify();
            }

            // 進行通訊
            //Scanner in = new Scanner(socket.getInputStream());
            clientWriter = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            clientWriter.println(userName);
            String line;
            while ((line=in.readLine())!=null){
                switch (line) {
                    case "REJECT:NAME_CONFLICT":{
                        System.err.println("Name used, disconnect from server.");
                        System.exit(0);
                    }
                    case "NOTUSEYET":
                        System.out.println("");
                    default:
                        System.out.println(line);
                }
            }
        }catch (KeyStoreException e){
            e.printStackTrace();
        } catch (SocketException e){
            System.err.println("Disconnect form server!");
            e.printStackTrace();
            System.exit(0);
        } catch (IOException e){
            e.printStackTrace();
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }catch (CertificateException e){
            e.printStackTrace();
        }catch (KeyManagementException e){
            e.printStackTrace();
        }catch (UnrecoverableKeyException e){
            e.printStackTrace();
        }
    }

    public void SendMessage(String message){
        clientWriter.println(message);
        clientWriter.flush();
    }
}


