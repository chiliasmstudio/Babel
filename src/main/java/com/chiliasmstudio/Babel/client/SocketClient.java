package com.chiliasmstudio.Babel.client;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;

public class SocketClient extends Thread{
    private PrintWriter clientWriter;
    public boolean isConnect = false;
    public SocketClient() throws Exception{


        // 關閉連線
        //reader.close();
        //socket.close();
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
            SSLSocket socket = (SSLSocket) socketFactory.createSocket("127.0.0.1", 81); // 請將 "server_hostname" 替換為實際的伺服器主機名稱
            //socket.startHandshake();
            System.out.println("Connect!");
            isConnect = true;
            notify();

            // 進行通訊
            //Scanner in = new Scanner(socket.getInputStream());
            clientWriter = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            Thread.sleep(3000L);
            clientWriter.println("Hello");
            //MessageHandler messageHandler = new MessageHandler(in);
            //messageHandler.start();
            while (true) {
                System.out.println(in.readLine());
            }
        }catch (KeyStoreException e){
            e.printStackTrace();
        }catch (IOException e){
            e.printStackTrace();
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }catch (CertificateException e){
            e.printStackTrace();
        }catch (KeyManagementException e){
            e.printStackTrace();
        }catch (UnrecoverableKeyException e){
            e.printStackTrace();
        } catch (InterruptedException e){
            e.printStackTrace();
        }

    }

    public void SendMessage(String message){
        clientWriter.println(message);
    }
    class MessageHandler extends Thread {
        BufferedReader in;
        public MessageHandler(BufferedReader in){
            this.in = in;
        }
        public void run(BufferedReader in) throws IOException {
            while (true){
                System.out.println(in.readLine());
            }
        }
    }
}


