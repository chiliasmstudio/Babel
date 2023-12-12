package com.chiliasmstudio.Babel.server;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.security.Security;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


public class SocketServer extends Thread{
    private static Set<ClientObject> clientObjects = new HashSet<>();

    public SocketServer() throws Exception {
        //System.setProperty("javax.net.debug", "ssl:handshake");
        Security.addProvider(new BouncyCastleProvider());

        // 載入信任的憑證
        KeyStore trustKeyStore = KeyStore.getInstance("PKCS12");
        trustKeyStore.load(new FileInputStream(".\\Config\\trust.pfx"), "".toCharArray());
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustKeyStore);
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();


        // 載入伺服器憑證和私鑰
        KeyStore serverKeyStore = KeyStore.getInstance("PKCS12");
        serverKeyStore.load(new FileInputStream(".\\Config\\server.pfx"), "".toCharArray());

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(serverKeyStore, "".toCharArray());

        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

        // 建立 SSLContext，並設定 TrustManager 和 KeyManager
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(keyManagers, trustManagers, null);

        // 建立 SSLServerSocketFactory
        SSLServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();

        // 建立 SSLServerSocket
        SSLServerSocket serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(5124);
        serverSocket.setNeedClientAuth(true);
        serverSocket.setEnabledProtocols(new String[]{"TLSv1.3"});
        System.out.println("Server start!");
        ExecutorService pool = Executors.newFixedThreadPool(10);

        while (true) {
            pool.execute(new Handler((SSLSocket) serverSocket.accept()));
        }
        /*while (true) {
            // 等待客戶端連線
            SSLSocket socket = (SSLSocket) serverSocket.accept();
            in = new Scanner(socket.getInputStream());
            out = new PrintWriter(socket.getOutputStream(), true);
            System.out.println("client connect");
            // 進行通訊
            // ...

            // 關閉連線
            //socket.close();
        }*/
    }

    private static class Handler implements Runnable {
        private ClientObject clientObject;
        private String name;
        private final SSLSocket socket;
        private PrintWriter out;
        private BufferedReader in;


        public Handler(SSLSocket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try {
                out = new PrintWriter(socket.getOutputStream(), true);
                in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                name = in.readLine();
                System.out.println("[INFO]: "+ name + " join the chat. "+ "Ip: " + socket.getRemoteSocketAddress().toString());
                for (ClientObject stuff:clientObjects) {
                    if(stuff.getName().equalsIgnoreCase(name)){
                        out.println("REJECT:NAME_CONFLICT");
                        //System.err.println("Name conflict: " + name);
                        throw new Exception("Name conflict: " + name);
                    }
                }
                out.println("ACCEPT");
                System.out.println(name+" join the chat");
                for (ClientObject clients:clientObjects) {
                    clients.getPrinter().println(name+" join the chat");
                }

                clientObject = new ClientObject(name,socket,out);
                clientObjects.add(clientObject);

                while (true){
                    String line =in.readLine();
                    switch (line) {
                        case "null":break;
                        default: {
                            System.out.println("["+name+"]: "+line);
                            for (ClientObject clients:clientObjects) {
                                clients.getPrinter().println("["+name+"]: "+line);
                            }
                        }
                    }

                }

            } catch (Exception e) {
                System.err.println(e.getMessage());
            } finally {
                clientObjects.remove(clientObject);
                System.out.println("[INFO]: "+ name + " left the chat. "+ "Ip: " + socket.getRemoteSocketAddress().toString());
                try {
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        //End run
    }
}