package com.chiliasmstudio.Babel.server;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.security.Security;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


public class Server {
    private static Set<SSLSocket> clientsSocket = new HashSet<>();

    public static void main(String[] args) throws Exception {
        //System.setProperty("javax.net.debug", "ssl:handshake");
        Security.addProvider(new BouncyCastleProvider());

        // 載入信任的憑證
        KeyStore trustKeyStore = KeyStore.getInstance("PKCS12");
        trustKeyStore.load(new FileInputStream(".\\Xtemp\\Xtrust.pfx"), "".toCharArray());
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustKeyStore);
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();


        // 載入伺服器憑證和私鑰
        KeyStore serverKeyStore = KeyStore.getInstance("PKCS12");
        serverKeyStore.load(new FileInputStream(".\\Xtemp\\server.pfx"), "".toCharArray());

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(serverKeyStore, "".toCharArray());

        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

        // 建立 SSLContext，並設定 TrustManager 和 KeyManager
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(keyManagers, trustManagers, null);

        // 建立 SSLServerSocketFactory
        SSLServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();

        // 建立 SSLServerSocket
        SSLServerSocket serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(81);
        serverSocket.setNeedClientAuth(true);
        serverSocket.setEnabledProtocols(new String[]{"TLSv1.3"});
        System.out.println("Server start!");
        ExecutorService pool = Executors.newFixedThreadPool(8);

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
        private final SSLSocket socket;
        private PrintWriter out;
        private BufferedReader in;

        public Handler(SSLSocket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            System.out.println("New client connect");
            System.out.println("ip: " + socket.getRemoteSocketAddress().toString());
            try {
                out = new PrintWriter(socket.getOutputStream(), true);
                in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                clientsSocket.add(socket);
                out.println("Hello world!");
                while (true)
                    System.out.println(in.readLine());
            } catch (Exception e) {
                System.err.println(e.getMessage());
            } finally {
                clientsSocket.remove(socket);
                System.out.println("Client quit");
                System.out.println("ip: " + socket.getRemoteSocketAddress().toString());
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