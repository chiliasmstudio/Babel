package com.chiliasmstudio.Babel;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.security.KeyStore;

public class SocketServer {
    private static final int PORT = 8888;
    private static final String KEYSTORE_PATH = "/path/to/keystore.jks";
    private static final String KEYSTORE_PASSWORD = "keystore_password";

    public static void main(String[] args) {
        try {
            // 載入憑證
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream(KEYSTORE_PATH), KEYSTORE_PASSWORD.toCharArray());

            // 初始化 SSL 上下文
            SSLContext sslContext = SSLContext.getInstance("TLS");
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
            trustManagerFactory.init(keyStore);
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

            // 建立 SSLServerSocket
            SSLServerSocketFactory socketFactory = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) socketFactory.createServerSocket(PORT);

            // 只接受受信任的憑證連線
            serverSocket.setNeedClientAuth(true);

            System.out.println("等待客戶端連線...");
            SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
            System.out.println("已建立連線");

            // 在此處處理客戶端連線

            // 關閉連線
            clientSocket.close();
            serverSocket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}