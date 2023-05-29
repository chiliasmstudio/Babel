package com.chiliasmstudio.Babel;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class Client {
    public static void main(String[] args) throws Exception {
        String trustCertFolderPath = "/path/to/trust_certificates_folder"; // 信任憑證的資料夾路徑
        String clientCertPath = "/path/to/client_certificate.pem"; // 客戶端憑證的路徑
        String clientKeyPath = "/path/to/client_private_key.pem"; // 客戶端私鑰的路徑
        String clientKeyPassword = "client_key_password"; // 客戶端私鑰的密碼

        // 載入信任的憑證
        TrustManager[] trustManagers = createTrustManagers(trustCertFolderPath);

        // 載入客戶端憑證和私鑰
        KeyStore clientKeyStore = KeyStore.getInstance("PKCS12");
        FileInputStream clientCertInput = new FileInputStream(clientCertPath);
        FileInputStream clientKeyInput = new FileInputStream(clientKeyPath);
        clientKeyStore.load(clientCertInput, clientKeyPassword.toCharArray());
        clientCertInput.close();
        clientKeyInput.close();

        // 建立 KeyManager，使用客戶端憑證和私鑰
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(clientKeyStore, clientKeyPassword.toCharArray());
        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

        // 建立 SSLContext，並設定 TrustManager 和 KeyManager
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagers, trustManagers, null);

        // 建立 SSLSocketFactory
        SSLSocketFactory socketFactory = sslContext.getSocketFactory();

        // 建立 SSLSocket
        SSLSocket socket = (SSLSocket) socketFactory.createSocket("server_hostname", 65534); // 請將 "server_hostname" 替換為實際的伺服器主機名稱
        socket.startHandshake();

        // 進行通訊
        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }

        // 關閉連線
        reader.close();
        socket.close();
    }

    private static TrustManager[] createTrustManagers(String trustCertFolderPath) throws Exception {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        KeyStore trustKeyStore = KeyStore.getInstance("PKCS12");

        // 載入信任的憑證
        FileInputStream trustCertInput = new FileInputStream(trustCertFolderPath);
        trustKeyStore.load(trustCertInput, null);
        trustCertInput.close();

        // 初始化 TrustManagerFactory
        trustManagerFactory.init(trustKeyStore);

        // 取得 TrustManager
        return trustManagerFactory.getTrustManagers();
    }
}
