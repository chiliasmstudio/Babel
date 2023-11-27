package com.chiliasmstudio.Babel;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import javax.net.ssl.*;
import java.io.*;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Scanner;

public class Client {
    public static void main(String[] args) throws Exception {
        String trustCertFolderPath = "C:\\Users\\paul0\\code\\java\\Babel\\temp\\atrust"; // 信任憑證的資料夾路徑
        String clientCertPath = "C:\\Users\\paul0\\code\\java\\Babel\\temp\\client\\client_FullChain.pem"; // 客戶端憑證的路徑
        String clientKeyPath = "C:\\Users\\paul0\\code\\java\\Babel\\temp\\client\\client_PrivateKey.pem"; // 客戶端私鑰的路徑
        String clientKeyPassword = ""; // 客戶端私鑰的密碼

        // 載入信任的憑證
        TrustManager[] trustManagers = TESTcreateTrustManagers(trustCertFolderPath);

        // 載入客戶端憑證和私鑰
        KeyStore clientKeyStore = createKeyStore(clientKeyPath,clientCertPath,"client");
        //FileInputStream clientCertInput = new FileInputStream(clientCertPath);
        //FileInputStream clientKeyInput = new FileInputStream(clientKeyPath);
        //clientKeyStore.load(clientCertInput, clientKeyPassword.toCharArray());
        //clientCertInput.close();
        //clientKeyInput.close();

        // 建立 KeyManager，使用客戶端憑證和私鑰
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(clientKeyStore, clientKeyPassword.toCharArray());
        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

        // 建立 SSLContext，並設定 TrustManager 和 KeyManager
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagers, trustManagers, null);

        System.out.println(sslContext.getSupportedSSLParameters());
        System.out.println(Arrays.toString(sslContext.getSupportedSSLParameters().getCipherSuites()));

        // 建立 SSLSocketFactory
        SSLSocketFactory socketFactory = sslContext.getSocketFactory();

        // 建立 SSLSocket
        SSLSocket socket = (SSLSocket) socketFactory.createSocket("127.0.0.1", 81); // 請將 "server_hostname" 替換為實際的伺服器主機名稱
        //socket.startHandshake();
        System.out.println("Connect!");

        // 進行通訊
        Scanner in = new Scanner(socket.getInputStream());
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        //BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        String line;
        Thread.sleep(3000L);
        out.println("Hello");
        while (true) {
            out.println("Hello");
            //Thread.sleep(1000L);
        }

        // 關閉連線
        //reader.close();
        //socket.close();
    }

    /*private static TrustManager[] createTrustManagers(String trustCertFolderPath) throws Exception {
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
    }*/
    public static TrustManager[] TESTcreateTrustManagers(String trustCertFolderPath) throws Exception {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        KeyStore trustKeyStore = KeyStore.getInstance("PKCS12");
        String keyStorePassword = "changeit";
        trustKeyStore.load(null, keyStorePassword.toCharArray());

        // 載入信任的憑證
        File folder = new File(trustCertFolderPath);
        for (File file : folder.listFiles()) {
            if (file.isFile() && file.getName().endsWith(".pem")) {
                FileInputStream certInputStream = new FileInputStream(file);
                X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(certInputStream);
                trustKeyStore.setCertificateEntry(cert.getSubjectDN().getName(), cert);
            }
        }

        // 初始化 TrustManagerFactory
        trustManagerFactory.init(trustKeyStore);

        // 取得 TrustManager
        return trustManagerFactory.getTrustManagers();
    }

    public static KeyStore createKeyStore(String privateKeyPath, String certificatePath, String alias) throws Exception {
        // 註冊 Bouncy Castle 提供者
        Security.addProvider(new BouncyCastleProvider());

        // 創建空的 KeyStore 物件
        KeyStore keyStore = KeyStore.getInstance("PKCS12","BC");
        keyStore.load(null, null);

        // 載入私鑰
        PEMParser pemParser = new PEMParser(new FileReader(privateKeyPath));
        Object pemObject = pemParser.readObject();
        PrivateKey privateKey = new JcaPEMKeyConverter().setProvider("BC").getPrivateKey((PrivateKeyInfo) pemObject);
        pemParser.close();

        // 載入憑證
        FileInputStream certificateInput = new FileInputStream(certificatePath);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certificateInput);
        certificateInput.close();

        // 將私鑰和憑證存入 KeyStore
        keyStore.setKeyEntry(alias, privateKey, null, new X509Certificate[]{certificate});

        // DEBUG
        try {
            Enumeration<String> enumeration = keyStore.aliases();
            while(enumeration.hasMoreElements()) {
                String aliasA = enumeration.nextElement();
                System.out.println("alias name: " + aliasA);
                Certificate certificateA = keyStore.getCertificate(aliasA);
                System.out.println(certificate.toString());

                Key key = keyStore.getKey(alias,"".toCharArray());
                String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
                System.out.println("key ? " + encodedKey);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        return keyStore;
    }
}
