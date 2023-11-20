package com.chiliasmstudio.Babel;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.net.ssl.*;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.*;


public class SocketServer {
    public static void main(String[] args) throws Exception {

        String trustCertFolderPath = "C:\\code\\Babel\\temp\\atrust"; // 信任憑證的資料夾路徑
        String serverCertPath = "C:\\code\\Babel\\temp\\server\\server_FullChain.pem"; // 伺服器憑證的路徑
        String serverKeyPath = "C:\\code\\Babel\\temp\\server\\server_PrivateKey.pem"; // 伺服器私鑰的路徑
        String serverKeyPassword = ""; // 伺服器私鑰的密碼

        // 載入信任的憑證
        TrustManager[] trustManagers = TESTcreateTrustManagers(trustCertFolderPath);

        // 載入伺服器憑證和私鑰
        KeyStore serverKeyStore = createKeyStore(serverKeyPath,serverCertPath,"server");//KeyStore.getInstance("PKCS12");
        FileInputStream serverCertInput = new FileInputStream(serverCertPath);
        FileInputStream serverKeyInput = new FileInputStream(serverKeyPath);
        //serverKeyStore.load(serverCertInput, null);
        serverCertInput.close();
        serverKeyInput.close();

        // 建立 KeyManager，使用伺服器憑證和私鑰
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(serverKeyStore, serverKeyPassword.toCharArray());
        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

        // 建立 SSLContext，並設定 TrustManager 和 KeyManager
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagers, trustManagers, null);

        // 建立 SSLServerSocketFactory
        SSLServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();

        // 建立 SSLServerSocket
        SSLServerSocket serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(65534);

        System.out.println("Server start!");
        while (true) {
            // 等待客戶端連線
            SSLSocket socket = (SSLSocket) serverSocket.accept();

            // 進行通訊
            // ...

            // 關閉連線
            socket.close();
        }
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

    public static KeyStore loadServerKeyStore(String serverCertPath, String serverKeyPath) throws Exception {
        // 註冊 Bouncy Castle 提供者
        Security.addProvider(new BouncyCastleProvider());

        // 創建空的 KeyStore 物件
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);

        // 載入伺服器憑證
        FileInputStream certInput = new FileInputStream(serverCertPath);
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(certInput);
        certInput.close();

        // 載入伺服器私鑰
        FileInputStream keyInput = new FileInputStream(serverKeyPath);
        byte[] keyBytes = new byte[keyInput.available()];
        keyInput.read(keyBytes);
        keyInput.close();
        System.out.println(new String((keyBytes)));


        // 將伺服器憑證和私鑰存入 KeyStore
        List<X509Certificate> certificateChain = new ArrayList<>();
        certificateChain.add(certificate);
        //keyStore.setKeyEntry("server", loadPrivateKey(serverKeyPath).getEncoded(), certificateChain.toArray(new X509Certificate[0]));

        return keyStore;
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