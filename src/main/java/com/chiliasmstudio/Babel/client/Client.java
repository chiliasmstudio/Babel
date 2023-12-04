package com.chiliasmstudio.Babel.client;

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

        // 進行通訊
        Scanner in = new Scanner(socket.getInputStream());
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        Thread.sleep(3000L);
        out.println("Hello");
        MessageHandler messageHandler = new MessageHandler();
        messageHandler.start();
        while (true) {
            out.println("Hello");
            Thread.sleep(5000L);
        }

        // 關閉連線
        //reader.close();
        //socket.close();
    }

    static class MessageHandler extends Thread {
        public void run() {
            System.out.println("Hello");
        }
    }
}


