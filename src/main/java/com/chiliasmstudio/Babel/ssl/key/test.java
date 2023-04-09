package com.chiliasmstudio.Babel.ssl.key;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileOutputStream;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class test {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        // Generate root key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed448", "BC");
        //keyPairGenerator.initialize(4096, new SecureRandom());
        KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
        PublicKey rootPublicKey = rootKeyPair.getPublic();
        PrivateKey rootPrivateKey = rootKeyPair.getPrivate();

        // Generate intermediate key pair
        KeyPair intermediateKeyPair = keyPairGenerator.generateKeyPair();
        PublicKey intermediatePublicKey = intermediateKeyPair.getPublic();
        PrivateKey intermediatePrivateKey = intermediateKeyPair.getPrivate();

        // Generate end entity key pair
        KeyPair endEntityKeyPair = keyPairGenerator.generateKeyPair();
        PublicKey endEntityPublicKey = endEntityKeyPair.getPublic();
        PrivateKey endEntityPrivateKey = endEntityKeyPair.getPrivate();

        // Generate root certificate
        X509v3CertificateBuilder rootCertBuilder = new X509v3CertificateBuilder(
                new X500Name("CN=Root"),
                BigInteger.valueOf(1),
                new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24),
                new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365 * 20)),
                new X500Name("CN=Root"),
                SubjectPublicKeyInfo.getInstance(rootPublicKey.getEncoded())
        );

        // Set key usage
        KeyUsage keyUsage = new KeyUsage(
                  KeyUsage.cRLSign
                | KeyUsage.keyCertSign
                | KeyUsage.digitalSignature
                | KeyUsage.nonRepudiation
        );
        rootCertBuilder.addExtension(X509Extension.keyUsage, true, keyUsage);

        //rootCertBuilder.addExtension(Extension.extendedKeyUsage,true,new ExtendedKeyUsage(KeyPurposeId.getInstance(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.1"))));

        // 建立金鑰用途的 ASN1ObjectIdentifier 列表
        ASN1ObjectIdentifier[] purposes = {
                new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.1"), // 伺服器驗證ㄊ
                new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.2"), // 用戶端驗證
                new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.3"), // 程式碼簽署
                new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.4"), // 安全電子郵件
                new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.8"), // 時間戳記
                new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.9"), // OCSP 簽署
                new ASN1ObjectIdentifier("1.3.6.1.4.1.311.10.3.1"), // Microsoft 信任清單簽署
                new ASN1ObjectIdentifier("1.3.6.1.4.1.311.10.3.4") // 加密檔案系統
        };

        // 將金鑰用途加入到 ASN1EncodableVector 中
        ASN1EncodableVector keyPurposeVector = new ASN1EncodableVector();
        for (ASN1ObjectIdentifier purpose : purposes)
            keyPurposeVector.add(purpose);

        // 建立 ExtendedKeyUsage 物件
        ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(new DERSequence(keyPurposeVector));

        // 將 ExtendedKeyUsage 物件加入到憑證的延伸金鑰使用字段中
        rootCertBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.extendedKeyUsage,
                false,
                extendedKeyUsage
        );

        // 設定基本限制 (Basic Constraints)
        BasicConstraints basicConstraints = new BasicConstraints(true); // Subject Type 為 CA
        byte[] basicConstraintsExtensionValue = basicConstraints.getEncoded();
        rootCertBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, basicConstraintsExtensionValue);

        // 設定演算法為Ed448並生成憑證
        ContentSigner rootContentSigner = new JcaContentSignerBuilder("Ed448").build(rootPrivateKey);
        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootContentSigner);
        X509Certificate rootCert = new JcaX509CertificateConverter().getCertificate(rootCertHolder);


        // Generate intermediate certificate
        X509v3CertificateBuilder intermediateCertBuilder = new X509v3CertificateBuilder(
                new X500Name("CN=Root"),
                BigInteger.valueOf(2),
                new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24),
                new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365)),
                new X500Name("CN=Intermediate"),
                SubjectPublicKeyInfo.getInstance(intermediatePublicKey.getEncoded()));
        ContentSigner intermediateContentSigner = new JcaContentSignerBuilder("Ed448").build(rootPrivateKey);
        X509CertificateHolder intermediateCertHolder = intermediateCertBuilder.build(intermediateContentSigner);
        X509Certificate intermediateCert = new JcaX509CertificateConverter().getCertificate(intermediateCertHolder);

        // Generate end entity certificate
        X509v3CertificateBuilder endEntityCertBuilder = new X509v3CertificateBuilder(
                new X500Name("CN=Intermediate"),
                BigInteger.valueOf(3),
                new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24),
                new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365)),
                new X500Name("CN=End Entity"),
                SubjectPublicKeyInfo.getInstance(endEntityPublicKey.getEncoded())
        );
        ContentSigner endEntityContentSigner = new JcaContentSignerBuilder("Ed448").build(intermediatePrivateKey);
        X509CertificateHolder endEntityCertHolder = endEntityCertBuilder.build(endEntityContentSigner);
        X509Certificate endEntityCert = new JcaX509CertificateConverter().getCertificate(endEntityCertHolder);

        // Create certificate chain
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certChain = Arrays.asList(rootCert, intermediateCert, endEntityCert);
        JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter("./temp/fullchain.pem"));
        for (X509Certificate cert : certChain) {
            pemWriter.writeObject(cert);
        }
        pemWriter.close();

        // Save root certificate as CRT
        try (FileOutputStream fos = new FileOutputStream("./temp/root.crt")) {
            fos.write(rootCert.getEncoded());
        }

        // Save intermediate certificate as CRT
        try (FileOutputStream fos = new FileOutputStream("./temp/intermediate.crt")) {
            fos.write(intermediateCert.getEncoded());
        }

        // Save end certificate as CRT
        try (FileOutputStream fos = new FileOutputStream("./temp/end.crt")) {
            fos.write(endEntityCert.getEncoded());
        }
    }


    public static ExtendedKeyUsage setExtendedKeyUsage() {
        List<ASN1ObjectIdentifier> purposes = new ArrayList<>();

        // 伺服器驗證 (1.3.6.1.5.5.7.3.1)
        purposes.add(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.1"));

        // 用戶端驗證 (1.3.6.1.5.5.7.3.2)
        purposes.add(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.2"));

        // 程式碼簽署 (1.3.6.1.5.5.7.3.3)
        purposes.add(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.3"));

        // 安全電子郵件 (1.3.6.1.5.5.7.3.4)
        purposes.add(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.4"));

        // 時間戳記 (1.3.6.1.5.5.7.3.8)
        purposes.add(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.8"));

        // OCSP 簽署 (1.3.6.1.5.5.7.3.9)
        purposes.add(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.9"));

        // Microsoft 信任清單簽署 (1.3.6.1.4.1.311.10.3.1)
        purposes.add(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.10.3.1"));

        // 加密檔案系統 (1.3.6.1.4.1.311.10.3.4)
        purposes.add(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.10.3.4"));
        return null;
        //return new ExtendedKeyUsage(purposes.toArray(new ASN1ObjectIdentifier[0]));
    }


}
