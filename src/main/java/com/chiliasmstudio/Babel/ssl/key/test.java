package com.chiliasmstudio.Babel.ssl.key;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class test {
    public static void main(String[] args) throws Exception {
        // Generate root key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
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
                new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365)),
                new X500Name("CN=Root"),
                SubjectPublicKeyInfo.getInstance(rootPublicKey.getEncoded())
        );
        ContentSigner rootContentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(rootPrivateKey);
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
        ContentSigner intermediateContentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(rootPrivateKey);
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
        ContentSigner endEntityContentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(intermediatePrivateKey);
        X509CertificateHolder endEntityCertHolder = endEntityCertBuilder.build(endEntityContentSigner);
        X509Certificate endEntityCert = new JcaX509CertificateConverter().getCertificate(endEntityCertHolder);

        // Create certificate chain
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certChain = Arrays.asList(endEntityCert, intermediateCert, rootCert);


        // Save root certificate as CRT
        try (FileOutputStream fos = new FileOutputStream("root.crt")) {
            fos.write(rootCert.getEncoded());
        }

// Save intermediate certificate as CRT
        try (FileOutputStream fos = new FileOutputStream("intermediate.crt")) {
            fos.write(intermediateCert.getEncoded());
        }

// Save end certificate as CRT
        try (FileOutputStream fos = new FileOutputStream("end.crt")) {
            fos.write(endEntityCert.getEncoded());
        }
    }
}
