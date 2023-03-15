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

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;

public class test {
    public static void main(String[] args) throws Exception {
        // Generate root certificate
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
        KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
        PrivateKey rootPrivateKey = rootKeyPair.getPrivate();
        PublicKey rootPublicKey = rootKeyPair.getPublic();

        X500Name rootIssuer = new X500Name("CN=Root");
        BigInteger rootSerial = BigInteger.valueOf(new SecureRandom().nextInt());

        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365 * 24 * 60 * 60 * 1000L);

        X509v3CertificateBuilder rootCertBuilder = new X509v3CertificateBuilder(
                rootIssuer,
                rootSerial,
                notBefore,
                notAfter,
                rootIssuer,
                SubjectPublicKeyInfo.getInstance(rootPublicKey.getEncoded())
        );

        rootCertBuilder.addExtension(
                Extension.basicConstraints,
                true,
                new BasicConstraints(true)
        );

        rootCertBuilder.addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)
        );

        ContentSigner rootContentSigner = new BcRSAContentSignerBuilder(
                new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA"),
                new DefaultDigestAlgorithmIdentifierFinder().find("SHA-256")
        ).build(PrivateKeyFactory.createKey(rootPrivateKey.getEncoded()));

        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootContentSigner);
        X509Certificate rootCert = new JcaX509CertificateConverter().getCertificate(rootCertHolder);


        // Generate intermediate certificate
        KeyPair intermediateKeyPair = keyPairGenerator.generateKeyPair();
        PrivateKey intermediatePrivateKey = intermediateKeyPair.getPrivate();
        PublicKey intermediatePublicKey = intermediateKeyPair.getPublic();

        X500Name intermediateIssuer = new X500Name("CN=Intermediate");
        BigInteger intermediateSerial = BigInteger.valueOf(new SecureRandom().nextInt());

        X509v3CertificateBuilder intermediateCertBuilder = new X509v3CertificateBuilder(
                rootIssuer,
                intermediateSerial,
                notBefore,
                notAfter,
                intermediateIssuer,
                SubjectPublicKeyInfo.getInstance(intermediatePublicKey.getEncoded())
        );

        intermediateCertBuilder.addExtension(
                Extension.basicConstraints,
                true,
                new BasicConstraints(true)
        );

        intermediateCertBuilder.addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)
        );

        ContentSigner intermediateContentSigner = new BcRSAContentSignerBuilder(
                new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA"),
                new DefaultDigestAlgorithmIdentifierFinder().find("SHA-256")
        ).build(PrivateKeyFactory.createKey(rootPrivateKey.getEncoded()));

        X509CertificateHolder intermediateCertHolder = intermediateCertBuilder.build(intermediateContentSigner);
        X509Certificate intermediateCert = new JcaX509CertificateConverter().getCertificate(intermediateCertHolder);

        // Generate end certificate
        KeyPair endKeyPair = keyPairGenerator.generateKeyPair();
        PrivateKey endPrivateKey = endKeyPair.getPrivate();
        PublicKey endPublicKey = endKeyPair.getPublic();

        X500Name endIssuer = new X500Name("CN=End");
        BigInteger endSerial = BigInteger.valueOf(new SecureRandom().nextInt());

        X509v3CertificateBuilder endCertBuilder = new X509v3CertificateBuilder(
                intermediateIssuer,
                endSerial,
                notBefore,
                notAfter,
                endIssuer,
                SubjectPublicKeyInfo.getInstance(endPublicKey.getEncoded())
        );

        endCertBuilder.addExtension(
                Extension.basicConstraints,
                true,
                new BasicConstraints(false)
        );

        ContentSigner endContentSigner = new BcRSAContentSignerBuilder(
                new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA"),
                new DefaultDigestAlgorithmIdentifierFinder().find("SHA-256")
        ).build(PrivateKeyFactory.createKey(intermediatePrivateKey.getEncoded()));

        X509CertificateHolder endCertHolder = endCertBuilder.build(endContentSigner);
        X509Certificate endCert = new JcaX509CertificateConverter().getCertificate(endCertHolder);

        // TODO: Save certificates in desired formats (Java KeyStore, CRT, PFX)

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
            fos.write(endCert.getEncoded());
        }
    }
}
