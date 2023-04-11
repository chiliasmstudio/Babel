package com.chiliasmstudio.Babel.ssl.key;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class test2 {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        // Generate root key pair.
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed448", "BC");
        KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
        PublicKey rootPublicKey = rootKeyPair.getPublic();
        PrivateKey rootPrivateKey = rootKeyPair.getPrivate();
        System.out.println(rootKeyPair.getPrivate().getFormat());
        // Generate intermediate key pair.
        KeyPair intermediateKeyPair = keyPairGenerator.generateKeyPair();
        PublicKey intermediatePublicKey = intermediateKeyPair.getPublic();
        PrivateKey intermediatePrivateKey = intermediateKeyPair.getPrivate();

        // Generate end entity key pair.
        KeyPair endEntityKeyPair = keyPairGenerator.generateKeyPair();
        PublicKey endEntityPublicKey = endEntityKeyPair.getPublic();
        PrivateKey endEntityPrivateKey = endEntityKeyPair.getPrivate();

        // Generate root certificate.
        X509v3CertificateBuilder rootCertBuilder = new X509v3CertificateBuilder(
                new X500Name("CN=Root"),
                BigInteger.valueOf(1),
                new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24),
                new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365 * 20)),
                new X500Name("CN=Root"),
                SubjectPublicKeyInfo.getInstance(rootPublicKey.getEncoded())
        );

        // Key usage.
        KeyUsage keyUsage = new KeyUsage(
                KeyUsage.cRLSign
                        | KeyUsage.keyCertSign
                        //| KeyUsage.dataEncipherment
                        | KeyUsage.digitalSignature
                        | KeyUsage.nonRepudiation
                        //| KeyUsage.keyEncipherment
                        //| KeyUsage.keyAgreement
                        //| KeyUsage.encipherOnly
                        //| KeyUsage.decipherOnly
        );
        rootCertBuilder.addExtension(X509Extension.keyUsage, true, keyUsage);

        // Key usage extension.
        ASN1ObjectIdentifier[] purposes = {
                // new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.1"), // Server authentication
                // new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.2"), // Client authentication
                // new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.3"), // Code signing
                // new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.4"), // Secure email
                //new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.8"), // Timestamping
                //new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.9"), // OCSP signing
                // new ASN1ObjectIdentifier("1.3.6.1.4.1.311.10.3.1"), // Microsoft trust list signing
                // new ASN1ObjectIdentifier("1.3.6.1.4.1.311.10.3.4") // Encrypted file system
        };
        ASN1EncodableVector keyPurposeVector = new ASN1EncodableVector();
        for (ASN1ObjectIdentifier purpose : purposes)
            keyPurposeVector.add(purpose);
        ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(new DERSequence(keyPurposeVector));
        rootCertBuilder.addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage);

        // Basic Constraints.
        BasicConstraints basicConstraints = new BasicConstraints(true); // Subject Type 為 CA
        byte[] basicConstraintsExtensionValue = basicConstraints.getEncoded();
        rootCertBuilder.addExtension(Extension.basicConstraints, true, basicConstraintsExtensionValue);

        // Set the algorithm to Ed448 and  generating the certificate.
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


        // Save root certificate as pem
        try (FileOutputStream fos = new FileOutputStream("./temp/root.pem")) {
            fos.write(convertToPemWithKey(rootCert,rootPrivateKey).getBytes());
        }

        // Save root certificate as CRT
        try (FileOutputStream fos = new FileOutputStream("./temp/root.crt")) {
            fos.write(convertToPem(rootCert).getBytes());
        }
        
        StringWriter stringWriter = new StringWriter();
        PEMWriter pemWriter2 = new PEMWriter(stringWriter);
        pemWriter2.writeObject(rootKeyPair.getPrivate());
        pemWriter2.close();
        // Save root private as .key file.
        try (FileOutputStream fos = new FileOutputStream("./temp/rootPrivate.key")) {
            fos.write(stringWriter.toString().getBytes());
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


    public static String convertToPem(X509Certificate cert) throws Exception {
        StringWriter sw = new StringWriter();
        PemWriter pw = new PemWriter(sw);
        pw.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
        pw.close();
        return sw.toString();
    }

    public static String convertPrivateKeyToPem(KeyPair keyPair) throws IOException {
        StringWriter stringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
        pemWriter.writeObject(keyPair.getPrivate());
        pemWriter.flush();
        pemWriter.close();
        return stringWriter.toString();
    }

    public static String convertToPemWithKey(X509Certificate cert, PrivateKey privateKey) throws Exception {
        StringWriter sw = new StringWriter();
        JcaPEMWriter pw = new JcaPEMWriter(sw);
        pw.writeObject(cert);
        pw.writeObject(privateKey);
        pw.flush();
        pw.close();
        return sw.toString();
    }

}
