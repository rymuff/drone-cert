package com.kweisa.certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

public class Main {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        generate();

//        CertificateAuthority certificateAuthority = CertificateAuthority.read("ca.keypair");
//
//        Certificate serverCertificate = Certificate.read("server.cert", "server.key");
//        System.out.println(certificateAuthority.verifyCertificate(serverCertificate));
//        d("serverCert", serverCertificate.getEncoded());
//
//        Certificate clientCertificate = Certificate.read("client.cert", "client.key");
//        System.out.println(certificateAuthority.verifyCertificate(clientCertificate));
//        d("clientCert", clientCertificate.getEncoded());
//
//        AlgorithmParameterSpec algorithmParameterSpec = new ECGenParameterSpec("secp256r1");
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME);
//        kpg.initialize(algorithmParameterSpec);
//
//        KeyPair keyPair = kpg.generateKeyPair();
////        KeyPair keyPair = clientCertificate.getKeyPair();
//
//        String plainText = "Hello, World!asdfasdfasdfasdf";
//        Cipher cipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
//
//
//        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
//        byte[] cipherText = cipher.doFinal(plainText.getBytes());
//        d("cipher", cipherText);
//
//        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
//        System.out.println(new String(cipher.doFinal(cipherText)));
    }

    private static void generate() throws Exception {
        CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.write("ca.keypair");

        Certificate serverCertificate = certificateAuthority.generateEncodedCertificate(
                Hex.decode("11"),
                Hex.decode("2222"),
                System.currentTimeMillis(),
                System.currentTimeMillis() + 60 * 60 * 24,
                Hex.decode("44444444"));
        serverCertificate.write("server.cert", "server.key");

        Certificate clientCertificate = certificateAuthority.generateEncodedCertificate(
                Hex.decode("11"),
                Hex.decode("2222"),
                System.currentTimeMillis(),
                System.currentTimeMillis() + 60 * 60 * 24,
                Hex.decode("44444444"));
        clientCertificate.write("client.cert", "client.key");
    }

    private static void d(String tag, byte[] message) {
        System.out.println(tag + ": " + Hex.toHexString(message));
    }
}
