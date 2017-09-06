package com.kweisa.certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.security.Security;

public class Main {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        CertificateAuthority certificateAuthority = CertificateAuthority.read("ca.keypair");

        Certificate serverCertificate = Certificate.read("server.cert");
        System.out.println(certificateAuthority.verifyCertificate(serverCertificate));
        d("serverCert", serverCertificate.getEncoded());

        Certificate clientCertificate = Certificate.read("client.cert");
        System.out.println(certificateAuthority.verifyCertificate(clientCertificate));
        d("clientCert", clientCertificate.getEncoded());
    }

    void generate() throws Exception {
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

    public static void d(String tag, byte[] message) {
        System.out.println(tag + ": " + Hex.toHexString(message));
    }
}
