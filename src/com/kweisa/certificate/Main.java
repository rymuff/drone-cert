package com.kweisa.certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.security.Security;

public class Main {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

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

        serverCertificate = Certificate.read("server.cert");
        serverCertificate.verify(certificateAuthority.getPublic());
    }
}
