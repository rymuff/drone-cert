package com.kweisa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

public class Main {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        CertificateAuthority certificateAuthority = new CertificateAuthority("ca.cert");

        Certificate serverCertificate = Certificate.read("server.cert");
        Certificate clientCertificate = Certificate.read("client.cert");

        System.out.println(serverCertificate.verify(certificateAuthority.getPublic()));
        System.out.println(clientCertificate.verify(certificateAuthority.getPublic()));
    }
}
