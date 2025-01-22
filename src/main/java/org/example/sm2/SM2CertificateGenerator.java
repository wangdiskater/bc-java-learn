package org.example.sm2;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

/**
 * @ClassName SM2CertificateGenerator
 * @Description sm2证书格式
 * @Author Dwang
 * @Date 2025/1/17 18:07
 * @Update
 */
public class SM2CertificateGenerator {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static X509Certificate generateCertificate(KeyPair keyPair, String subjectDN, String usageOID, int keyUsage) throws Exception {
        // 证书有效期
        Date startDate = new Date();
        Date endDate = new Date(startDate.getTime() + 365L * 24 * 60 * 60 * 1000); // 1年

        // 证书序列号
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());

        // 构建证书生成器
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                new org.bouncycastle.asn1.x500.X500Name("CN=Issuer"),
                serialNumber,
                startDate,
                endDate,
                new org.bouncycastle.asn1.x500.X500Name(subjectDN),
                keyPair.getPublic()
        );

        // 添加 Key Usage
        certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.keyUsage,
                true,
                new KeyUsage(keyUsage)
        );

        // 添加 Extended Key Usage
        certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.extendedKeyUsage,
                true,
                new org.bouncycastle.asn1.DERSequence(new ASN1ObjectIdentifier(usageOID))
        );

        // 签名算法
        ContentSigner signer = new JcaContentSignerBuilder("SM3withSM2").setProvider("BC").build(keyPair.getPrivate());

        // 构建证书并转换为 X509Certificate
        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
    }






    public static void main(String[] args) throws Exception {
        // 生成 SM2 密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(new ECGenParameterSpec("sm2p256v1"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // 签名证书
        System.out.println("签名证书");
        X509Certificate signingCert = generateCertificate(keyPair, "CN=Signing", "1.2.156.10197.1.501", KeyUsage.digitalSignature);
        System.out.println("Signing Certificate OID: " + signingCert.getSigAlgName());
        System.out.println(Base64.toBase64String(signingCert.getEncoded()));


        // 加密证书
        X509Certificate encryptionCert = generateCertificate(keyPair, "CN=Encryption", "1.2.156.10197.1.301", KeyUsage.keyEncipherment);
        System.out.println("Encryption Certificate OID: " + encryptionCert.getSigAlgName());
        System.out.println("加密证书");
        System.out.println(Base64.toBase64String(encryptionCert.getEncoded()));



        // 密钥交换证书
        X509Certificate exchangeCert = generateCertificate(keyPair, "CN=KeyExchange", "1.2.156.10197.1.401", KeyUsage.keyAgreement);
        System.out.println("Key Exchange Certificate OID: " + exchangeCert.getSigAlgName());
        System.out.println("密钥交换证书");
        System.out.println(Base64.toBase64String(exchangeCert.getEncoded()));


    }
}
