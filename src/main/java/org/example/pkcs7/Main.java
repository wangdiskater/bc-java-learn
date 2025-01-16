package org.example.pkcs7;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

public class Main {


    static {
        Security.addProvider(new BouncyCastleProvider());
    }


    private static String createP7() throws Exception {
        // 1. 生成 SM4 密钥
        KeyGenerator keyGenerator = KeyGenerator.getInstance("SM4", "BC");
        keyGenerator.init(128);
        SecretKey sm4Key = keyGenerator.generateKey();
        byte[] sm4KeyBytes = sm4Key.getEncoded();
        System.out.println("SM4 Key: " + Hex.toHexString(sm4KeyBytes));

        // 2. 用 SM4 加密数据
        String plaintext = "This is a test message for SM4 encryption!";
        byte[] encryptedContent = encryptWithSM4(plaintext.getBytes(), sm4KeyBytes);
        System.out.println("Encrypted Data (SM4): " + Hex.toHexString(encryptedContent));


        // 3.生成 SM2 密钥对
        KeyPair sm2KeyPair = generateSM2KeyPair();
        X509Certificate certificate = generateSelfSignedCertificate(sm2KeyPair, "CN=Recipient");

        // 4. 用 SM2 公钥加密 SM4 密钥
        byte[] encryptedKey = encryptWithSM2(sm2KeyPair.getPublic(), sm4KeyBytes);
        System.out.println("Encrypted SM4 Key (SM2): " + Hex.toHexString(encryptedKey));


        byte[] pkcs7 = buildPKCS7(encryptedContent, encryptedKey, certificate);


        System.out.println(Base64.toBase64String(pkcs7));
        return Base64.toBase64String(pkcs7);

    }
    public static void main(String[] args) throws Exception {

        String p7 = createP7();

        readP7(p7);

    }

    private static void readP7(String p7) throws Exception {
        byte[] decode = Base64.decode(p7);
        ASN1Sequence pkcs7Sequence = (ASN1Sequence) ASN1Primitive.fromByteArray(decode);
        ContentInfo contentInfo = ContentInfo.getInstance(pkcs7Sequence);


        // 解析 PKCS#7 EnvelopedData
        EnvelopedData envelopedData = EnvelopedData.getInstance(contentInfo.getContent());

        // 版本号
        System.out.println("Version: " + envelopedData.getVersion());

        // RecipientInfos
        ASN1Set recipientInfos = envelopedData.getRecipientInfos();
        for (int i = 0; i < recipientInfos.size(); i++) {
            RecipientInfo recipientInfo = RecipientInfo.getInstance(recipientInfos.getObjectAt(i));
            parseRecipientInfo(recipientInfo);
        }

        // EncryptedContentInfo
        EncryptedContentInfo encryptedContentInfo = envelopedData.getEncryptedContentInfo();
        parseEncryptedContentInfo(encryptedContentInfo);

    }


    private static void parseRecipientInfo(RecipientInfo recipientInfo) {
        // 获取 Recipient 信息
        KeyTransRecipientInfo keyTransRecipientInfo = KeyTransRecipientInfo.getInstance(recipientInfo.getInfo());
        IssuerAndSerialNumber issuerAndSerial = IssuerAndSerialNumber.getInstance(keyTransRecipientInfo.getRecipientIdentifier().getId());
        byte[] encryptedKey = keyTransRecipientInfo.getEncryptedKey().getOctets();

        System.out.println("Recipient Issuer: " + issuerAndSerial.getName());
        System.out.println("Recipient Serial Number: " + issuerAndSerial.getSerialNumber());
        System.out.println("Encrypted Key: " + Hex.toHexString(encryptedKey));
    }

    private static void parseEncryptedContentInfo(EncryptedContentInfo encryptedContentInfo) {
        // 获取加密内容信息
        String contentType = encryptedContentInfo.getContentType().getId();
        AlgorithmIdentifier encryptionAlgorithm = encryptedContentInfo.getContentEncryptionAlgorithm();
        byte[] encryptedContent = ((ASN1OctetString) encryptedContentInfo.getEncryptedContent()).getOctets();

        System.out.println("Content Type: " + contentType);
        System.out.println("Encryption Algorithm: " + encryptionAlgorithm.getAlgorithm());
        System.out.println("Encrypted Content: " + Hex.toHexString(encryptedContent));
    }

    public static byte[] buildPKCS7(byte[] encryptedContent, byte[] encryptedKey, X509Certificate recipientCert) throws Exception {
        // 1. RecipientInfo 接收人
        ASN1EncodableVector recipientInfos = new ASN1EncodableVector();
        recipientInfos.add(createRecipientInfo(encryptedKey, recipientCert));
        recipientInfos.add(createRecipientInfo(encryptedKey, recipientCert));

        // 2. EncryptedContentInfo 加密数据信息
//        AlgorithmIdentifier encAlgId = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.156.10197.1.104.2")); // SM4-CBC
        AlgorithmIdentifier encAlgId = new AlgorithmIdentifier(GMObjectIdentifiers.sms4_ecb); // SM4-ECB
        EncryptedContentInfo encContentInfo = new EncryptedContentInfo(
                PKCSObjectIdentifiers.data,
                encAlgId,
                new DEROctetString(encryptedContent)
        );

        // 3. EnvelopedData 完整信封
        ASN1EncodableVector envelopedData = new ASN1EncodableVector();
        envelopedData.add(new ASN1Integer(0)); // Version
        envelopedData.add(new DERSet(recipientInfos));
        envelopedData.add(encContentInfo);

        // 4. ContentInfo
        ContentInfo contentInfo = new ContentInfo(PKCSObjectIdentifiers.envelopedData, new DERSequence(envelopedData));

        // 5. Encode to DER
        return contentInfo.getEncoded("DER");
    }

    private static RecipientInfo createRecipientInfo(byte[] encryptedKey, X509Certificate cert) throws Exception {
        ASN1Integer version = new ASN1Integer(0);
        IssuerAndSerialNumber issuerAndSerial = new IssuerAndSerialNumber(
                new X500Name(cert.getIssuerX500Principal().getName()),
                cert.getSerialNumber()
        );

        KeyTransRecipientInfo recipientInfo = new KeyTransRecipientInfo(
                new RecipientIdentifier(issuerAndSerial),
//                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.156.10197.1.301")), // SM2 加密
                new AlgorithmIdentifier(GMObjectIdentifiers.sm2p256v1), // SM2 加密
                new DEROctetString(encryptedKey)
        );

        return new RecipientInfo(recipientInfo);
    }


    /**
     * 创建自签名证书
     */
    public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String subjectDN) throws Exception {
        // 设置证书有效期
        Date startDate = new Date();
        Date endDate = new Date(startDate.getTime() + 365L * 24 * 60 * 60 * 1000); // 有效期 1 年

        // 证书序列号
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());

        // 设置证书信息
        X500Name issuer = new X500Name(subjectDN);
        X500Name subject = issuer;

        // 构建证书
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serialNumber, startDate, endDate, subject, keyPair.getPublic());

        // 使用 SM2 签名算法生成签名
        ContentSigner signer = new JcaContentSignerBuilder("SM3withSM2").setProvider("BC").build(keyPair.getPrivate());

        // 转换为 X509Certificate
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));
    }

    // 用 SM4 加密数据
    private static byte[] encryptWithSM4(byte[] data, byte[] sm4Key) throws Exception {
        Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS5Padding", "BC");
        SecretKeySpec keySpec = new SecretKeySpec(sm4Key, "SM4");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }

    // 生成 SM2 密钥对
    private static KeyPair generateSM2KeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(new ECGenParameterSpec("sm2p256v1"), new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    // 用 SM2 公钥加密数据
    private static byte[] encryptWithSM2(PublicKey publicKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("SM2", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }
}