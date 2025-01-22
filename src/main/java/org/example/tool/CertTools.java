package org.example.tool;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertTools {

    public static final String BC               = BouncyCastleProvider.PROVIDER_NAME;
    public static UuidGenerator uuidGenerator = new UuidGenerator();
    public static final String SUN              = "SUN";
    public static final String SUN_JCE          = "SunJCE";

    public static final String TYPE_JKS         = "JKS";
    public static final String TYPE_JCEKS       = "JCEKS";
    public static final String TYPE_BKS         = "BKS";
    public static final String TYPE_PKCS12      = "PKCS12";
    public static final String TYPE_UBER        = "UBER";
    public static final String TYPE_X509        = "X.509";

    /**
     * 获取DN(Distinct Name)构造者<br>
     * {@see <a href="https://www.ibm.com/support/knowledgecenter/en/SSFKSJ_7.5.0/com.ibm.mq.sec.doc/q009860_.htm"></a>}
     *
     * @return X500NameBuilder
     */
    public static X500NameBuilder createStdBuilder(String cn, String c, String o, String st, String l, String e) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, cn);                 // 通用名称
        builder.addRDN(BCStyle.C,   c);                 // 国家代码
        builder.addRDN(BCStyle.O,   o);                 // 组织
        builder.addRDN(BCStyle.ST, st);                 // 省份
        builder.addRDN(BCStyle.L,   l);                 // 地区
        builder.addRDN(BCStyle.E,   e);                 // 邮箱
        return builder;
    }

    /**
     * 获取扩展密钥用途
     * @return 增强密钥用法ASN.1对象
     */
    public static DERSequence extendedKeyUsage() {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(KeyPurposeId.id_kp_clientAuth);              // 客户端身份认证
        vector.add(KeyPurposeId.id_kp_emailProtection);         // 安全电子邮件
        return new DERSequence(vector);
    }

    public static PKCS10CertificationRequest generateCertificationRequest(X500Name subject, KeyPair kp) throws Exception {
        PublicKey pubKey = kp.getPublic();
        PrivateKey privKey = kp.getPrivate();
        AsymmetricKeyParameter pubkeyParam = PublicKeyFactory.createKey(pubKey.getEncoded());
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pubkeyParam);
        PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(subject, publicKeyInfo);
        AlgorithmIdentifier signatureAi = new AlgorithmIdentifier(OIWObjectIdentifiers.sha1WithRSA);
        //AlgorithmIdentifier signatureAi = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.14.3.2.29"));                     //sha1WithRSA
        //AlgorithmIdentifier signatureAi = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"));              //sha1WithRSA
        //AlgorithmIdentifier signatureAi = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11"));             //sha256WithRSA
        //AlgorithmIdentifier signatureAi = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.13"));             //sha512WithRSA
        //AlgorithmIdentifier signatureAi = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.4.1"));                 //SHA1WITHECDSA
        //AlgorithmIdentifier signatureAi = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.4.3.2"));               //SHA256WITHECDSA
        //AlgorithmIdentifier signatureAi = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.4.3.4"));               //SHA512WITHECDSA
        //AlgorithmIdentifier signatureAi = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.156.10197.1.501"));               //SM3WITHSM2
        //AlgorithmIdentifier signatureAi = new AlgorithmIdentifier(GMObjectIdentifiers.sm2sign_with_sm3,DERNull.INSTANCE);         //SM3WITHSM2
        //AlgorithmIdentifier signatureAi = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.156.10197.1.502"));               //SHA1WITHSM2
        //AlgorithmIdentifier signatureAi = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.156.10197.1.503"));               //SHA256WITHSM2
        //AlgorithmIdentifier signatureAi =new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption,DERNull.INSTANCE); //SHA256WITHSM2
        //AlgorithmIdentifier signatureAi = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.156.10197.1.504"));               //SHA512WITHSM2
        BcRSAContentSignerBuilder signerBuilder = new BcRSAContentSignerBuilder(signatureAi, AlgorithmIdentifier.getInstance(OIWObjectIdentifiers.idSHA1));
        AsymmetricKeyParameter pkParam = PrivateKeyFactory.createKey(privKey.getEncoded());
        ContentSigner signer = signerBuilder.build(pkParam);

        return builder.build(signer);
    }


    public static AlgorithmIdentifier getSignAlgo(AlgorithmIdentifier asymAlgo) {  //根据公钥算法标识返回对应签名算法标识
        if(asymAlgo.getAlgorithm().equals(X9ObjectIdentifiers.id_ecPublicKey) && asymAlgo.getParameters().equals(GMObjectIdentifiers.sm2p256v1)) {
            return new AlgorithmIdentifier(GMObjectIdentifiers.sm2sign_with_sm3, DERNull.INSTANCE);
        }else if(asymAlgo.getAlgorithm().equals(PKCSObjectIdentifiers.rsaEncryption)) {
            return new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE);
        } else {
            throw new IllegalArgumentException("密钥算法不支持");
        }
    }


    /**
     *  byte[] 转成证书格式，只支持der编码
     * @param certData
     * @return
     * @throws Exception
     */
    public static X509Certificate toCert(byte[] certData) throws Exception {
        X509CertificateHolder holder = new X509CertificateHolder(certData);
        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(holder);
    }

    public static GeneralName[] getSubAlternativeName(X509Certificate cert) throws Exception {
        TBSCertificate tbsCert = TBSCertificate.getInstance(cert.getTBSCertificate());
        Extension ext = tbsCert.getExtensions().getExtension(Extension.subjectAlternativeName);
        GeneralNames generalNames = GeneralNames.getInstance(ext.getParsedValue());
        GeneralName[] names = generalNames.getNames();
        return names;
    }

    public static X509Certificate getCertDafault(String cert) throws Exception {
        X509Certificate cert509 = null;
        String dstCert = StoreReader.parseCert(cert);
        byte[] certBytes;
        if(dstCert.contains("BEGIN")) {
            certBytes = dstCert.getBytes();
        }else{
            certBytes = Hex.decode(dstCert);
        }
        return StoreReader.getCertificate(certBytes);
    }

}
