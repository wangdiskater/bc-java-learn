package org.example.tool;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class StoreReader {

    /**
     * X.509 证书 ASNI1编码 : .cer/.crt/.rsa
     * @param path
     * @return
     * @throws Exception
     */
    public static X509Certificate readCert(String path) throws Exception {
        return readCert(path, false);
    }

    /**
     *  X.509 证书 ASNI1编码/BSAE64编码 : .cer/.crt/.rsa
     * @param path
     * @param isBase64
     * @return
     * @throws Exception
     */
    public static X509Certificate readCert(String path, boolean isBase64) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance(CertTools.TYPE_X509, CertTools.BC);
        FileInputStream fis = new FileInputStream(path);

        X509Certificate cert;
        if (isBase64) {
            byte[] base64EncodedCert = new byte[fis.available()];
            fis.read(base64EncodedCert);
            byte[] asn1BinCert = Base64.decode(base64EncodedCert);

            InputStream in = new ByteArrayInputStream(asn1BinCert);
            cert = (X509Certificate) cf.generateCertificate(in);
            in.close();
        } else {
            cert = (X509Certificate) cf.generateCertificate(fis);
        }
        fis.close();
        return cert;
    }

    /**
     *  读取pem证书并转成X.509格式
     * @param path
     * @return
     * @throws IOException
     * @throws CertificateException
     */
    public static X509Certificate readCertPem(String path) throws IOException, CertificateException {
        PemReader pRd = new PemReader(new InputStreamReader(new FileInputStream(path)));
        PemObject pem = pRd.readPemObject();
        pRd.close();
        return new JcaX509CertificateConverter().setProvider(CertTools.BC).getCertificate(new X509CertificateHolder(pem.getContent()));
    }

    public static X509Certificate readCertPem(InputStream in) throws IOException, CertificateException {
        PemReader pRd = new PemReader(new InputStreamReader(in));
        PemObject pem = pRd.readPemObject();
        pRd.close();
        return new JcaX509CertificateConverter().setProvider(CertTools.BC).getCertificate(new X509CertificateHolder(pem.getContent()));
    }

    /**
     * 读取CRL文件
     * @param path
     * @return
     * @throws IOException
     * @throws CRLException
     */
    public static X509CRL readCrlPem(String path) throws IOException, CRLException {
        PemReader pRd = new PemReader(new InputStreamReader(new FileInputStream(path)));
        PemObject pem = pRd.readPemObject();
        pRd.close();
        return new JcaX509CRLConverter().setProvider(CertTools.BC).getCRL(new X509CRLHolder(pem.getContent()));
    }

    /**
     * 读取CRL文件
     * @param in
     * @return
     * @throws IOException
     * @throws CRLException
     */
    public static X509CRL readCrlPem(InputStream in) throws IOException, CRLException {
        PemReader pRd = new PemReader(new InputStreamReader(in));
        PemObject pem = pRd.readPemObject();
        pRd.close();
        return new JcaX509CRLConverter().setProvider(CertTools.BC).getCRL(new X509CRLHolder(pem.getContent()));
    }

    /**
     * 读取CRL文件
     * @param data
     * @return
     * @throws IOException
     * @throws CRLException
     */
    public static X509CRL readCrlPem(byte[] data) throws IOException, CRLException {
        return readCrlPem(new ByteArrayInputStream(data));
    }

    /**
     * byte[] 转成证书格式，支持der编码、base64编码
     * @param data
     * @return
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchProviderException
     */
    public static X509Certificate getCertificate(byte[] data) throws CertificateException, IOException, NoSuchProviderException {
        return getCertificate(new ByteArrayInputStream(data));
    }

    public static X509Certificate getCertificate(InputStream in) throws CertificateException, IOException, NoSuchProviderException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", CertTools.BC);
        X509Certificate x509Cert = (X509Certificate) cf.generateCertificate(in);
        in.close();
        return x509Cert;
    }

    /**
     *  读取KeyStore
     * @param pwd
     * @param type
     * @param provicer
     * @param path
     * @return
     * @throws Exception
     */
    public static KeyStore KeyStoreReader(String pwd, String type, String provicer, String path) throws Exception {
        FileInputStream in = new FileInputStream(path);
        KeyStore keyStore = KeyStore.getInstance(type, provicer);
        keyStore.load(in, pwd.toCharArray());
        in.close();
        return keyStore;
    }

    /**
     * 读取KeyStore
     *
     * @param pwd
     * @param type
     * @param provicer
     * @param in
     * @return
     * @throws Exception
     */
    public static KeyStore KeyStoreReader(String pwd, String type, String provicer, InputStream in) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(type, provicer);
        keyStore.load(in, pwd.toCharArray());
        in.close();
        return keyStore;
    }

    /**
     * 格式：.p12/.pfx
     * @param pwd
     * @param path
     * @return
     * @throws Exception
     */
    public static KeyStore KeyStorePKCS12Reader(String pwd, String path) throws Exception {
        return KeyStoreReader(pwd, CertTools.TYPE_PKCS12, CertTools.BC, path);  //SunJSSE
    }

    /**
     * 格式：.p12/.pfx
     *
     * @param pwd
     * @param in
     * @return
     * @throws Exception
     */
    public static KeyStore KeyStorePKCS12Reader(String pwd, InputStream in) throws Exception {
        return KeyStoreReader(pwd, CertTools.TYPE_PKCS12, CertTools.BC, in);  //SunJSSE
    }

    /**
     * 格式： .bks
     * @param pwd
     * @param path
     * @return
     * @throws Exception
     */
    public static KeyStore KeyStoreBKSReader(String pwd, String path) throws Exception {
        return KeyStoreReader(pwd, CertTools.TYPE_BKS, CertTools.BC, path);
    }

    /**
     *  格式 .jks/.ks
     * @param pwd
     * @param path
     * @return
     * @throws Exception
     */
    public static KeyStore KeyStoreJKSReader(String pwd, String path) throws Exception {
        return KeyStoreReader(pwd, CertTools.TYPE_JKS, CertTools.SUN, path);
    }

    /**
     *  格式： .jce
     * @param pwd
     * @param path
     * @return
     * @throws Exception
     */
    public static KeyStore KeyStoreJCEKSReader(String pwd, String path) throws Exception {
        return KeyStoreReader(pwd, CertTools.TYPE_JCEKS, CertTools.SUN_JCE, path);
    }

    /**
     *  格式： .ubr
     * @param pwd
     * @param path
     * @return
     * @throws Exception
     */
    public static KeyStore KeyStoreUBERReader(String pwd, String path) throws Exception {
        return KeyStoreReader(pwd, CertTools.TYPE_UBER, CertTools.BC, path);
    }

    /**
     * Reads in a X509Certificate.
     *
     * @return the X509Certificate
     * @throws IOException if an I/O error occured
     */
    public static Certificate toCertificate(PemObject obj) throws IOException {
        ByteArrayInputStream bIn = new ByteArrayInputStream(obj.getContent());
        try {
            CertificateFactory certFact = CertificateFactory.getInstance(CertTools.TYPE_X509, CertTools.BC);
            return certFact.generateCertificate(bIn);
        } catch (Exception e) {
            throw new PEMException("problem parsing cert: " + e.toString(), e);
        }finally {
            if(null != bIn) bIn.close();
        }
    }

    /**
     * 获取keyStore的默认证书
     *
     * @param keyStore
     * @return
     * @throws Exception
     */
    public static Certificate getCertDefault(KeyStore keyStore) throws Exception {
        Enumeration<String> enumKey = keyStore.aliases();
        if (enumKey.hasMoreElements()) {
            return keyStore.getCertificate(enumKey.nextElement());
        }
        return null;
    }

    public static PublicKey readPublicKey(String path) throws Exception {
        PemReader pRd = new PemReader(new InputStreamReader(new FileInputStream(path)));
        PemObject pem = pRd.readPemObject();
        pRd.close();
        X509EncodedKeySpec caKeySpec = new X509EncodedKeySpec(pem.getContent());
        return  KeyFactory.getInstance("EC", "BC").generatePublic(caKeySpec);
    }

    /**
     * 获取证书列表
     *
     * @param keyStore
     * @return
     * @throws Exception
     */
    public static List<Certificate> getCertList(KeyStore keyStore) throws Exception {
        List<Certificate> list = new ArrayList<>();
        Enumeration<String> enumKey = keyStore.aliases();
        while (enumKey.hasMoreElements()) {
            Certificate cert0 = keyStore.getCertificate(enumKey.nextElement());
            list.add(cert0);
        }
        return list;
    }

    public static PrivateKey readPrivatePkcs8(byte[] data) throws Exception {
        return readPrivatePkcs8("EC", data);
    }

    public static PrivateKey readPrivatePkcs8(String alg, byte[] data) throws Exception {
        PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(data);
        KeyFactory keyf = KeyFactory.getInstance(alg, BouncyCastleProvider.PROVIDER_NAME);
        return keyf.generatePrivate(priPKCS8);

    }

    public static PrivateKey readPrivatePkcs8(String path) throws Exception {
        PemReader pRd = new PemReader(new InputStreamReader(new FileInputStream(path)));
        PemObject pem = pRd.readPemObject();
        pRd.close();
        return readPrivatePkcs8(pem.getContent());
    }

    public static PrivateKey readPrivatePkcs1(String path) throws Exception {
        PEMParser pemParser = new PEMParser(new FileReader(path));
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        Object object = pemParser.readObject();
        KeyPair kp = converter.getKeyPair((PEMKeyPair) object);
        PrivateKey privateKey = kp.getPrivate();
        return privateKey;
    }

    public static PrivateKey readPrivateP12(String path, String alias, String pwd) throws Exception {
        KeyStore keyStore = StoreReader.KeyStorePKCS12Reader(pwd, path) ;
        return (PrivateKey)keyStore.getKey(alias, pwd.toCharArray());
    }

    public static String parseCert(String cert){
        String dstCert = "";
        if(cert.contains("BEGIN CERTIFICATE") || cert.startsWith("30")){
            dstCert = cert;
        }else{
            dstCert = "-----BEGIN CERTIFICATE-----\n";
            dstCert += cert + "\n";
            dstCert += "-----END CERTIFICATE-----\n";
        }
        return dstCert;
    }





    /**
     * 判断文件内容是否为标准 PEM 格式
     */
    private static boolean isStandardPEMFormat(File certificateFile) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(certificateFile))) {
            String firstLine = reader.readLine();
            return firstLine != null && firstLine.contains("-----BEGIN CERTIFICATE-----");
        }
    }



}
