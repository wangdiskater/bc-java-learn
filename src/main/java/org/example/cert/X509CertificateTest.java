package org.example.cert;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;
import org.example.tool.StoreReader;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * @Author dwang
 * @Description TODO
 * @create 2025/1/22 13:57
 * @Modified By:
 */
public class X509CertificateTest {

    public static void main(String[] args) {
        test_cert();
    }

    private static X509Certificate getSKFCertificate(String cert) {
        byte[] decode = Base64.decode(cert);
        try {
            return StoreReader.getCertificate(decode);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 测试bug:证书公钥x,y转换问题
     */
    public static void test_cert() {
        String testCert = "MIIB5zCCAY6gAwIBAgIQSrbA+OlsQX+2wPjpbMF/ITAKBggqgRzPVQGDdTBGMQswCQYDVQQGEwJDTjESMBAGA1UECgwJU3lzdGVtIENBMSMwIQYDVQQDDBpTeXN0ZW0gUm9vdCBDQSBDZXJ0aWZpY2F0ZTAgFw0yMzA2MjkwMjIyMzRaGA8yMTIzMDYyOTAyMjIzNFowPzELMAkGA1UEBhMCQ04xFjAUBgNVBAoMDUFkbWluaXN0cmF0b3IxGDAWBgNVBAMMD3Rlc3QtY2lwaGVyY2VydDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABBhmHgKVBcXWj8m0OIPomJ9XgIDwZgCDMztXGchGK8rECZcRnL7HP6ia/3mQgwilYLGnyvZ0SkDlGb/FewPAtcijYzBhMB0GA1UdDgQWBBQ6fiwRA74I34bWoXYjIJml0ix6ATAOBgNVHQ8BAf8EBAMCBDAwDAYDVR0TAQH/BAIwADAiBgNVHSMBAf8EGDAWgBQ+mnCU2B+jVaaPT49oEWazBILFGzAKBggqgRzPVQGDdQNHADBEAiAM6fJ9bYmphpSIM90vt/GCmk5L/s/txRR5DL8AmNh5KQIgaXcJRgF9Cg7zr81tfcKxejQGtW+ONByHxpifK+MCdCk=";
        X509Certificate certificate = getSKFCertificate(testCert);
        org.bouncycastle.jce.interfaces.ECPublicKey publicKey = (org.bouncycastle.jce.interfaces.ECPublicKey) certificate.getPublicKey();
        ECPoint q = publicKey.getQ();
        ECFieldElement affineXCoordX = q.getXCoord();
        BigInteger x = affineXCoordX.toBigInteger();
        int signum = x.signum();
        String s = affineXCoordX.toString().toUpperCase();
        System.out.println("x " + s);

        ECFieldElement affineXCoordY = q.getYCoord();
        BigInteger y = affineXCoordY.toBigInteger();
        String s1 = affineXCoordY.toString().toUpperCase();
        int signum2 = y.signum();
        System.out.println("y " + s1);


        System.out.println("x1 " + bytesToHex(toFixedLengthBytes(x,32)));
        System.out.println("y1 " +  bytesToHex(toFixedLengthBytes(y,32)));


        System.out.println("x2 " + String.format("%064x", new BigInteger(q.getXCoord().toString().toLowerCase(), 16)));
        System.out.println("y2 " + String.format("%064x", new BigInteger(q.getYCoord().toString().toLowerCase(), 16)));

    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    public static byte[] toFixedLengthBytes(BigInteger value, int length) {
        // 转为无符号的二进制表示
        byte[] bytes = value.toByteArray();
        if (bytes.length == length) {
            return bytes;
        } else if (bytes.length < length) {
            // 补齐前导零
            byte[] padded = new byte[length];
            System.arraycopy(bytes, 0, padded, length - bytes.length, bytes.length);
            return padded;
        } else {
            // 截取多余部分
            return Arrays.copyOfRange(bytes, bytes.length - length, bytes.length);
        }
    }
}
