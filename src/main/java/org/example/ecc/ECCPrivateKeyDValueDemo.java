package org.example.ecc;

import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

/**
 * @Author dwang
 * @Description TODO
 * @create 2025/1/22 14:13
 * @Modified By:
 */
public class ECCPrivateKeyDValueDemo {
    public static void main(String[] args) throws Exception {
        // 添加 BouncyCastle 提供者
        Security.addProvider(new BouncyCastleProvider());

        // 生成 ECC 密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(256); // 使用 256 位曲线
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // 获取私钥
        BCECPrivateKey privateKey = (BCECPrivateKey) keyPair.getPrivate();

        // 获取私钥中的 D 值
        BigInteger d = privateKey.getD();
        BigInteger S = privateKey.getS();

        // 输出 D 值
        System.out.println("Private Key (D): " + d.toString(16)); // 十六进制输出
    }
}
