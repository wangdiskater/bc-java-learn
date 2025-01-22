package org.example.ecc;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

/**
 * @Author dwang
 * @Description TODO
 * @create 2025/1/22 14:17
 * @Modified By:
 */
public class ECCSignatureRSValueDemo {
    public static void main(String[] args) throws Exception {
        // 添加 BouncyCastle 提供者
        Security.addProvider(new BouncyCastleProvider());

        // 生成 ECC 密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1")); // 使用标准曲线 secp256r1
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // 获取私钥和公钥
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 待签名数据
        String data = "Hello ECC!";
        byte[] dataBytes = data.getBytes();

        // 签名
        Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
        signature.initSign(privateKey);
        signature.update(dataBytes);
        byte[] signedBytes = signature.sign();

        // 打印签名结果（完整签名）
        System.out.println("Full Signature (Hex): " + Hex.toHexString(signedBytes));

        // 提取 R 和 S 值
        int rLength = signedBytes[3]; // 签名的结构是 DER 编码，第4字节为 R 的长度
        byte[] r = new byte[rLength];
        System.arraycopy(signedBytes, 4, r, 0, rLength); // 提取 R 的值

        int sLength = signedBytes[4 + rLength + 1]; // 紧跟 R 后面的字节为 S 的长度
        byte[] s = new byte[sLength];
        System.arraycopy(signedBytes, 4 + rLength + 2, s, 0, sLength); // 提取 S 的值

        // 打印 R 和 S 值
        System.out.println("R (Hex): " + Hex.toHexString(r));
        System.out.println("S (Hex): " + Hex.toHexString(s));

        // 验证签名
        signature.initVerify(publicKey);
        signature.update(dataBytes);
        boolean verified = signature.verify(signedBytes);
        System.out.println("Signature Verified: " + verified);
    }

}
