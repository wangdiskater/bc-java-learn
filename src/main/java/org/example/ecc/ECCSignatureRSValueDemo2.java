package org.example.ecc;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @Author dwang
 * @Description BC库验证签名bug
 * @create 2025/1/22 14:17
 * @Modified By:
 */
public class ECCSignatureRSValueDemo2 {

    public static void main(String[] args) {
        try {
            // 输入数据
            String dataHex = "29b36a2ad65e004a49bba1ec14dfbe024ec280cc39fe77717e23121791c1bfb9";
            String signHex_error = "30450220005643fa18f8b2dbca7cc09f95316697983494ea615f6e24bac51433465a20ed022100f180c6ea81d1481db4aae0412f1ef425cbffc364ffd29d1e0af27347f267c02c";
            String signHex_right = "3044021F5643fa18f8b2dbca7cc09f95316697983494ea615f6e24bac51433465a20ed022100f180c6ea81d1481db4aae0412f1ef425cbffc364ffd29d1e0af27347f267c02c";
            String publicKeyHex = "3059301306072a8648ce3d020106082a811ccf5501822d0342000431699d6a736cf6920151724eb044637dc0a957cc637c02ecc1236c2e61a9a1ef446d9f9ecccb1e86ca4ac57f1d0d510e55c76e010267198c71839cf2af3a87e3";

            // 将 16 进制数据转换为字节数组
            byte[] data = Hex.decode(dataHex);
            byte[] sign = Hex.decode(signHex_right);
            byte[] publicKeyBytes = Hex.decode(publicKeyHex);

            // 初始化 Bouncy Castle 提供器
            Security.addProvider(new BouncyCastleProvider());

            // 构造公钥对象
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            // 初始化 Signature 验证器
            Signature signature = Signature.getInstance("SM3withSM2", "BC");
            signature.initVerify(publicKey);

            // 传入数据
            signature.update(data);

            // 验证签名
            boolean isValid = signature.verify(sign);

            // 输出结果
            if (isValid) {
                System.out.println("签名验证成功！");
            } else {
                System.out.println("签名验证失败！");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }



}
