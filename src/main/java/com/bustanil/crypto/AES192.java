package com.bustanil.crypto;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES192 {

    public static void main(String[] args) {
        try {
            String password = "duithape";
            String text = "abc";

            byte[][] keyAndIV = OpenSSL3DES.EVP_BytesToKey(24, 16, null,
                    password.getBytes(), 1);


            IvParameterSpec iv = new IvParameterSpec(keyAndIV[1]);
            SecretKeySpec skeySpec = new SecretKeySpec(keyAndIV[0], "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(text.getBytes());
//            System.out.println("encrypted string: "
//                    + new String(encrypted, StandardCharsets.UTF_8));

            System.out.println(new String(new Hex().encode(encrypted)));

        } catch (Exception ex) {
            ex.printStackTrace();
        }

    }


}
