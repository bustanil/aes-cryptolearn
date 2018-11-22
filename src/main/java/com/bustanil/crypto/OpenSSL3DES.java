package com.bustanil.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

public class OpenSSL3DES {

    private static final byte[] SALT = new byte[] { (byte) 0x72, (byte) 0x6d,
            (byte) 0xb5, (byte) 0xf2, (byte) 0xdf, (byte) 0x7e, (byte) 0x37,
            (byte) 0x34 };

    private static final byte[] PREFIX = "Salted__".getBytes();

    private static final int TRIPLEDES_KEY_LEN = 24; // 192 bits
    private static final int TRIPLEDES_IV_LEN = 8;

    public String encrypt(String secret, String password) throws Exception {

        byte[][] keyAndIV = EVP_BytesToKey(TRIPLEDES_KEY_LEN, TRIPLEDES_IV_LEN, SALT,
                password.getBytes(), 1);

        SecretKeySpec key = new SecretKeySpec(keyAndIV[0], "DESede");
        IvParameterSpec iv = new IvParameterSpec(keyAndIV[1]);

        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        final byte[] cipherText = cipher.doFinal(secret.getBytes());

        byte[] opensslFormatted = opensslFormat(cipherText);

        String base64str = Base64.getEncoder().encodeToString(opensslFormatted);

        return base64str;
    }

    public String decrypt(String base64str, String password) throws Exception {

        byte[][] keyAndIV = EVP_BytesToKey(TRIPLEDES_KEY_LEN, TRIPLEDES_IV_LEN, SALT,
                password.getBytes(), 1);

        SecretKeySpec key = new SecretKeySpec(keyAndIV[0], "DESede");
        IvParameterSpec iv = new IvParameterSpec(keyAndIV[1]);
        
        byte[] decoded = Base64.getDecoder().decode(base64str);

        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        byte[] encrypted = Arrays.copyOfRange(decoded, PREFIX.length + SALT.length,
                decoded.length);
        
        final byte[] secret = cipher.doFinal(encrypted);

        return new String(secret);
    }
    
    /**
     * Java version of OpenSSL EVP_BytesToKey. Derives key and IV from
     * password and salt.
     * 
     * https://www.openssl.org/docs/crypto/EVP_BytesToKey.html
     * 
     * Source: https://olabini.com/blog/tag/evp_bytestokey/
     * 
     * @param key_len
     * @param iv_len
     * @param md
     * @param salt
     * @param data
     * @param count
     * 
     * @return derived Key and IV
     */
    public static byte[][] EVP_BytesToKey(int key_len, int iv_len, byte[] salt,
            byte[] data, int count) throws Exception {

        final MessageDigest md = MessageDigest.getInstance("md5");

        byte[][] both = new byte[2][];
        byte[] key = new byte[key_len];
        int key_ix = 0;
        byte[] iv = new byte[iv_len];
        int iv_ix = 0;
        both[0] = key;
        both[1] = iv;
        byte[] md_buf = null;
        int nkey = key_len;
        int niv = iv_len;
        int i = 0;
        if (data == null) {
            return both;
        }
        int addmd = 0;
        for (;;) {
            md.reset();
            if (addmd++ > 0) {
                md.update(md_buf);
            }
            md.update(data);
            if (null != salt) {
                md.update(salt, 0, 8);
            }
            md_buf = md.digest();
            for (i = 1; i < count; i++) {
                md.reset();
                md.update(md_buf);
                md_buf = md.digest();
            }
            i = 0;
            if (nkey > 0) {
                for (;;) {
                    if (nkey == 0)
                        break;
                    if (i == md_buf.length)
                        break;
                    key[key_ix++] = md_buf[i];
                    nkey--;
                    i++;
                }
            }
            if (niv > 0 && i != md_buf.length) {
                for (;;) {
                    if (niv == 0)
                        break;
                    if (i == md_buf.length)
                        break;
                    iv[iv_ix++] = md_buf[i];
                    niv--;
                    i++;
                }
            }
            if (nkey == 0 && niv == 0) {
                break;
            }
        }
        for (i = 0; i < md_buf.length; i++) {
            md_buf[i] = 0;
        }
        return both;
    }

    /**
     * Formats cipherText as 'SALTED__' (8 bytes) + SALT (8 bytes) + cipherText
     * 
     * @param cipherText
     * @return
     */
    private byte[] opensslFormat(final byte[] cipherText) {
        byte[] formatted = new byte[PREFIX.length + SALT.length + cipherText.length];

        int offset = 0;
        System.arraycopy(PREFIX, 0, formatted, offset, PREFIX.length);
        offset += PREFIX.length;
        System.arraycopy(SALT, 0, formatted, offset, SALT.length);
        offset += SALT.length;
        System.arraycopy(cipherText, 0, formatted, offset, cipherText.length);
        
        return formatted;
    }

    // test driver
    public static void main(String argv[]) throws Exception {
        OpenSSL3DES des3 = new OpenSSL3DES();

        String secret = "a secret";
        String password = "some password";

        String encrypted = des3.encrypt(secret, password);
        System.out.println(secret + " -> " + encrypted);

        String decrypted = des3.decrypt(encrypted, password);
        System.out.println(encrypted + " -> " + decrypted);
    }

}