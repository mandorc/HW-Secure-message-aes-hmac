
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
/**
 *
 * @author arman
 */
public final class CryptoKit {

    private static final byte[] SALT = "demo-salt-please-change".getBytes(StandardCharsets.UTF_8);

    public static final class Keys {

        public final SecretKey aes, mac;

        public Keys(SecretKey aes, SecretKey mac) {
            this.aes = aes;
            this.mac = mac;
        }
    }

    // Deriva claves simétricas por par de IDs (mismo resultado en ambos lados)
    public static Keys derive(String idA, String idB) throws Exception {
        String a = idA.toLowerCase(), b = idB.toLowerCase();
        String pair = (a.compareTo(b) <= 0 ? a + "|" + b : b + "|" + a);

        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        // 16 bytes AES + 32 bytes HMAC = 48 bytes totales
        PBEKeySpec spec = new PBEKeySpec(pair.toCharArray(), SALT, 50_000, (16 + 32) * 8);
        byte[] kb = f.generateSecret(spec).getEncoded();

        byte[] aesBytes = Arrays.copyOfRange(kb, 0, 16);
        byte[] macBytes = Arrays.copyOfRange(kb, 16, 48);

        SecretKey aes = new SecretKeySpec(aesBytes, "AES");
        SecretKey mac = new SecretKeySpec(macBytes, "HmacSHA256");
        return new Keys(aes, mac);
    }

    public static String encryptThenMac(String plaintext, String fromId, String toId) throws Exception {
        Keys k = derive(fromId, toId);

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, k.aes, new IvParameterSpec(iv));
        byte[] ct = c.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        Mac m = Mac.getInstance("HmacSHA256");
        m.init(k.mac);
        m.update(iv);
        m.update(ct);
        byte[] tag = m.doFinal();

        Base64.Encoder enc = Base64.getEncoder();
        return enc.encodeToString(iv) + ":" + enc.encodeToString(ct) + ":" + enc.encodeToString(tag);
    }

    public static String decryptIfValid(String packet, String fromId, String toId) throws Exception {
        String[] parts = packet.split(":");
        if (parts.length != 3) {
            throw new SecurityException("paquete malformado");
        }

        Base64.Decoder dec = Base64.getDecoder();
        byte[] iv = dec.decode(parts[0]);
        byte[] ct = dec.decode(parts[1]);
        byte[] tag = dec.decode(parts[2]);

        Keys k = derive(fromId, toId);

        Mac m = Mac.getInstance("HmacSHA256");
        m.init(k.mac);
        m.update(iv);
        m.update(ct);
        byte[] tag2 = m.doFinal();

        if (!java.security.MessageDigest.isEqual(tag, tag2)) {
            throw new SecurityException("MAC inválido");
        }

        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, k.aes, new IvParameterSpec(iv));
        byte[] pt = c.doFinal(ct);
        return new String(pt, StandardCharsets.UTF_8);
    }

    private CryptoKit() {
    }
}
