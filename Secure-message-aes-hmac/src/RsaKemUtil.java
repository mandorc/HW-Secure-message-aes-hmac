/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

/**
 *
 * @author armando
 */
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.Cipher;

public final class RsaKemUtil {

    private RsaKemUtil() {}

    public static final int MASTER_BYTES = 32;

    public static class KemResult {
        public final byte[] encMaster;  // K cifrada para el receptor
        public final byte[] master;     // K en claro (lado emisor)

        public KemResult(byte[] encMaster, byte[] master) {
            this.encMaster = encMaster;
            this.master = master;
        }
    }

    // Emisor: genera K y la cifra con la pública del receptor
    public static KemResult encapsulate(PublicKey recipientPub) throws Exception {
        byte[] master = new byte[MASTER_BYTES];
        new SecureRandom().nextBytes(master);

        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsa.init(Cipher.ENCRYPT_MODE, recipientPub);
        byte[] enc = rsa.doFinal(master);

        return new KemResult(enc, master);
    }

    // Receptor: descifra K con su privada
    public static byte[] decapsulate(byte[] encMaster, PrivateKey recipientPriv) throws Exception {
        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsa.init(Cipher.DECRYPT_MODE, recipientPriv);
        return rsa.doFinal(encMaster);
    }
}