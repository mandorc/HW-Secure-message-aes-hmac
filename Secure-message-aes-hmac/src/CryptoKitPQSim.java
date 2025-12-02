/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

/**
 *
 * @author armando
 */
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Versión simulada de un esquema post-cuántico:
 *  - Deriva una llave "post-quantum" por par de usuarios
 *    usando SHA-256(idA|idB + SALT_PQ).
 *  - Usa AES-GCM para cifrado autenticado.
 *
 * NO usa Kyber real, pero ilustra:
 *  - Protocolo distinto al clásico
 *  - Llave simétrica derivada
 *  - Cifrado con AES-GCM (AEAD)
 */
public final class CryptoKitPQSim {

    // Salt distinta a la del esquema clásico
    private static final byte[] SALT_PQ =
            "demo-pq-salt-change-me".getBytes(StandardCharsets.UTF_8);

    private CryptoKitPQSim() {
    }

    // Construye un identificador canónico de par (idA|idB) ordenado
    private static String canonicalPair(String a, String b) {
        String x = a.toLowerCase();
        String y = b.toLowerCase();
        return (x.compareTo(y) <= 0) ? (x + "|" + y) : (y + "|" + x);
    }

    /**
     * Deriva una llave AES-256 a partir de un par de IDs.
     * Simula una "llave post-cuántica" compartida.
     */
    public static SecretKey deriveAesKey(String idA, String idB) throws Exception {
        String pair = canonicalPair(idA, idB);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");

        // hash = SHA-256( SALT_PQ || pairBytes )
        sha.update(SALT_PQ);
        sha.update(pair.getBytes(StandardCharsets.UTF_8));
        byte[] keyBytes = sha.digest(); // 32 bytes

        return new SecretKeySpec(keyBytes, "AES"); // AES-256
    }

    /**
     * Cifra un mensaje usando AES-GCM.
     * Formato de salida: Base64(iv) : Base64(ciphertext)
     */
    public static String encryptPQ(String plaintext,
                                   String fromId,
                                   String toId) throws Exception {

        SecretKey aesKey = deriveAesKey(fromId, toId);

        byte[] iv = new byte[12]; // 96 bits recomendado en GCM
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv); // tag 128 bits
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);

        byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        Base64.Encoder enc = Base64.getEncoder();
        return enc.encodeToString(iv) + ":" + enc.encodeToString(ct);
    }

    /**
     * Descifra un paquete generado por encryptPQ.
     * Si falla la autenticación GCM, lanza SecurityException.
     */
    public static String decryptPQ(String packet,
                                   String fromId,
                                   String toId) throws Exception {

        String[] parts = packet.split(":");
        if (parts.length != 2) {
            throw new SecurityException("Paquete PQ malformado");
        }

        Base64.Decoder dec = Base64.getDecoder();
        byte[] iv = dec.decode(parts[0]);
        byte[] ct = dec.decode(parts[1]);

        SecretKey aesKey = deriveAesKey(fromId, toId);

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
            byte[] pt = cipher.doFinal(ct);
            return new String(pt, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new SecurityException("Error en descifrado GCM / autenticación fallida", e);
        }
    }
}
