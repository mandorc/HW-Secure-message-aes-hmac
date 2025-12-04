/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

/**
 *
 * @author armando
 */
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;

public final class PqKeyManager {

    // Reutilizamos el mismo directorio que CertManager
    // Asegúrate de que CertManager.KEYSTORE_DIR sea visible (package-private o public)
    private static final String PQ_DIR = CertManager.KEYSTORE_DIR;
    private static final String PUB_SUFFIX = "-pq.pub";
    private static final String SEC_SUFFIX = "-pq.sec";

    private PqKeyManager() {
    }

    public static void ensurePqKeys(String userId) throws Exception {
        String alias = userId.toLowerCase();

        Path dir = Paths.get(PQ_DIR);
        if (!Files.exists(dir)) {
            Files.createDirectories(dir);
        }

        Path pubPath = dir.resolve(alias + PUB_SUFFIX);
        Path secPath = dir.resolve(alias + SEC_SUFFIX);

        // Si ya existen, no hacemos nada
        if (Files.exists(pubPath) && Files.exists(secPath)) {
            return;
        }

        // 1) Generar secreto sk
        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);

        // 2) pk = H(sk)
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] pub = md.digest(secret);

        // 3) Guardar en disco
        Files.write(secPath, secret);
        Files.write(pubPath, pub);
    }

    public static byte[] getPublicKey(String userId) throws Exception {
        String alias = userId.toLowerCase();
        Path pubPath = Paths.get(PQ_DIR, alias + PUB_SUFFIX);

        if (!Files.exists(pubPath)) {
            throw new IllegalStateException("No existe clave PQ pública para " + userId);
        }
        return Files.readAllBytes(pubPath);
    }

    public static byte[] getSecretKey(String userId) throws Exception {
        String alias = userId.toLowerCase();
        Path secPath = Paths.get(PQ_DIR, alias + SEC_SUFFIX);

        if (!Files.exists(secPath)) {
            throw new IllegalStateException("No existe clave PQ secreta para " + userId);
        }
        return Files.readAllBytes(secPath);
    }
}
