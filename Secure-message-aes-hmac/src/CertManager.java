/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

/**
 *
 * @author armando
 */

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class CertManager {

    private static final String KEYSTORE_DIR = "certs";
    private static final String STOREPASS = "changeit";
    private static final String KEYALG = "RSA";
    private static final int KEYSIZE = 2048;
    private static final int VALIDITY_DAYS = 365;

    public static class UserCertInfo {
        public final Path keystorePath;
        public final Path certPath;
        public final String alias;
        public final String storepass;

        public UserCertInfo(Path keystorePath, Path certPath, String alias, String storepass) {
            this.keystorePath = keystorePath;
            this.certPath = certPath;
            this.alias = alias;
            this.storepass = storepass;
        }
    }

    // ===============================================================
    // 1) GENERAR CERTIFICADO SI NO EXISTE
    // ===============================================================
    public static UserCertInfo ensureUserCertificate(String userId, String commonName)
            throws IOException, InterruptedException {

        Path dir = Paths.get(KEYSTORE_DIR);
        if (!Files.exists(dir)) {
            Files.createDirectories(dir);
        }

        String alias = userId.toLowerCase();
        Path ksPath = dir.resolve(alias + ".jks");
        Path certPath = dir.resolve(alias + ".cer");

        // Si ya existe, no lo generamos de nuevo
        if (Files.exists(ksPath) && Files.exists(certPath)) {
            return new UserCertInfo(ksPath, certPath, alias, STOREPASS);
        }

        // Crear dname
        String dname = String.format(
                "CN=%s, OU=ChatDemo, O=ProyectoSeguridad, L=CDMX, ST=CDMX, C=MX",
                commonName.replaceAll("[,=]", "")
        );

        // --------------- generar llave + certificado autofirmado ----------------
        ProcessBuilder genKeyPB = new ProcessBuilder(
                "keytool", "-genkeypair",
                "-alias", alias,
                "-keyalg", KEYALG,
                "-keysize", String.valueOf(KEYSIZE),
                "-validity", String.valueOf(VALIDITY_DAYS),
                "-keystore", ksPath.toString(),
                "-storepass", STOREPASS,
                "-keypass", STOREPASS,
                "-dname", dname
        );

        genKeyPB.inheritIO();
        int exit1 = genKeyPB.start().waitFor();
        if (exit1 != 0) {
            throw new IOException("Error al ejecutar keytool -genkeypair");
        }

        // ----------------- exportar certificado público -----------------
        ProcessBuilder exportPB = new ProcessBuilder(
                "keytool", "-exportcert",
                "-alias", alias,
                "-keystore", ksPath.toString(),
                "-storepass", STOREPASS,
                "-rfc",
                "-file", certPath.toString()
        );

        exportPB.inheritIO();
        int exit2 = exportPB.start().waitFor();
        if (exit2 != 0) {
            throw new IOException("Error al ejecutar keytool -exportcert");
        }

        return new UserCertInfo(ksPath, certPath, alias, STOREPASS);
    }

    // ===============================================================
    // 2) LEER CERTIFICADO .CER DEL USUARIO
    // ===============================================================
    public static X509Certificate getUserCertificate(String userId) throws Exception {

        Path certPath = Paths.get(KEYSTORE_DIR).resolve(userId.toLowerCase() + ".cer");

        if (!Files.exists(certPath)) {
            throw new IllegalStateException("No existe el certificado para el usuario: " + userId);
        }

        try (InputStream in = Files.newInputStream(certPath)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(in);
        }
    }
}
