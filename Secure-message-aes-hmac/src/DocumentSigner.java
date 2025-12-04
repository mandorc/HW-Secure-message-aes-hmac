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
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;

/**
 * Utilidad para firmar documentos con la llave privada RSA del usuario
 * y verificar firmas con el certificado X.509 correspondiente.
 */
public final class DocumentSigner {

    private DocumentSigner() {
    }

    /**
     * Firma un archivo usando la llave privada del usuario.
     *
     * @param userId       ID del usuario (debe tener .key y .crt generados por CertManager)
     * @param documentPath ruta del archivo a firmar
     * @return ruta del archivo de firma generado (mismo nombre + ".sig")
     */
    public static Path signFileForUser(String userId, Path documentPath) throws Exception {
        // 1) Cargar llave privada del usuario
        PrivateKey privateKey = CertManager.getUserPrivateKey(userId);

        // 2) Leer todo el contenido del documento
        byte[] data = Files.readAllBytes(documentPath);

        // 3) Crear objeto Signature (SHA-256 con RSA)
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(data);

        // 4) Obtener la firma en bytes
        byte[] signatureBytes = sig.sign();

        // 5) Guardar la firma en un archivo .sig
        Path sigPath = documentPath.resolveSibling(documentPath.getFileName().toString() + ".sig");
        Files.write(sigPath, signatureBytes);

        return sigPath;
    }

    /**
     * Verifica la firma de un archivo usando el certificado proporcionado.
     *
     * @param documentPath  ruta del documento original
     * @param signaturePath ruta del archivo de firma (.sig)
     * @param cert          certificado del firmante (contiene la llave pública RSA)
     * @return true si la firma es válida, false si no lo es
     */
    public static boolean verifyFileWithCert(Path documentPath, Path signaturePath, X509Certificate cert) throws Exception {
        // 1) Leer documento y firma
        byte[] data = Files.readAllBytes(documentPath);
        byte[] signatureBytes = Files.readAllBytes(signaturePath);

        // 2) Crear objeto Signature con la llave pública del certificado
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(cert.getPublicKey());
        sig.update(data);

        // 3) Verificar
        return sig.verify(signatureBytes);
    }

    /**
     * Versión de conveniencia: verifica usando el certificado del propio usuario.
     */
    public static boolean verifyFileForUser(String userId, Path documentPath, Path signaturePath) throws Exception {
        X509Certificate cert = CertManager.getUserCertificate(userId);
        return verifyFileWithCert(documentPath, signaturePath, cert);
    }
}
