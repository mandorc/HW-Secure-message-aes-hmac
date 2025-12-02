/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

/**
 *
 * @author armando
 */
import java.security.cert.X509Certificate;
import javax.swing.*;

public class CertDetailsFrame extends JInternalFrame {

    private JTextArea textArea;

    public CertDetailsFrame(String userId, X509Certificate cert) {
        super("Certificado de " + userId, true, true, true, true);
        initComponents();
        fillData(cert);
        pack();
        setSize(550, 500);
    }

    private void initComponents() {
        textArea = new JTextArea();
        textArea.setEditable(false);
        textArea.setFont(new java.awt.Font("Monospaced", java.awt.Font.PLAIN, 12));

        JScrollPane scroll = new JScrollPane(textArea);

        getContentPane().setLayout(new java.awt.BorderLayout());
        getContentPane().add(scroll, java.awt.BorderLayout.CENTER);
    }

    private void fillData(X509Certificate cert) {
        StringBuilder sb = new StringBuilder();

        sb.append("========== CERTIFICADO X.509 ==========\n\n");

        sb.append("Subject:   ").append(cert.getSubjectX500Principal()).append("\n");
        sb.append("Issuer:    ").append(cert.getIssuerX500Principal()).append("\n\n");

        sb.append("Número de serie: ").append(cert.getSerialNumber()).append("\n");
        sb.append("Válido desde:    ").append(cert.getNotBefore()).append("\n");
        sb.append("Válido hasta:    ").append(cert.getNotAfter()).append("\n\n");

        sb.append("Algoritmo de firma: ").append(cert.getSigAlgName()).append("\n");
        sb.append("Clave pública: ").append(cert.getPublicKey().getAlgorithm()).append("\n");
        sb.append("Tamaño de clave (aprox): ")
                .append(cert.getPublicKey().getEncoded().length * 8)
                .append(" bits\n\n");

        sb.append("------ DN Subject Completo ------\n");
        sb.append(cert.getSubjectX500Principal().getName()).append("\n\n");

        sb.append("------ CERTIFICADO EN FORMATO PEM ------\n");

        try {
            String base64 = java.util.Base64.getEncoder().encodeToString(cert.getEncoded());
            sb.append("-----BEGIN CERTIFICATE-----\n");
            for (int i = 0; i < base64.length(); i += 64) {
                int end = Math.min(i + 64, base64.length());
                sb.append(base64.substring(i, end)).append("\n");
            }
            sb.append("-----END CERTIFICATE-----\n");
        } catch (Exception e) {
            sb.append("[Error mostrando el certificado en Base64]\n");
        }

        textArea.setText(sb.toString());
        textArea.setCaretPosition(0);
    }
}

