
import java.awt.Color;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.event.InternalFrameAdapter;
import javax.swing.event.InternalFrameEvent;

/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/GUIForms/JInternalFrame.java to edit this template
 */
/**
 *
 * @author arman
 */
public class FrameClient extends javax.swing.JInternalFrame {

    private String nombre;
    private String id;

    private ProtocolType preferredProtocol;  // el que eligió al crearse
    private ProtocolType sessionProtocol;    // el que se usa en ESTA conversación

    public FrameClient(String nombre, String id, ProtocolType preferredProtocol) {
        initComponents();

        this.preferredProtocol = preferredProtocol;
        this.sessionProtocol = preferredProtocol; // por defecto inicia usando su preferido

        jLabel7.setVisible(false);
        this.nombre = nombre;
        this.id = id;
        setTitle(nombre);     // establece el título solo con el nombre

        setupFields();

        /// Registrar este cliente por su ID
        boolean ok = ClientRegistry.get().register(this.id, this);
        if (!ok) {
            jLabel7.setText("ID en uso");
            jLabel7.setForeground(java.awt.Color.RED);
        }

        // Darse de baja al cerrar
        addInternalFrameListener(new InternalFrameAdapter() {
            @Override
            public void internalFrameClosed(InternalFrameEvent e) {
                ClientRegistry.get().unregister(FrameClient.this.id);
            }
        });

        // Acción del botón "Comprobar"
        checkAvalability.addActionListener(evt -> {
            try {
                checkAvailabilityAction();
            } catch (Exception ex) {
                Logger.getLogger(FrameClient.class.getName()).log(Level.SEVERE, null, ex);
            }
        });
        sendButton.addActionListener(evt -> sendMessageAction());
        deleteUser.addActionListener(evt -> dispose()); // cierra y dispara el unregister

    }

    private void checkAvailabilityAction() throws Exception {
        String target = destUser.getText();
        if (target == null) {
            target = "";
        }
        target = target.trim().toLowerCase();

        // Validaciones básicas
        if (target.isEmpty()) {
            showStatus("Escribe un ID", Color.RED);
            return;
        }
        if (target.equals(this.id.toLowerCase())) {
            showStatus("Es tu propio ID", Color.ORANGE);
            return;
        }

        // Ver si el cliente existe
        if (!ClientRegistry.get().exists(target)) {
            showStatus("No encontrado", Color.RED);
            return;
        }

        FrameClient receptor = ClientRegistry.get().get(target);
        if (receptor == null) {
            showStatus("Destinatario no encontrado", Color.RED);
            return;
        }

        // --- Validar certificados de ambos lados ---
        X509Certificate myCert;
        X509Certificate theirCert;
        try {
            myCert = CertManager.validateUserCertificate(this.id);
            theirCert = CertManager.validateUserCertificate(target);
        } catch (IllegalStateException ex) {
            ex.printStackTrace();
            showStatus("Error de certificado: " + ex.getMessage(), Color.RED);
            return;
        }

        // --- Negociación de protocolo ---
        ProtocolType myPref = this.preferredProtocol;
        ProtocolType remotePref = receptor.getPreferredProtocol();
        ProtocolType usedProtocol;

        if (myPref == remotePref) {
            usedProtocol = myPref;
        } else {
            // me adapto al preferido del otro
            usedProtocol = remotePref;
            showStatus("Se cambió el protocolo a " + usedProtocol
                    + " para comunicarse con " + target,
                    Color.BLUE);
        }
        this.sessionProtocol = usedProtocol;

        try {
            if (usedProtocol == ProtocolType.CLASSIC) {
                // ==========================================================
                //  MODO CLÁSICO: RSA-KEM + AES-CBC / HMAC (canal simétrico)
                // ==========================================================

                // 1) Emisor (this) ejecuta el KEM hacia el receptor,
                //    usando la llave pública RSA del certificado de 'target'
                RsaKemUtil.KemResult kem
                        = RsaKemUtil.encapsulate(theirCert.getPublicKey());

                // 2) Derivar claves AES + HMAC a partir del secreto maestro K
                CryptoKit.Keys myKeys = CryptoKit.deriveFromMaster(kem.master);

                // 3) Registrar claves de sesión para este par
                SessionKeyRegistry.get().put(this.id, target, myKeys);

                // 4) Avisar al receptor para que decapsule y derive sus claves
                receptor.acceptClassicKemFrom(this.id, kem.encMaster);

                // 5) Mostrar las claves en la UI de este cliente
                showKeys(myKeys);
                showStatus("Sesión CLASSIC (RSA-KEM) establecida con " + target,
                        new Color(0, 128, 0)); // verde

            } else if (usedProtocol == ProtocolType.KYBER_PQ) {
                // ==========================================================
                //  MODO PQ SIMULADO: "Kyber-512 + AES-GCM"
                //  (claves derivadas con CryptoKitPQSim)
                // ==========================================================

                javax.crypto.SecretKey aes
                        = CryptoKitPQSim.deriveAesKey(this.id, target);

                aesKeyField.setText(
                        java.util.Base64.getEncoder().encodeToString(aes.getEncoded())
                );
                // Aquí no hay HMAC aparte: AES-GCM ya es autenticado
                aesKeyField1.setText("AES-GCM (simulado PQ)");

                showStatus("Sesión PQ (Kyber-512 simulado) establecida con " + target,
                        new Color(0, 128, 0));
            }

        } catch (Exception e) {
            e.printStackTrace();
            aesKeyField.setText("Error derivando claves");
            aesKeyField1.setText("Error derivando claves");
            showStatus("Error al derivar claves", Color.RED);
        }
    }

    public void showKeys(CryptoKit.Keys keys) {
        aesKeyField.setText(
                java.util.Base64.getEncoder().encodeToString(keys.aes.getEncoded())
        );
        aesKeyField1.setText(
                java.util.Base64.getEncoder().encodeToString(keys.mac.getEncoded())
        );
    }

    public String getNombre() {
        return nombre;
    }

    public String getIdCliente() {
        return id;
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel1 = new javax.swing.JPanel();
        jPanel2 = new javax.swing.JPanel();
        username = new javax.swing.JLabel();
        jLabel1 = new javax.swing.JLabel();
        userID = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        destUser = new javax.swing.JTextField();
        checkAvalability = new javax.swing.JButton();
        aesKeyLabel = new javax.swing.JLabel();
        aesKeyField = new javax.swing.JTextField();
        jLabel5 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        inboxPane = new javax.swing.JTextPane();
        jLabel6 = new javax.swing.JLabel();
        txtField = new javax.swing.JTextField();
        sendButton = new javax.swing.JButton();
        deleteUser = new javax.swing.JButton();
        jLabel7 = new javax.swing.JLabel();
        jLabel8 = new javax.swing.JLabel();
        aesKeyField1 = new javax.swing.JTextField();
        viewCertButton = new javax.swing.JButton();
        btnFirmarActionPerformed = new javax.swing.JButton();
        btnVerificarActionPerformed = new javax.swing.JButton();

        jPanel2.setBackground(new java.awt.Color(255, 255, 255));

        username.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        username.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        username.setText("Armando Rivera Castillo");

        jLabel1.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        jLabel1.setText("ID:");

        userID.setText("identificadorUnico");

        jLabel3.setText("Destinatario:");

        checkAvalability.setText("Comprobar");

        aesKeyLabel.setText("Llave AES:");

        jLabel5.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        jLabel5.setText("Mensajes de entrada:");

        jScrollPane1.setViewportView(inboxPane);

        jLabel6.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        jLabel6.setText("Mensaje para enviar:");

        sendButton.setText("Enviar");
        sendButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                sendButtonActionPerformed(evt);
            }
        });

        deleteUser.setText("Eliminar usuario");

        jLabel7.setText("Error: Este mensaje ha sido modificado");

        jLabel8.setText("Llave HMAC:");

        viewCertButton.setText("Certificado");
        viewCertButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                viewCertButtonActionPerformed(evt);
            }
        });

        btnFirmarActionPerformed.setText("F");
        btnFirmarActionPerformed.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnFirmarActionPerformedActionPerformed(evt);
            }
        });

        btnVerificarActionPerformed.setText("V");
        btnVerificarActionPerformed.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnVerificarActionPerformedActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1)
                    .addComponent(username, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addComponent(jLabel3)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(destUser, javax.swing.GroupLayout.PREFERRED_SIZE, 163, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(checkAvalability, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addComponent(txtField)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel2Layout.createSequentialGroup()
                        .addComponent(deleteUser)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(viewCertButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnFirmarActionPerformed)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnVerificarActionPerformed)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 39, Short.MAX_VALUE)
                        .addComponent(sendButton))
                    .addComponent(jLabel6, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel7, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel2Layout.createSequentialGroup()
                                .addComponent(jLabel1)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(userID, javax.swing.GroupLayout.PREFERRED_SIZE, 125, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addComponent(jLabel5))
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel2Layout.createSequentialGroup()
                        .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel8, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(aesKeyLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(aesKeyField, javax.swing.GroupLayout.DEFAULT_SIZE, 308, Short.MAX_VALUE)
                            .addComponent(aesKeyField1))))
                .addContainerGap())
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(username, javax.swing.GroupLayout.PREFERRED_SIZE, 39, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(userID))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3)
                    .addComponent(destUser, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(checkAvalability))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(aesKeyLabel)
                    .addComponent(aesKeyField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel8)
                    .addComponent(aesKeyField1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel5)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 49, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel7, javax.swing.GroupLayout.PREFERRED_SIZE, 34, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel6)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(txtField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(sendButton)
                    .addComponent(deleteUser)
                    .addComponent(viewCertButton)
                    .addComponent(btnFirmarActionPerformed)
                    .addComponent(btnVerificarActionPerformed))
                .addContainerGap())
        );

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jPanel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jPanel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 424, Short.MAX_VALUE)
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addGap(0, 0, Short.MAX_VALUE)
                    .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGap(0, 0, Short.MAX_VALUE)))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 354, Short.MAX_VALUE)
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addGap(0, 0, Short.MAX_VALUE)
                    .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGap(0, 0, Short.MAX_VALUE)))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void sendButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_sendButtonActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_sendButtonActionPerformed

    private void viewCertButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_viewCertButtonActionPerformed
        openCertDetails();
    }//GEN-LAST:event_viewCertButtonActionPerformed

    private void btnFirmarActionPerformedActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnFirmarActionPerformedActionPerformed
        try {
            javax.swing.JFileChooser chooser = new javax.swing.JFileChooser();
            chooser.setDialogTitle("Selecciona el documento a firmar");

            if (chooser.showOpenDialog(this) == javax.swing.JFileChooser.APPROVE_OPTION) {
                java.io.File file = chooser.getSelectedFile();
                java.nio.file.Path docPath = file.toPath();

                // Firmar usando la llave privada RSA de este usuario
                java.nio.file.Path sigPath = DocumentSigner.signFileForUser(this.id, docPath);

                javax.swing.JOptionPane.showMessageDialog(this,
                        "Documento firmado correctamente.\nFirma guardada en:\n" + sigPath.toString(),
                        "Firma generada",
                        javax.swing.JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (Exception e) {
            e.printStackTrace();
            javax.swing.JOptionPane.showMessageDialog(this,
                    "Error al firmar el documento: " + e.getMessage(),
                    "Error",
                    javax.swing.JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_btnFirmarActionPerformedActionPerformed

    private void btnVerificarActionPerformedActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnVerificarActionPerformedActionPerformed
        try {
            javax.swing.JFileChooser chooser = new javax.swing.JFileChooser();

            // 1) Seleccionar documento
            chooser.setDialogTitle("Selecciona el documento original");
            if (chooser.showOpenDialog(this) != javax.swing.JFileChooser.APPROVE_OPTION) {
                return;
            }
            java.nio.file.Path docPath = chooser.getSelectedFile().toPath();

            // 2) Seleccionar archivo de firma
            chooser.setDialogTitle("Selecciona el archivo de firma (.sig)");
            if (chooser.showOpenDialog(this) != javax.swing.JFileChooser.APPROVE_OPTION) {
                return;
            }
            java.nio.file.Path sigPath = chooser.getSelectedFile().toPath();

            // 3) Seleccionar certificado (.crt) del firmante
            chooser.setDialogTitle("Selecciona el certificado del firmante (.crt)");
            if (chooser.showOpenDialog(this) != javax.swing.JFileChooser.APPROVE_OPTION) {
                return;
            }
            java.nio.file.Path crtPath = chooser.getSelectedFile().toPath();

            // Cargar el certificado desde el .crt
            java.security.cert.CertificateFactory cf
                    = java.security.cert.CertificateFactory.getInstance("X.509");
            try (java.io.InputStream in = java.nio.file.Files.newInputStream(crtPath)) {
                java.security.cert.X509Certificate cert
                        = (java.security.cert.X509Certificate) cf.generateCertificate(in);

                boolean ok = DocumentSigner.verifyFileWithCert(docPath, sigPath, cert);

                if (ok) {
                    javax.swing.JOptionPane.showMessageDialog(this,
                            "Firma VÁLIDA.\nEl documento no ha sido modificado y fue firmado con la llave privada correspondiente a ese certificado.",
                            "Firma válida",
                            javax.swing.JOptionPane.INFORMATION_MESSAGE);
                } else {
                    javax.swing.JOptionPane.showMessageDialog(this,
                            "Firma NO válida.\nEl documento ha sido modificado o no corresponde al certificado seleccionado.",
                            "Firma inválida",
                            javax.swing.JOptionPane.ERROR_MESSAGE);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            javax.swing.JOptionPane.showMessageDialog(this,
                    "Error al verificar la firma: " + e.getMessage(),
                    "Error",
                    javax.swing.JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_btnVerificarActionPerformedActionPerformed

    private void openCertDetails() {
        try {
            X509Certificate cert = CertManager.getUserCertificate(this.id);

            CertDetailsFrame cf = new CertDetailsFrame(this.id, cert);
            MainInterface.jDesktopPane_menu.add(cf);
            cf.setVisible(true);

        } catch (Exception e) {
            e.printStackTrace();
            javax.swing.JOptionPane.showMessageDialog(
                    this,
                    "No se pudo cargar el certificado para el usuario " + this.id
                    + "\nAsegúrate de que se generó correctamente.",
                    "Error de certificado",
                    javax.swing.JOptionPane.ERROR_MESSAGE
            );
        }
    }

    private void setupFields() {
        username.setText(this.nombre);
        userID.setText(this.id);
    }

    private void sendMessageAction() {
        String target = destUser.getText();
        if (target == null) {
            target = "";
        }
        target = target.trim().toLowerCase();

        String msg = txtField.getText();
        if (msg == null) {
            msg = "";
        }
        msg = msg.trim();

        if (target.isEmpty()) {
            showStatus("Escribe un ID destino", java.awt.Color.RED);
            return;
        }
        if (msg.isEmpty()) {
            showStatus("Escribe un mensaje", java.awt.Color.RED);
            return;
        }
        if (target.equals(this.id.toLowerCase())) {
            showStatus("Es tu propio ID", java.awt.Color.ORANGE);
            return;
        }

        FrameClient receptor = ClientRegistry.get().get(target);
        if (receptor == null) {
            showStatus("Destinatario no encontrado", java.awt.Color.RED);
            return;
        }

        try {
            String packet;

            if (sessionProtocol == ProtocolType.CLASSIC) {
                // ================= MODO CLÁSICO =================
                packet = CryptoKit.encryptThenMac(msg, this.id, target);

            } else if (sessionProtocol == ProtocolType.KYBER_PQ) {
                // ================= MODO PQ SIMULADO =================
                packet = CryptoKitPQSim.encryptPQ(msg, this.id, target);

            } else {
                showStatus("Protocolo de sesión no definido", java.awt.Color.RED);
                return;
            }

            // Pasar a FrameMITM
            FrameMITM mitm = new FrameMITM();
            MainInterface.jDesktopPane_menu.add(mitm);
            mitm.setVisible(true);

            mitm.setPacket(this.id, target, packet, msg, receptor);

        } catch (Exception e) {
            showStatus("Error al cifrar", java.awt.Color.RED);
            e.printStackTrace();
        }
    }

    public void receiveMessage(String fromId, String fromName, String msg) {
        // Asegura actualización en el EDT
        javax.swing.SwingUtilities.invokeLater(() -> {
            appendInbox(fromName + ": " + msg);
        });
    }

    private void appendInbox(String line) {
        String prev = inboxPane.getText();
        if (prev == null || prev.isEmpty()) {
            inboxPane.setText(line);
        } else {
            inboxPane.setText(prev + "\n" + line);
        }
    }

    private void showStatus(String text, java.awt.Color color) {
        if (text == null || text.isEmpty()) {
            jLabel7.setVisible(false); // si no hay texto, ocultar
        } else {
            jLabel7.setText(text);
            jLabel7.setForeground(color);
            jLabel7.setVisible(true); // solo mostrar si hay texto
        }
    }

    public ProtocolType getPreferredProtocol() {
        return preferredProtocol;
    }

    public ProtocolType getSessionProtocol() {
        return sessionProtocol;
    }

    public void acceptClassicKemFrom(String fromId, byte[] encMaster) {
        try {
            // 1) Obtener mi llave privada (soy el receptor)
            PrivateKey priv = CertManager.getUserPrivateKey(this.id);

            // 2) Decapsular: recuperar el secreto maestro
            byte[] master = RsaKemUtil.decapsulate(encMaster, priv);

            // 3) Derivar claves AES + HMAC a partir del maestro
            CryptoKit.Keys keys = CryptoKit.deriveFromMaster(master);

            // 4) Registrar claves de sesión para este par
            SessionKeyRegistry.get().put(fromId, this.id, keys);

            // 5) Mostrar en la UI
            showKeys(keys);
            showStatus("Sesión CLASSIC (RSA-KEM) establecida con " + fromId,
                    new Color(0, 128, 0));
        } catch (Exception e) {
            e.printStackTrace();
            showStatus("Error al completar RSA-KEM: " + e.getMessage(), Color.RED);
        }
    }


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextField aesKeyField;
    private javax.swing.JTextField aesKeyField1;
    private javax.swing.JLabel aesKeyLabel;
    private javax.swing.JButton btnFirmarActionPerformed;
    private javax.swing.JButton btnVerificarActionPerformed;
    private javax.swing.JButton checkAvalability;
    private javax.swing.JButton deleteUser;
    private javax.swing.JTextField destUser;
    private javax.swing.JTextPane inboxPane;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JButton sendButton;
    private javax.swing.JTextField txtField;
    private javax.swing.JLabel userID;
    private javax.swing.JLabel username;
    private javax.swing.JButton viewCertButton;
    // End of variables declaration//GEN-END:variables
}
