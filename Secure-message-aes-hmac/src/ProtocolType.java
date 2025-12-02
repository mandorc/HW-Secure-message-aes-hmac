/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Enum.java to edit this template
 */

/**
 *
 * @author armando
 */
public enum ProtocolType {
    CLASSIC,   // tu esquema actual: PBKDF2 + AES-CBC + HMAC
    KYBER_PQ   // esquema nuevo: Kyber-512 + AES-GCM
}