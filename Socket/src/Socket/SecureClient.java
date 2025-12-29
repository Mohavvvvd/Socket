package Socket;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.util.Base64;
import java.util.UUID;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Client TCP Sécurisé
 * Compatible avec SecureServer.java
 * 
 * IMPORTANT : 
 * - SECRET_KEY doit être identique au serveur
 * - SERVER_PORT doit être identique au serveur (6443)
 * - Le serveur doit être lancé AVANT le client
 * 
 * @author ESSTHS - LI3
 * @version 1.0
 */
public class SecureClient {
    
    // ═══════════════════════════════════════════════════════════
    // CONFIGURATION - Doit correspondre au serveur
    // ═══════════════════════════════════════════════════════════
    private static final String SECRET_KEY = "VotreCleSuperSecrete2025!";
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 6443;
    private static final int CONNECTION_TIMEOUT = 5000; // 5 secondes
    private static final int READ_TIMEOUT = 10000; // 10 secondes
    
    /**
     * Point d'entrée du client
     */
    public static void main(String[] args) {
        SecureClient client = new SecureClient();
        client.run();
    }
    
    /**
     * Exécute le client
     */
    public void run() {
        printBanner();
        printConfiguration();
        
        try {
            // Créer le contexte SSL
            SSLContext sslContext = createTrustAllSSLContext();
            SSLSocketFactory factory = sslContext.getSocketFactory();
            
            System.out.println("🔄 Tentative de connexion à " + SERVER_HOST + ":" + SERVER_PORT + "...");
            
            // Créer la socket avec timeout
            SSLSocket socket = (SSLSocket) factory.createSocket();
            socket.connect(new java.net.InetSocketAddress(SERVER_HOST, SERVER_PORT), CONNECTION_TIMEOUT);
            socket.setSoTimeout(READ_TIMEOUT);
            
            try (socket;
                 BufferedReader console = new BufferedReader(new InputStreamReader(System.in));
                 BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));
                 BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), "UTF-8"))) {
                
                // Afficher les informations de connexion
                printConnectionInfo(socket);
                
                // Boucle interactive
                interactiveLoop(console, in, out);
                
            }
            
            System.out.println("\n👋 Déconnexion réussie.");
            
        } catch (ConnectException e) {
            System.err.println("\n╔════════════════════════════════════════════════════════╗");
            System.err.println("║              ❌ ERREUR DE CONNEXION                    ║");
            System.err.println("╚════════════════════════════════════════════════════════╝");
            System.err.println("\n   Le serveur n'est pas accessible sur " + SERVER_HOST + ":" + SERVER_PORT);
            System.err.println("\n📋 Vérifications à faire :");
            System.err.println("   1️⃣  Le serveur SecureServer est-il lancé ?");
            System.err.println("   2️⃣  Le port " + SERVER_PORT + " est-il le bon ?");
            System.err.println("   3️⃣  Y a-t-il un firewall qui bloque la connexion ?");
            System.err.println("\n💡 Lancez d'abord : java Socket.SecureServer");
            
        } catch (SocketTimeoutException e) {
            System.err.println("\n❌ TIMEOUT - Le serveur ne répond pas assez rapidement");
            
        } catch (javax.net.ssl.SSLHandshakeException e) {
            System.err.println("\n❌ ERREUR SSL/TLS");
            System.err.println("   Impossible d'établir la connexion sécurisée");
            System.err.println("   Détails: " + e.getMessage());
            
        } catch (Exception e) {
            System.err.println("\n❌ ERREUR INATTENDUE: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Boucle interactive avec l'utilisateur
     */
    private void interactiveLoop(BufferedReader console, BufferedReader in, BufferedWriter out) throws Exception {
        String message;
        int messageCount = 0;
        
        while (true) {
            System.out.print("\n📤 Message > ");
            message = console.readLine();
            
            if (message == null) {
                break;
            }
            
            message = message.trim();
            
            // Commandes spéciales
            if ("exit".equalsIgnoreCase(message) || "quit".equalsIgnoreCase(message)) {
                System.out.println("🚪 Fermeture de la connexion...");
                break;
            }
            
            if (message.isEmpty()) {
                continue;
            }
            
            if ("help".equalsIgnoreCase(message)) {
                printHelp();
                continue;
            }
            
            if ("stats".equalsIgnoreCase(message)) {
                System.out.println("📊 Messages envoyés: " + messageCount);
                continue;
            }
            
            // Envoyer le message sécurisé
            try {
                String secureMessage = createSecureMessage(message);
                
                // Debug (décommentez si nécessaire)
                // System.out.println("🔍 [DEBUG] Message brut: " + secureMessage);
                
                out.write(secureMessage + "\r\n");
                out.flush();
                messageCount++;
                
                // Lire la réponse du serveur
                String response = in.readLine();
                
                if (response == null) {
                    System.err.println("⚠️  Le serveur a fermé la connexion");
                    break;
                }
                
                // Afficher la réponse avec formatage
                displayResponse(response);
                
            } catch (SocketTimeoutException e) {
                System.err.println("⏱️  Timeout - Le serveur ne répond pas");
            } catch (Exception e) {
                System.err.println("❌ Erreur lors de l'envoi: " + e.getMessage());
            }
        }
    }
    
    /**
     * Affiche la réponse du serveur avec formatage
     */
    private void displayResponse(String response) {
        if (response.startsWith("OK:")) {
            System.out.println("✅ Serveur: " + response);
        } else if (response.startsWith("ERR:REPLAY_ATTACK")) {
            System.out.println("🔄 Serveur: REPLAY ATTACK détecté!");
        } else if (response.startsWith("ERR:MESSAGE_EXPIRE")) {
            System.out.println("⏰ Serveur: Message expiré (timestamp trop ancien)");
        } else if (response.startsWith("ERR:INTEGRITE_COMPROMISE")) {
            System.out.println("🔐 Serveur: HMAC invalide - Intégrité compromise!");
        } else if (response.startsWith("ERR:")) {
            System.out.println("❌ Serveur: " + response);
        } else {
            System.out.println("📨 Serveur: " + response);
        }
    }
    
    /**
     * Crée un message sécurisé au format: NONCE|TIMESTAMP|MESSAGE|HMAC
     */
    private String createSecureMessage(String message) throws Exception {
        String nonce = UUID.randomUUID().toString();
        long timestamp = System.currentTimeMillis();
        String data = nonce + "|" + timestamp + "|" + message;
        String hmac = calculateHMAC(data, SECRET_KEY);
        
        return data + "|" + hmac;
    }
    
    /**
     * Calcule le HMAC-SHA256
     */
    private String calculateHMAC(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256");
        mac.init(keySpec);
        byte[] hmacBytes = mac.doFinal(data.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(hmacBytes);
    }
    
    /**
     * Crée un contexte SSL qui accepte tous les certificats
     * ⚠️ TEST UNIQUEMENT! En production, utilisez un truststore approprié
     */
    private SSLContext createTrustAllSSLContext() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        
        // TrustManager qui accepte tous les certificats (DANGEREUX en production!)
        TrustManager[] trustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { 
                    return null; 
                }
                public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
            }
        };
        
        ctx.init(null, trustAllCerts, new java.security.SecureRandom());
        return ctx;
    }
    
    /**
     * Affiche la bannière de démarrage
     */
    private void printBanner() {
        System.out.println("╔════════════════════════════════════════════════════════╗");
        System.out.println("║                                                        ║");
        System.out.println("║          CLIENT TCP SÉCURISÉ                          ║");
        System.out.println("║          Version 1.0 - ESSTHS LI3                     ║");
        System.out.println("║                                                        ║");
        System.out.println("╚════════════════════════════════════════════════════════╝");
        System.out.println();
    }
    
    /**
     * Affiche la configuration actuelle
     */
    private void printConfiguration() {
        System.out.println("📋 Configuration:");
        System.out.println("   • Hôte: " + SERVER_HOST);
        System.out.println("   • Port: " + SERVER_PORT);
        System.out.println("   • Clé partagée: " + maskSecret(SECRET_KEY));
        System.out.println("   • Timeout connexion: " + CONNECTION_TIMEOUT + "ms");
        System.out.println("   • Timeout lecture: " + READ_TIMEOUT + "ms");
        System.out.println();
    }
    
    /**
     * Affiche les informations de connexion SSL/TLS
     */
    private void printConnectionInfo(SSLSocket socket) throws Exception {
        System.out.println("╔════════════════════════════════════════════════════════╗");
        System.out.println("║              ✅ CONNEXION ÉTABLIE                      ║");
        System.out.println("╚════════════════════════════════════════════════════════╝");
        System.out.println("\n🔐 Informations de sécurité:");
        System.out.println("   • Protocole: " + socket.getSession().getProtocol());
        System.out.println("   • Cipher Suite: " + socket.getSession().getCipherSuite());
        System.out.println("   • Serveur: " + socket.getSession().getPeerHost() + ":" + socket.getPort());
        System.out.println("\n🛡️  Protections actives:");
        System.out.println("   ✓ Chiffrement end-to-end (TLS 1.3)");
        System.out.println("   ✓ Anti-Replay (Nonce + Timestamp)");
        System.out.println("   ✓ Intégrité (HMAC-SHA256)");
        System.out.println("\n💡 Tapez 'help' pour l'aide, 'exit' pour quitter");
    }
    
    /**
     * Affiche l'aide
     */
    private void printHelp() {
        System.out.println("\n╔════════════════════════════════════════════════════════╗");
        System.out.println("║                    COMMANDES                           ║");
        System.out.println("╠════════════════════════════════════════════════════════╣");
        System.out.println("║  help   - Afficher cette aide                         ║");
        System.out.println("║  stats  - Afficher les statistiques                   ║");
        System.out.println("║  exit   - Quitter le client (ou quit)                 ║");
        System.out.println("╚════════════════════════════════════════════════════════╝");
    }
    
    /**
     * Masque partiellement un secret pour l'affichage
     */
    private String maskSecret(String secret) {
        if (secret.length() <= 8) {
            return "****";
        }
        return secret.substring(0, 4) + "****" + secret.substring(secret.length() - 4);
    }
}