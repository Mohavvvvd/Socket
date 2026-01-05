package attack;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Programme de test des attaques réseau contre le serveur sécurisé
 * 
 * @author Mohamed Ghoul
 * @version 1.0
 */
public class AttackTester {
    
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 6443;
    private static final String SECRET_KEY = "CleSuperSecrete2026!";
    
    public static void main(String[] args) throws Exception {
        printBanner();
        
        Scanner scanner = new Scanner(System.in);
        
        while (true) {
            System.out.println("\n🔻 MENU DES ATTAQUES 🔻");
            System.out.println("1. Attaque Man-in-the-Middle (Altération)");
            System.out.println("2. Attaque par Rejeu (Replay)");
            System.out.println("3. Client Lent (Slow Loris)");
            System.out.println("4. Attaque par Déni de Service (Connexions multiples)");
            System.out.println("5. Message Trop Long");
            System.out.println("6. Test de message valide (référence)");
            System.out.println("7. Test avec HMAC invalide");
            System.out.println("8. Test avec Timestamp expiré");
            System.out.println("9. Test avec Nonce dupliqué");
            System.out.println("0. Quitter");
            System.out.print("Choisissez une attaque > ");
            
            int choice;
            try {
                choice = Integer.parseInt(scanner.nextLine());
            } catch (NumberFormatException e) {
                System.out.println("❌ Choix invalide");
                continue;
            }
            
            switch (choice) {
                case 1 -> testMitmAttack();
                case 2 -> testReplayAttack();
                case 3 -> testSlowClient();
                case 4 -> testDosAttack();
                case 5 -> testOversizedMessage();
                case 6 -> testValidMessage();
                case 7 -> testInvalidHmac();
                case 8 -> testExpiredTimestamp();
                case 9 -> testDuplicateNonce();
                case 0 -> {
                    System.out.println("👋 Au revoir!");
                    return;
                }
                default -> System.out.println("❌ Option non valide");
            }
        }
    }
    
    /**
     * 1. Simulation d'attaque Man-in-the-Middle par altération
     */
    private static void testMitmAttack() {
        System.out.println("\n🔓 TEST MITM - Altération de message");
        
        try {
            // Créer un message valide
            String nonce = UUID.randomUUID().toString();
            long timestamp = System.currentTimeMillis();
            String message = "TRANSFERT:1000€ vers compte 12345";
            String data = nonce + "|" + timestamp + "|" + message;
            String hmac = calculateHMAC(data, SECRET_KEY);
            String validMessage = data + "|" + hmac;
            
            // Altérer le message (simulation MITM)
            String tamperedMessage = validMessage.replace("1000", "5000");
            
            System.out.println("📤 Message original: " + message);
            System.out.println("⚠️  Message altéré: " + tamperedMessage);
            
            // Envoyer le message altéré
            String response = sendMessage(tamperedMessage);
            System.out.println("📥 Réponse serveur: " + response);
            
        } catch (Exception e) {
            System.out.println("❌ Erreur: " + e.getMessage());
        }
    }
    
    /**
     * 2. Attaque par rejeu (Replay Attack)
     */
    private static void testReplayAttack() {
        System.out.println("\n🔁 TEST REPLAY ATTACK");
        
        try {
            // Premier message valide
            String nonce = UUID.randomUUID().toString();
            long timestamp = System.currentTimeMillis();
            String message = "ACHAT:Produit XYZ - 500€";
            String data = nonce + "|" + timestamp + "|" + message;
            String hmac = calculateHMAC(data, SECRET_KEY);
            String validMessage = data + "|" + hmac;
            
            System.out.println("📤 Premier envoi (valide)...");
            String response1 = sendMessage(validMessage);
            System.out.println("📥 Réponse 1: " + response1);
            
            // Rejouer exactement le même message
            System.out.println("🔄 Rejeu du même message...");
            String response2 = sendMessage(validMessage);
            System.out.println("📥 Réponse 2: " + response2);
            
        } catch (Exception e) {
            System.out.println("❌ Erreur: " + e.getMessage());
        }
    }
    
    /**
     * 3. Client Lent (Slow Loris)
     */
    private static void testSlowClient() {
        System.out.println("\n🐌 TEST SLOW CLIENT");
        
        new Thread(() -> {
            try (SSLSocket socket = createSSLSocket(SERVER_HOST, SERVER_PORT);
                 OutputStream out = socket.getOutputStream()) {
                
                socket.setSoTimeout(30000);
                
                String nonce = UUID.randomUUID().toString();
                long timestamp = System.currentTimeMillis();
                String message = "SLOW:Je suis un client très lent";
                String data = nonce + "|" + timestamp + "|" + message;
                String hmac = calculateHMAC(data, SECRET_KEY);
                String fullMessage = data + "|" + hmac + "\r\n";
                
                byte[] messageBytes = fullMessage.getBytes("UTF-8");
                
                System.out.println("⏳ Envoi très lent...");
                
                // Envoi octet par octet avec délai
                for (int i = 0; i < messageBytes.length; i++) {
                    out.write(messageBytes[i]);
                    out.flush();
                    Thread.sleep(1000); // 1 seconde entre chaque octet
                    System.out.println("📤 Envoyé octet " + (i + 1) + "/" + messageBytes.length);
                }
                
                // Lire la réponse
                BufferedReader in = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), "UTF-8"));
                String response = in.readLine();
                System.out.println("📥 Réponse: " + response);
                
            } catch (Exception e) {
                System.out.println("❌ Connexion interrompue: " + e.getMessage());
            }
        }).start();
    }
    
    /**
     * 4. Attaque par Déni de Service (connexions multiples)
     */
    private static void testDosAttack() {
        System.out.println("\n💥 TEST DOS - Connexions multiples");
        
        int numConnections = 50;
        System.out.println("🚀 Tentative de " + numConnections + " connexions simultanées...");
        
        ExecutorService executor = Executors.newFixedThreadPool(numConnections);
        List<Future<String>> results = new ArrayList<>();
        
        for (int i = 0; i < numConnections; i++) {
            final int clientId = i + 1;
            Future<String> future = executor.submit(() -> {
                try (SSLSocket socket = createSSLSocket(SERVER_HOST, SERVER_PORT);
                     BufferedReader in = new BufferedReader(
                         new InputStreamReader(socket.getInputStream(), "UTF-8"));
                     BufferedWriter out = new BufferedWriter(
                         new OutputStreamWriter(socket.getOutputStream(), "UTF-8"))) {
                    
                    socket.setSoTimeout(5000);
                    
                    String nonce = UUID.randomUUID().toString();
                    long timestamp = System.currentTimeMillis();
                    String message = "DOS:Client " + clientId;
                    String data = nonce + "|" + timestamp + "|" + message;
                    String hmac = calculateHMAC(data, SECRET_KEY);
                    String fullMessage = data + "|" + hmac;
                    
                    out.write(fullMessage + "\r\n");
                    out.flush();
                    
                    String response = in.readLine();
                    return "Client " + clientId + ": " + response;
                    
                } catch (Exception e) {
                    return "Client " + clientId + ": ÉCHEC - " + e.getMessage();
                }
            });
            results.add(future);
        }
        
        // Afficher les résultats
        executor.shutdown();
        try {
            executor.awaitTermination(30, TimeUnit.SECONDS);
            
            int success = 0, failed = 0;
            for (Future<String> future : results) {
                String result = future.get();
                System.out.println(result);
                if (result.contains("OK")) success++;
                else failed++;
            }
            
            System.out.println("\n📊 STATISTIQUES DOS:");
            System.out.println("✅ Réussites: " + success);
            System.out.println("❌ Échecs: " + failed);
            
        } catch (Exception e) {
            System.out.println("❌ Erreur pendant l'attaque DOS: " + e.getMessage());
        }
    }
    
    /**
     * 5. Message trop long
     */
    private static void testOversizedMessage() {
        System.out.println("\n📏 TEST MESSAGE TROP LONG");
        
        try {
            String nonce = UUID.randomUUID().toString();
            long timestamp = System.currentTimeMillis();
            
            // Créer un message très long
            String longMessage = "A".repeat(10000); // 10,000 caractères
            String data = nonce + "|" + timestamp + "|" + longMessage;
            String hmac = calculateHMAC(data, SECRET_KEY);
            String oversizedMessage = data + "|" + hmac;
            
            System.out.println("📤 Envoi message de " + oversizedMessage.length() + " caractères...");
            String response = sendMessage(oversizedMessage);
            System.out.println("📥 Réponse: " + response);
            
        } catch (Exception e) {
            System.out.println("❌ Erreur: " + e.getMessage());
        }
    }
    
    /**
     * 6. Test de message valide (référence)
     */
    private static void testValidMessage() {
        System.out.println("\n✅ TEST MESSAGE VALIDE");
        
        try {
            String nonce = UUID.randomUUID().toString();
            long timestamp = System.currentTimeMillis();
            String message = "COMMANDE:Produit ABC - Quantité: 5";
            String data = nonce + "|" + timestamp + "|" + message;
            String hmac = calculateHMAC(data, SECRET_KEY);
            String validMessage = data + "|" + hmac;
            
            System.out.println("📤 Message: " + message);
            String response = sendMessage(validMessage);
            System.out.println("📥 Réponse: " + response);
            
        } catch (Exception e) {
            System.out.println("❌ Erreur: " + e.getMessage());
        }
    }
    
    /**
     * 7. Test avec HMAC invalide
     */
    private static void testInvalidHmac() {
        System.out.println("\n🔐 TEST HMAC INVALIDE");
        
        try {
            String nonce = UUID.randomUUID().toString();
            long timestamp = System.currentTimeMillis();
            String message = "TRANSACTION_SECRETE";
            String data = nonce + "|" + timestamp + "|" + message;
            
            // Utiliser une mauvaise clé pour le HMAC
            String invalidHmac = calculateHMAC(data, "MauvaiseCle");
            String invalidMessage = data + "|" + invalidHmac;
            
            System.out.println("📤 Message avec HMAC invalide...");
            String response = sendMessage(invalidMessage);
            System.out.println("📥 Réponse: " + response);
            
        } catch (Exception e) {
            System.out.println("❌ Erreur: " + e.getMessage());
        }
    }
    
    /**
     * 8. Test avec Timestamp expiré
     */
    private static void testExpiredTimestamp() {
        System.out.println("\n⏰ TEST TIMESTAMP EXPIRE");
        
        try {
            String nonce = UUID.randomUUID().toString();
            
            // Timestamp vieux de 1 heure
            long expiredTimestamp = System.currentTimeMillis() - (60 * 60 * 1000);
            String message = "MESSAGE_EXPIRE";
            String data = nonce + "|" + expiredTimestamp + "|" + message;
            String hmac = calculateHMAC(data, SECRET_KEY);
            String expiredMessage = data + "|" + hmac;
            
            System.out.println("📤 Message avec timestamp expiré...");
            String response = sendMessage(expiredMessage);
            System.out.println("📥 Réponse: " + response);
            
        } catch (Exception e) {
            System.out.println("❌ Erreur: " + e.getMessage());
        }
    }
    
    /**
     * 9. Test avec Nonce dupliqué
     */
    private static void testDuplicateNonce() {
        System.out.println("\n🔄 TEST NONCE DUPLIQUE");
        
        try {
            // Utiliser le même nonce deux fois
            String duplicateNonce = "NONCE_DUPLIQUE_12345";
            long timestamp1 = System.currentTimeMillis();
            String message1 = "PREMIER_MESSAGE";
            String data1 = duplicateNonce + "|" + timestamp1 + "|" + message1;
            String hmac1 = calculateHMAC(data1, SECRET_KEY);
            String message1Full = data1 + "|" + hmac1;
            
            long timestamp2 = System.currentTimeMillis() + 1000;
            String message2 = "DEUXIEME_MESSAGE_MEME_NONCE";
            String data2 = duplicateNonce + "|" + timestamp2 + "|" + message2;
            String hmac2 = calculateHMAC(data2, SECRET_KEY);
            String message2Full = data2 + "|" + hmac2;
            
            System.out.println("📤 Premier message...");
            String response1 = sendMessage(message1Full);
            System.out.println("📥 Réponse 1: " + response1);
            
            System.out.println("📤 Deuxième message (même nonce)...");
            String response2 = sendMessage(message2Full);
            System.out.println("📥 Réponse 2: " + response2);
            
        } catch (Exception e) {
            System.out.println("❌ Erreur: " + e.getMessage());
        }
    }
    
    /**
     * Méthode utilitaire pour envoyer un message
     */
    private static String sendMessage(String message) {
        try (SSLSocket socket = createSSLSocket(SERVER_HOST, SERVER_PORT);
             BufferedReader in = new BufferedReader(
                 new InputStreamReader(socket.getInputStream(), "UTF-8"));
             BufferedWriter out = new BufferedWriter(
                 new OutputStreamWriter(socket.getOutputStream(), "UTF-8"))) {
            
            socket.setSoTimeout(10000);
            out.write(message + "\r\n");
            out.flush();
            
            return in.readLine();
            
        } catch (Exception e) {
            return "ERREUR: " + e.getMessage();
        }
    }
    
    /**
     * Crée une socket SSL (ignorer la vérification du certificat pour les tests)
     */
    private static SSLSocket createSSLSocket(String host, int port) throws Exception {
        // Configuration SSL pour ignorer la vérification des certificats (tests uniquement)
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(null, new TrustManager[]{
            new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) { }
                public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) { }
            }
        }, new SecureRandom());
        
        SSLSocketFactory factory = sslContext.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
        socket.setEnabledProtocols(new String[]{"TLSv1.3"});
        
        return socket;
    }
    
    /**
     * Calcule le HMAC-SHA256
     */
    private static String calculateHMAC(String data, String secret) throws Exception {
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(
            secret.getBytes("UTF-8"), "HmacSHA256");
        mac.init(keySpec);
        byte[] hmacBytes = mac.doFinal(data.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(hmacBytes);
    }
    
    /**
     * Affiche la bannière
     */
    private static void printBanner() {
        System.out.println("╔════════════════════════════════════════════════════════╗");
        System.out.println("║                                                        ║");
        System.out.println("║           TESTEUR D'ATTAQUES RÉSEAU                   ║");
        System.out.println("║           Contre Serveur Sécurisé                     ║");
        System.out.println("║           Version 1.0 - Mohamed Ghoul                 ║");
        System.out.println("║                                                        ║");
        System.out.println("╠════════════════════════════════════════════════════════╣");
        System.out.println("║  ⚠️   UTILISATION PÉDAGOGIQUE UNIQUEMENT              ║");
        System.out.println("║  ⚠️   Ne pas utiliser sur des systèmes non autorisés  ║");
        System.out.println("╚════════════════════════════════════════════════════════╝");
        System.out.println();
    }
}
