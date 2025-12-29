package Socket;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.security.KeyStore;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Serveur TCP Ultra-Sécurisé - Version Améliorée
 * 
 * Protections contre :
 * - Man-in-the-Middle (MITM) : TLS 1.3
 * - Replay Attack : Nonce + Timestamp + Cache
 * - Altération : HMAC-SHA256
 * - DoS : Thread Pool + Limites de connexions + Timeouts améliorés
 * - Slow clients : Read timeout par octet + Max line length
 * 
 * @author Mohamed Ghoul
 * @version 2.0
 */
public class SecureServer {
    
    // ═══════════════════════════════════════════════════════════
    // CONFIGURATION SÉCURITÉ
    // ═══════════════════════════════════════════════════════════
    private static final String SECRET_KEY = "VotreCleSuperSecrete2025!";
    private static final int PORT = 6443;
    private static final int READ_TIMEOUT_MS = 5000; // Réduit pour plus de réactivité
    private static final int BYTE_TIMEOUT_MS = 2000; // Timeout entre chaque octet
    private static final int MAX_LINE_LENGTH = 4096;
    private static final long REPLAY_WINDOW_MS = 15000;
    private static final int MAX_CONNECTIONS = 64;
    
    // ═══════════════════════════════════════════════════════════
    // GESTION AVANCÉE DES THREADS
    // ═══════════════════════════════════════════════════════════
    private static final ThreadPoolExecutor threadPool = new ThreadPoolExecutor(
        8, // corePoolSize
        32, // maximumPoolSize  
        60, // keepAliveTime
        TimeUnit.SECONDS,
        new LinkedBlockingQueue<>(128),
        new CustomThreadFactory(), // Factory personnalisée
        new ThreadPoolExecutor.CallerRunsPolicy() // Politique de rejet
    );
    
    // ═══════════════════════════════════════════════════════════
    // STATISTIQUES ET MONITORING
    // ═══════════════════════════════════════════════════════════
    private static final AtomicInteger activeConnections = new AtomicInteger(0);
    private static final AtomicInteger totalConnections = new AtomicInteger(0);
    private static final AtomicInteger blockedAttacks = new AtomicInteger(0);
    private static final AtomicInteger validMessages = new AtomicInteger(0);
    
    // ═══════════════════════════════════════════════════════════
    // CACHE ANTI-REPLAY AMÉLIORÉ
    // ═══════════════════════════════════════════════════════════
    private static final ConcurrentMap<String, Long> nonceCache = new ConcurrentHashMap<>();
    
    /**
     * Factory personnalisée pour les threads avec naming et gestion d'exceptions
     */
    private static class CustomThreadFactory implements ThreadFactory {
        private final AtomicInteger threadNumber = new AtomicInteger(1);
        
        @Override
        public Thread newThread(Runnable r) {
            Thread thread = new Thread(r, "secure-server-thread-" + threadNumber.getAndIncrement());
            thread.setUncaughtExceptionHandler((t, e) -> {
                log("🚨 THREAD CRASH: " + t.getName() + " - " + e.getMessage());
            });
            thread.setDaemon(true);
            return thread;
        }
    }
    
    /**
     * Point d'entrée du serveur
     */
    public static void main(String[] args) {
        printBanner();
        
        // Gestion propre de l'arrêt
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            shutdownServer();
        }));
        
        try {
            // Démarrer le serveur TLS
            SSLServerSocket serverSocket = createTLSServerSocket(PORT);
            log("✅ Serveur démarré avec succès sur le port " + PORT);
            
            // Démarrer les tâches de maintenance
            startMaintenanceTasks();
            
            // Accepter les connexions
            log("👂 En écoute des connexions...\n");
            
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                    totalConnections.incrementAndGet();
                    
                    // Vérifier la limite de connexions
                    if (activeConnections.get() >= MAX_CONNECTIONS) {
                        log("⚠️  REFUSÉ - Limite de connexions atteinte (" + activeConnections.get() + "/" + MAX_CONNECTIONS + ")");
                        clientSocket.close();
                        continue;
                    }
                    
                    activeConnections.incrementAndGet();
                    threadPool.submit(new ClientHandler(clientSocket));
                    
                } catch (IOException e) {
                    if (!Thread.currentThread().isInterrupted()) {
                        log("❌ Erreur acceptation: " + e.getMessage());
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("\n❌ [FATAL] Impossible de démarrer le serveur");
            System.err.println("   Raison: " + e.getMessage());
            System.err.println("\n📋 Vérifications :");
            System.err.println("   1. Le fichier serverkeystore.jks existe-t-il ?");
            System.err.println("   2. Le port " + PORT + " est-il disponible ?");
            System.err.println("   3. Exécutez : lsof -i :" + PORT + " (Linux/Mac) ou netstat -ano | findstr " + PORT + " (Windows)");
            e.printStackTrace();
        }
    }
    
    /**
     * Handler dédié pour chaque client (Runnable)
     */
    private static class ClientHandler implements Runnable {
        private final SSLSocket clientSocket;
        
        public ClientHandler(SSLSocket socket) {
            this.clientSocket = socket;
        }
        
        @Override
        public void run() {
            handleClient(clientSocket);
        }
    }
    
    /**
     * Crée un ServerSocket TLS sécurisé
     */
    private static SSLServerSocket createTLSServerSocket(int port) throws Exception {
        // Charger le keystore
        char[] keystorePassword = "changeit".toCharArray();
        KeyStore keystore = KeyStore.getInstance("JKS");
        
        try (FileInputStream fis = new FileInputStream("serverkeystore.jks")) {
            keystore.load(fis, keystorePassword);
        }
        
        // Initialiser le KeyManager
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keystore, keystorePassword);
        
        // Créer le contexte SSL avec TLS 1.3
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(kmf.getKeyManagers(), null, null);
        
        // Créer le ServerSocket TLS
        SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(port);
        
        // Forcer TLS 1.3 uniquement
        serverSocket.setEnabledProtocols(new String[]{"TLSv1.3"});
        
        return serverSocket;
    }
    
    /**
     * Traite une connexion client
     */
    private static void handleClient(SSLSocket clientSocket) {
        String clientInfo = clientSocket.getRemoteSocketAddress().toString();
        String threadName = Thread.currentThread().getName();
        
        try {
            clientSocket.setSoTimeout(READ_TIMEOUT_MS);
            
            BufferedReader in = new BufferedReader(
                new InputStreamReader(clientSocket.getInputStream(), "UTF-8")
            );
            BufferedWriter out = new BufferedWriter(
                new OutputStreamWriter(clientSocket.getOutputStream(), "UTF-8")
            );
            
            log("🔗 CONNECTÉ: " + clientInfo + " [Thread: " + threadName + "] (Actifs: " + activeConnections.get() + ")");
            
            // Lire et traiter les messages
            String line;
            while ((line = readBoundedLineWithTimeout(in)) != null) {
                String response = processSecureMessage(line, clientInfo);
                out.write(response + "\r\n");
                out.flush();
            }
            
        } catch (SocketTimeoutException e) {
            log("⏱️  TIMEOUT: " + clientInfo + " - Lecture trop lente");
        } catch (IOException e) {
            if (e.getMessage() != null && e.getMessage().contains("trop longue")) {
                log("📏 LIGNE TROP LONGUE: " + clientInfo);
                try {
                    BufferedWriter out = new BufferedWriter(
                        new OutputStreamWriter(clientSocket.getOutputStream(), "UTF-8"));
                    out.write("ERR:LIGNE_TROP_LONGUE\r\n");
                    out.flush();
                } catch (IOException ignored) {}
            } else {
                log("⚠️  ERREUR I/O: " + clientInfo + " - " + e.getMessage());
            }
        } finally {
            try {
                clientSocket.close();
            } catch (IOException ignored) {}
            activeConnections.decrementAndGet();
            log("🔌 DÉCONNECTÉ: " + clientInfo + " (Actifs: " + activeConnections.get() + ")");
        }
    }
    
    /**
     * Traite un message sécurisé avec vérifications anti-attaque
     * Format attendu: NONCE|TIMESTAMP|MESSAGE|HMAC
     */
    private static String processSecureMessage(String line, String clientInfo) {
        try {
            // Parser le message
            String[] parts = line.split("\\|", 4);
            if (parts.length != 4) {
                logSecurityEvent("FORMAT_INVALIDE", clientInfo, "Parts: " + parts.length);
                return "ERR:FORMAT_INVALIDE";
            }
            
            String nonce = parts[0];
            String timestampStr = parts[1];
            String message = parts[2];
            String receivedHmac = parts[3];
            
            // Vérifier le timestamp (anti-replay temporel)
            long timestamp;
            try {
                timestamp = Long.parseLong(timestampStr);
            } catch (NumberFormatException e) {
                logSecurityEvent("TIMESTAMP_INVALIDE", clientInfo, "Valeur: " + timestampStr);
                return "ERR:TIMESTAMP_INVALIDE";
            }
            
            long now = System.currentTimeMillis();
            long timeDiff = Math.abs(now - timestamp);
            
            if (timeDiff > REPLAY_WINDOW_MS) {
                logSecurityEvent("REPLAY_TEMPS", clientInfo, "Diff: " + timeDiff + "ms");
                blockedAttacks.incrementAndGet();
                return "ERR:MESSAGE_EXPIRE";
            }
            
            // Vérifier le nonce (anti-replay par unicité)
            if (nonceCache.putIfAbsent(nonce, now) != null) {
                logSecurityEvent("REPLAY_NONCE", clientInfo, "Nonce: " + nonce.substring(0, 8) + "...");
                blockedAttacks.incrementAndGet();
                return "ERR:REPLAY_ATTACK";
            }
            
            // Vérifier l'intégrité avec HMAC
            String data = nonce + "|" + timestamp + "|" + message;
            String expectedHmac = calculateHMAC(data, SECRET_KEY);
            
            if (!expectedHmac.equals(receivedHmac)) {
                logSecurityEvent("HMAC_INVALIDE", clientInfo, "Altération détectée");
                blockedAttacks.incrementAndGet();
                return "ERR:INTEGRITE_COMPROMISE";
            }
            
            // Message valide - Traiter
            validMessages.incrementAndGet();
            log("✅ MESSAGE VALIDE: " + clientInfo + " - " + preview(message));
            return "OK:MESSAGE_ACCEPTE:" + message;
            
        } catch (Exception e) {
            log("❌ ERREUR TRAITEMENT: " + clientInfo + " - " + e.getMessage());
            return "ERR:ERREUR_SERVEUR";
        }
    }
    
    /**
     * Lit une ligne avec limitation de taille ET timeout par octet
     */
    private static String readBoundedLineWithTimeout(BufferedReader in) throws IOException {
        StringBuilder sb = new StringBuilder();
        long lastByteTime = System.currentTimeMillis();
        int ch;
        
        while ((ch = in.read()) != -1) {
            // Vérifier le timeout entre les octets
            long currentTime = System.currentTimeMillis();
            if (currentTime - lastByteTime > BYTE_TIMEOUT_MS) {
                throw new SocketTimeoutException("Timeout entre les octets dépassé");
            }
            lastByteTime = currentTime;
            
            if (ch == '\n') {
                break;
            }
            if (ch != '\r') {
                sb.append((char) ch);
            }
            if (sb.length() > MAX_LINE_LENGTH) {
                throw new IOException("Ligne trop longue (> " + MAX_LINE_LENGTH + ")");
            }
        }
        
        return (sb.length() == 0 && ch == -1) ? null : sb.toString();
    }
    
    /**
     * Calcule le HMAC-SHA256 d'un message
     */
    private static String calculateHMAC(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256");
        mac.init(keySpec);
        byte[] hmacBytes = mac.doFinal(data.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(hmacBytes);
    }
    
    /**
     * Démarre les tâches de maintenance périodiques
     */
    private static void startMaintenanceTasks() {
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);
        
        // Nettoyage du cache anti-replay
        scheduler.scheduleAtFixedRate(() -> {
            long now = System.currentTimeMillis();
            int removed = 0;
            
            for (var entry : nonceCache.entrySet()) {
                if (now - entry.getValue() > REPLAY_WINDOW_MS) {
                    nonceCache.remove(entry.getKey());
                    removed++;
                }
            }
            
            if (removed > 0) {
                log("🧹 Cache nettoyé: " + removed + " entrées supprimées");
            }
        }, 10, 10, TimeUnit.SECONDS);
        
        // Statistiques périodiques
        scheduler.scheduleAtFixedRate(() -> {
            logStats();
        }, 30, 30, TimeUnit.SECONDS);
        
        // Monitoring du thread pool
        scheduler.scheduleAtFixedRate(() -> {
            logThreadPoolStats();
        }, 60, 60, TimeUnit.SECONDS);
    }
    
    /**
     * Arrêt propre du serveur
     */
    private static void shutdownServer() {
        log("🚦 Arrêt du serveur en cours...");
        
        // Arrêt du thread pool
        threadPool.shutdown();
        try {
            if (!threadPool.awaitTermination(10, TimeUnit.SECONDS)) {
                threadPool.shutdownNow();
            }
        } catch (InterruptedException e) {
            threadPool.shutdownNow();
            Thread.currentThread().interrupt();
        }
        
        log("📊 STATISTIQUES FINALES:");
        log("   Connexions totales: " + totalConnections.get());
        log("   Messages valides: " + validMessages.get());
        log("   Attaques bloquées: " + blockedAttacks.get());
        log("   Cache size: " + nonceCache.size());
        log("👋 Serveur arrêté proprement");
    }
    
    /**
     * Journalisation des événements de sécurité
     */
    private static void logSecurityEvent(String eventType, String clientInfo, String details) {
        System.out.println("🚨 [SECURITY] " + eventType + " - " + clientInfo + " - " + details);
    }
    
    /**
     * Affiche les statistiques du serveur
     */
    private static void logStats() {
        System.out.println("📈 [STATS] Connexions: " + activeConnections.get() + 
                         "/" + MAX_CONNECTIONS + " actives | " +
                         "Messages: " + validMessages.get() + " valides | " +
                         "Attaques: " + blockedAttacks.get() + " bloquées");
    }
    
    /**
     * Affiche les statistiques du thread pool
     */
    private static void logThreadPoolStats() {
        System.out.println("🔄 [THREADS] Pool: " + threadPool.getPoolSize() + 
                         "/" + threadPool.getMaximumPoolSize() + " threads | " +
                         "Queue: " + threadPool.getQueue().size() + " en attente | " +
                         "Actifs: " + threadPool.getActiveCount() + " actifs");
    }
    
    /**
     * Prévisualisation d'un message (tronqué si trop long)
     */
    private static String preview(String s) {
        return s.length() > 60 ? s.substring(0, 60) + "..." : s;
    }
    
    /**
     * Journalisation avec timestamp
     */
    private static void log(String message) {
        System.out.println("[" + LocalDateTime.now().toString().substring(11, 19) + "] " + message);
    }
    
    /**
     * Affiche la bannière de démarrage
     */
    private static void printBanner() {
        System.out.println("╔════════════════════════════════════════════════════════╗");
        System.out.println("║                                                        ║");
        System.out.println("║          SERVEUR TCP ULTRA-SÉCURISÉ v2.0              ║");
        System.out.println("║          Version Améliorée - Mohamed Ghoul            ║");
        System.out.println("║                                                        ║");
        System.out.println("╠════════════════════════════════════════════════════════╣");
        System.out.println("║  🔐 TLS 1.3         : Chiffrement end-to-end           ║");
        System.out.println("║  🔄 Anti-Replay     : Nonce + Timestamp + Cache        ║");
        System.out.println("║  🛡️  HMAC-SHA256     : Vérification d'intégrité        ║");
        System.out.println("║  ⚡ Thread Pool     : Gestion avancée des threads      ║");
        System.out.println("║  ⏱️  Timeout Octet   : Protection renforcée slow client ║");
        System.out.println("║  📊 Monitoring      : Statistiques en temps réel      ║");
        System.out.println("║  🚫 Rate Limiting   : Max " + MAX_CONNECTIONS + " connexions simultanées ║");
        System.out.println("╚════════════════════════════════════════════════════════╝");
        System.out.println();
    }
}