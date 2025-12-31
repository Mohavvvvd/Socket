# 🔐 Serveur TCP Ultra-Sécurisé

## 📋 Description du Projet

Ce projet implémente un système de communication client-serveur TCP sécurisé en Java, avec des protections avancées contre les attaques réseau les plus courantes. Il utilise **TLS 1.3** pour le chiffrement des communications et **HMAC-SHA256** pour garantir l'intégrité des messages.

### 🎯 Objectifs Pédagogiques

- Comprendre les principes de la sécurité réseau
- Implémenter des protections contre les attaques courantes (MITM, Replay, DoS)
- Maîtriser les sockets SSL/TLS en Java
- Gérer des connexions concurrentes avec un Thread Pool

---

## 🏗️ Architecture du Projet

```
Socket/
├── src/
│   ├── Socket/
│   │   ├── SecureServer.java      # Serveur sécurisé principal
│   │   └── SecureClient.java      # Client sécurisé
│   └── attack/
│       └── AttackTester.java      # Outil de test des attaques
├── serverkeystore.jks             # Certificat SSL/TLS (à générer)
└── README.md
```

---

## 🛡️ Mécanismes de Sécurité

### 1. **Chiffrement TLS 1.3**
- Chiffrement end-to-end de toutes les communications
- Protection contre les attaques Man-in-the-Middle (MITM)

### 2. **Authentification par HMAC-SHA256**
- Vérification de l'intégrité des messages
- Détection des altérations de données

### 3. **Protection Anti-Replay**
- **Nonce unique** : UUID pour chaque message
- **Timestamp** : Fenêtre de validité de 15 secondes
- **Cache** : Mémorisation des nonces déjà utilisés

### 4. **Protection Anti-DoS**
- Thread Pool limité (8-32 threads)
- Maximum de 64 connexions simultanées
- Timeouts configurables sur les lectures

### 5. **Protection Slow Client**
- Timeout global de 5 secondes
- Timeout inter-octets de 2 secondes
- Limitation de la taille des messages (4096 caractères)

---

## 📦 Prérequis

### Logiciels Requis
- **Java JDK 22** ou supérieur
- **Eclipse IDE** (ou tout autre IDE Java)
- **Keytool** (inclus avec le JDK)

### Génération du Certificat SSL

Avant de lancer le serveur, vous devez générer un certificat SSL :

```bash
keytool -genkeypair -alias serverkey -keyalg RSA -keysize 2048 \
  -validity 365 -keystore serverkeystore.jks -storepass changeit \
  -keypass changeit -dname "CN=localhost, OU=ESSTHS, O=ESSTHS, L=Sousse, ST=Sousse, C=TN"
```

⚠️ **Important** : Le fichier `serverkeystore.jks` doit être placé à la racine du projet.

---

## 🚀 Installation et Démarrage

### 1. **Cloner ou Importer le Projet**

```bash
# Si vous utilisez Git
git clone https://github.com/Mohavvvvd/Socket.git
cd Socket

# Ou importez le projet dans Eclipse
```

### 2. **Configurer le Projet dans Eclipse**

1. Ouvrir Eclipse
2. `File` → `Import` → `Existing Projects into Workspace`
3. Sélectionner le dossier `Socket`
4. Vérifier que le JDK 22 est configuré

### 3. **Lancer le Serveur**

```bash
# Depuis Eclipse : Run As → Java Application
# Ou en ligne de commande :
cd Socket/bin
java Socket.SecureServer
```

**Sortie attendue :**
```
╔════════════════════════════════════════════════════════╗
║          SERVEUR TCP ULTRA-SÉCURISÉ v2.0              ║
╚════════════════════════════════════════════════════════╝
[10:30:45] ✅ Serveur démarré avec succès sur le port 6443
[10:30:45] 👂 En écoute des connexions...
```

### 4. **Lancer le Client**

**Dans un nouveau terminal ou une nouvelle console Eclipse :**

```bash
java Socket.SecureClient
```

**Sortie attendue :**
```
╔════════════════════════════════════════════════════════╗
║              ✅ CONNEXION ÉTABLIE                      ║
╚════════════════════════════════════════════════════════╝
📤 Message >
```

---

## 💬 Utilisation du Client

### Commandes Disponibles

| Commande | Description |
|----------|-------------|
| `help` | Afficher l'aide |
| `stats` | Afficher les statistiques |
| `exit` ou `quit` | Quitter le client |
| *Tout autre texte* | Envoyer un message au serveur |

### Exemple de Session

```
📤 Message > Bonjour serveur!
✅ Serveur: OK:MESSAGE_ACCEPTE:Bonjour serveur!

📤 Message > Commande #12345
✅ Serveur: OK:MESSAGE_ACCEPTE:Commande #12345

📤 Message > stats
📊 Messages envoyés: 2

📤 Message > exit
🚪 Fermeture de la connexion...
👋 Déconnexion réussie.
```

---

## 🧪 Tests des Attaques

Le projet inclut un **testeur d'attaques** pour valider les protections du serveur.

### Lancer le Testeur

```bash
java attack.AttackTester
```

### Menu des Attaques

```
🔻 MENU DES ATTAQUES 🔻
1. Attaque Man-in-the-Middle (Altération)
2. Attaque par Rejeu (Replay)
3. Client Lent (Slow Loris)
4. Attaque par Déni de Service (Connexions multiples)
5. Message Trop Long
6. Test de message valide (référence)
7. Test avec HMAC invalide
8. Test avec Timestamp expiré
9. Test avec Nonce dupliqué
0. Quitter
```

### Résultats Attendus

| Attaque | Résultat Attendu |
|---------|------------------|
| **MITM (Altération)** | `ERR:INTEGRITE_COMPROMISE` |
| **Replay Attack** | `ERR:REPLAY_ATTACK` |
| **Slow Client** | Timeout + déconnexion |
| **DoS** | Connexions limitées à 64 |
| **Message Trop Long** | `ERR:LIGNE_TROP_LONGUE` |
| **HMAC Invalide** | `ERR:INTEGRITE_COMPROMISE` |
| **Timestamp Expiré** | `ERR:MESSAGE_EXPIRE` |
| **Nonce Dupliqué** | `ERR:REPLAY_ATTACK` |

---

## 🔧 Configuration

### Paramètres du Serveur (`SecureServer.java`)

```java
private static final String SECRET_KEY = "VotreCleSuperSecrete2025!";
private static final int PORT = 6443;
private static final int READ_TIMEOUT_MS = 5000;
private static final int BYTE_TIMEOUT_MS = 2000;
private static final int MAX_LINE_LENGTH = 4096;
private static final long REPLAY_WINDOW_MS = 15000;  // 15 secondes
private static final int MAX_CONNECTIONS = 64;
```

### Paramètres du Client (`SecureClient.java`)

```java
private static final String SECRET_KEY = "VotreCleSuperSecrete2025!";
private static final String SERVER_HOST = "localhost";
private static final int SERVER_PORT = 6443;
private static final int CONNECTION_TIMEOUT = 5000;
private static final int READ_TIMEOUT = 10000;
```

⚠️ **Important** : La `SECRET_KEY` doit être **identique** entre le serveur et le client !

---

## 📊 Format des Messages

### Structure d'un Message Sécurisé

```
NONCE|TIMESTAMP|MESSAGE|HMAC
```

**Exemple :**
```
a1b2c3d4-e5f6-7890-1234-567890abcdef|1735477200000|Bonjour|AbCdEf123...=
```

| Champ | Description |
|-------|-------------|
| **NONCE** | UUID unique pour éviter les replay attacks |
| **TIMESTAMP** | Horodatage en millisecondes (epoch Unix) |
| **MESSAGE** | Contenu du message en clair |
| **HMAC** | Hash HMAC-SHA256 calculé sur `NONCE\|TIMESTAMP\|MESSAGE` |

---

## 📈 Monitoring et Statistiques

### Statistiques Serveur

Le serveur affiche automatiquement des statistiques toutes les 30 secondes :

```
[10:35:45] 📈 [STATS] Connexions: 3/64 actives | Messages: 127 valides | Attaques: 5 bloquées
[10:36:45] 🔄 [THREADS] Pool: 12/32 threads | Queue: 0 en attente | Actifs: 3 actifs
```

### Logs d'Événements

```
[10:30:45] 🔗 CONNECTÉ: /127.0.0.1:54321 [Thread: secure-server-thread-1] (Actifs: 1)
[10:31:12] ✅ MESSAGE VALIDE: /127.0.0.1:54321 - Bonjour serveur!
[10:31:45] 🚨 [SECURITY] REPLAY_NONCE - /127.0.0.1:54321 - Nonce: a1b2c3d4...
[10:32:00] 🔌 DÉCONNECTÉ: /127.0.0.1:54321 (Actifs: 0)
```

---

## 🐛 Dépannage

### Le serveur ne démarre pas

**Erreur :** `FileNotFoundException: serverkeystore.jks`

**Solution :** Générez le certificat SSL avec la commande keytool (voir section Prérequis).

---

**Erreur :** `Address already in use (port 6443)`

**Solution :** Le port est déjà utilisé. Vérifiez avec :
```bash
# Linux/Mac
lsof -i :6443

# Windows
netstat -ano | findstr 6443
```

### Le client ne se connecte pas

**Erreur :** `ConnectException`

**Solution :**
1. Vérifiez que le serveur est lancé
2. Vérifiez que le port est le même (6443)
3. Vérifiez le firewall

---

**Erreur :** `ERR:INTEGRITE_COMPROMISE`

**Solution :** La `SECRET_KEY` est différente entre le client et le serveur. Vérifiez qu'elles sont identiques.

---

## 📚 Concepts Clés

### HMAC (Hash-based Message Authentication Code)

Le HMAC permet de vérifier :
- **L'authenticité** : Le message provient bien du bon émetteur
- **L'intégrité** : Le message n'a pas été modifié en transit

### Replay Attack

Une attaque par rejeu consiste à intercepter un message valide et à le renvoyer plus tard. La protection utilise :
- Un **nonce** unique par message
- Un **timestamp** pour limiter la durée de validité
- Un **cache** pour mémoriser les nonces déjà vus

### TLS 1.3

Le protocole TLS 1.3 assure :
- Le chiffrement des données
- L'authentification du serveur
- La protection contre les attaques MITM

---

## 👨‍💻 Auteurs

- **Mohamed Ghoul** - ESSTHS LI3
- **Projet pédagogique** - Sécurité des réseaux

---

## 📄 Licence

Ce projet est à usage **pédagogique uniquement**. Ne pas utiliser en production sans une révision complète de la sécurité.

---

## 🎓 Ressources Complémentaires

- [Documentation TLS 1.3](https://tools.ietf.org/html/rfc8446)
- [HMAC RFC 2104](https://tools.ietf.org/html/rfc2104)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Java Cryptography Architecture](https://docs.oracle.com/en/java/javase/22/security/)

---

## 🆘 Support

Pour toute question ou problème :
1. Consultez la section **Dépannage**
2. Vérifiez les logs du serveur
3. Testez avec `AttackTester.java` pour isoler le problème
