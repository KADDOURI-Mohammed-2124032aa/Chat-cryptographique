# 📜 Rapport sur le projet de chat sécurisé

## 🔒 Introduction
Ce projet vise à implémenter un **chat sécurisé** avec un chiffrement **de bout en bout (E2EE)**, garantissant que seuls les interlocuteurs peuvent lire les messages échangés. Nous utilisons **NaCl/libsodium**, une bibliothèque cryptographique reconnue pour sa sécurité et sa simplicité d'utilisation.

L'objectif principal est d'intégrer plusieurs mécanismes de sécurité :
- **Chiffrement asymétrique** pour sécuriser l'échange des messages.
- **Chiffrement symétrique avec des clés éphémères** pour améliorer la rapidité et la sécurité.
- **Signature numérique** pour garantir l'authenticité des messages.
- **Empreinte des clés publiques (hash SHA-256)** pour empêcher les attaques MITM.
- **Protection contre les modifications** grâce à l'authentification intégrée.

Ce document détaille en profondeur l’architecture cryptographique utilisée, les algorithmes employés et leur implémentation.

---

## 🔐 Chiffrement de bout en bout (E2EE)

### 📌 Pourquoi ?
Le chiffrement de bout en bout garantit que **seuls** l'expéditeur et le destinataire peuvent lire un message. Même si un attaquant intercepte les données, elles restent illisibles.

### 🔧 Implémentation
Nous utilisons **NaCl/libsodium**, une bibliothèque de cryptographie moderne qui offre :
- **Une API simple** pour éviter les erreurs classiques en cryptographie.
- **Une implémentation sécurisée** d'algorithmes reconnus.

```python
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import Base64Encoder
```
Chaque utilisateur possède une **paire de clés** :
- **Clé privée** (`PrivateKey`) : utilisée pour déchiffrer les messages.
- **Clé publique** (`PublicKey`) : utilisée pour chiffrer les messages destinés à l'utilisateur.

Le chiffrement s’effectue ainsi :
```python
box = Box(sender_private_key, recipient_public_key)
encrypted = box.encrypt(message.encode(), encoder=Base64Encoder)
```
Et le déchiffrement :
```python
decrypted = box.decrypt(encrypted_message.encode(), encoder=Base64Encoder).decode()
```
👉 **Seul le destinataire peut lire le message, même si un attaquant l’intercepte.**

---

## 🔑 Chiffrement asymétrique

### 📌 Pourquoi ?
Le chiffrement asymétrique permet de **sécuriser l’échange de messages** sans avoir besoin d’une clé partagée à l’avance.

### 🔧 Implémentation
Chaque utilisateur dispose d’une **paire de clés asymétriques** générées ainsi :
```python
private_key = PrivateKey.generate()
public_key = private_key.public_key
```
L’expéditeur chiffre le message avec la **clé publique** du destinataire, et le destinataire le déchiffre avec sa **clé privée**.

---

## 🔄 Chiffrement symétrique avec clés éphémères

### 📌 Pourquoi ?
Le chiffrement asymétrique est **plus lent** que le chiffrement symétrique. Pour optimiser la rapidité, on utilise **une clé éphémère** générée pour chaque message.

### 🔧 Implémentation
- L’expéditeur génère une **clé temporaire** à chaque message.
- Cette clé est utilisée pour **chiffrer** le message avec un algorithme symétrique rapide.
- La clé publique temporaire est envoyée avec le message pour permettre au destinataire de reconstruire la clé partagée.

```python
ephemeral_private = PrivateKey.generate()
ephemeral_public = ephemeral_private.public_key
box = Box(ephemeral_private, recipient_public_key)
encrypted = box.encrypt(message.encode(), encoder=Base64Encoder)
```
👉 **Même si une clé privée est compromise, les anciens messages restent protégés.**

---

## ✍️ Signature numérique (Authenticité)

### 📌 Pourquoi ?
Un attaquant pourrait intercepter un message et le **modifier** avant de le transmettre au destinataire. Pour éviter cela, nous signons chaque message avec une **clé privée de signature**.

### 🔧 Implémentation
Chaque utilisateur a :
- Une **clé de signature** (`SigningKey`).
- Une **clé de vérification** (`VerifyKey`).

```python
from nacl.signing import SigningKey, VerifyKey

signing_key = SigningKey.generate()
verify_key = signing_key.verify_key
```
Le message est signé ainsi :
```python
signed_message = signing_key.sign(message.encode(), encoder=Base64Encoder)
```
Et vérifié à la réception :
```python
verified_message = verify_key.verify(base64.b64decode(signed_message.encode())).decode()
```
👉 **Un message modifié sera détecté et rejeté.**

---

## 🔍 Empreinte des clés publiques (SHA-256)

### 📌 Pourquoi ?
Une attaque Man-in-the-Middle (MITM) pourrait substituer une fausse clé publique. Pour éviter cela, on affiche **une empreinte unique** de la clé publique avec SHA-256.

### 🔧 Implémentation
```python
import hashlib

def fingerprint(public_key: PublicKey) -> str:
    return hashlib.sha256(public_key.encode()).hexdigest()
```
Les utilisateurs peuvent **vérifier** les empreintes avant de communiquer.

---

## 🛠️ Utilisation et tests

### 🚀 Démarrer le serveur
```bash
python app.py
```
Le chat est accessible via `http://127.0.0.1:5000/`.

### 🔧 Tester le chat
1. **Choisir un utilisateur** (`Alice` ou `Bob`).
2. **Envoyer un message**.
3. **Changer d’utilisateur** pour voir l’historique mis à jour.

---

## 🎨 Mise en place de l’interface
L'interface est une simple application **Flask + WebSockets (Socket.IO)** permettant :
- De **choisir un utilisateur**.
- D’**envoyer un message**.
- D’**afficher l’historique** pour chaque utilisateur.

Le chat fonctionne **sans avoir à ouvrir plusieurs onglets** et met à jour les messages **en temps réel**.

---

## 🎯 Conclusion
✅ **Chiffrement de bout en bout (E2EE)**.
✅ **Sécurisation par chiffrement asymétrique et symétrique hybride**.
✅ **Protection contre les modifications (signature numérique)**.
✅ **Empreinte cryptographique pour éviter MITM**.
✅ **Historique persistant et chat en temps réel.**

**Améliorations possibles :**
- Ajout du **Double Ratchet Algorithm** pour renouveler les clés à chaque message.
- Chiffrement des **métadonnées** pour masquer qui parle à qui.

🔥 **Projet sécurisé, rapide et robuste !** 😎

