<p align="center">
<h1 align="center">🛡️ Analyse IOC avec VirusTotal 🔍</h1>
<h3 align="center">Automatisation de l'analyse d'adresses IP et URLs suspectes - Script Python 2025</h3>
</p>

<p align="center">
<a href="https://github.com/0mar557/virustotal-ioc-checker">📂 Code Source</a>
</p>

---

## 🎯 Objectif du projet

Ce script permet d'automatiser l'analyse d'adresses IP et de domaines via l'API VirusTotal.  
Il vérifie si l'élément est malicieux, résout automatiquement les domaines/IPS et exporte les résultats dans un fichier `.csv` pour une analyse rapide.

**Avantages clés :**
- Analyse en masse d'IOCs.
- Résolution DNS automatique.
- Résultat clair, structuré et exportable.

---

## 🚀 Fonctionnalités

- ✅ **Résolution automatique** des domaines/IP.
- ✅ **Analyse via l'API VirusTotal** : Statut (malicieux, sûr, etc.).
- ✅ **Export CSV** complet avec toutes les infos utiles.
- ✅ **Lecture d’un fichier texte contenant les IOCs**.
- ✅ **Script léger et portable** (Python).

---

## 🛠️ Architecture technique

| Composant           | Technologie                | Rôle                                      |
|---------------------|----------------------------|-------------------------------------------|
| 🐍 **Script Python** | Python + Requests + socket | Récupération, résolution, requêtes API    |
| 🌍 **API**          | VirusTotal v3              | Analyse de réputation IP/URL              |
| 📁 **Fichier CSV**   | CSV Python standard        | Archivage des résultats                   |
| 🔑 **Fichier .env**  | dotenv                     | Stockage de la clé API                    |

---

## 📦 Installation rapide

### 1. Cloner le dépôt
```bash

git clone https://github.com/0mar557/virustotal-ioc-checker.git
cd virustotal-ioc-checker
```
### 2. Installer les dépendances
```bash
pip install -r requirements.txt
```
### 3. Ajouter votre clé API VirusTotal

Créez un fichier .env avec :
```bash
VT_API_KEY=votre_cle_api_virustotal
```
### 4. Ajouter vos IOCs

Ajoutez les IPs ou URLs dans un fichier iocs.txt, une par ligne.

### 5. Lancer le script
```bash
python scan.py
```
📬 Contact

Pour toute question ou suggestion :
📧 omar.elnmrawy@hotmail.com
<h2 align="center"> ⭐ Laisse une étoile si ce projet t’a aidé ou t’a plu ! ⭐ </h2> <p align="center"> <em>Projet personnel réalisé pour l'entraînement à la CTI & Threat Intelligence.</em> </p> ```
