# ARP-(hackers_tchad)

<img width="533" height="375" alt="images" src="https://github.com/user-attachments/assets/b54c6fb4-69a1-4e8a-80f5-1fb674842812" />


**ARP-(hackers_tchad)** est un scanner et éducateur de protocole ARP avancé, avec interface graphique moderne style terminal green/red. Il permet de découvrir les appareils d'un réseau local, d'afficher leur adresse MAC, de résoudre les vendeurs, d'apprendre le fonctionnement ARP et d'exporter des rapports.

---

##  Installation

```bash
pip install -r requirements_arp_hackers_tchad.txt
```

Sous Linux, exécutez avec `sudo` pour les scans ARP (Scapy nécessite les droits root pour envoyer des paquets de couche 2).

---

##  Utilisation graphique

```bash
python arp_hackers_tchad.py
```

L'interface propose :
- un onglet **Scan ARP** pour scanner un réseau CIDR
- un onglet **Table ARP** pour voir le cache système
- un onglet **Apprendre ARP** avec explications et animation 3D simplifiée
- un onglet **Logs** pour suivre les opérations

---

## ⌨️ Utilisation en ligne de commande

```bash
sudo python arp_hackers_tchad.py --cidr 192.168.1.0/24 --interface eth0
```

Options disponibles :

| Option | Description |
|--------|-------------|
| `--cidr` | Réseau à scanner |
| `--interface` | Interface réseau |
| `--timeout` | Timeout ARP |
| `--retries` | Nombre de retries |
| `--no-vendor` | Désactiver la résolution de vendeur |
| `--no-hostname` | Désactiver la résolution de nom |
| `--export` | Chemin d'export JSON |

---

##  Ce que contient le guide

- Définition du protocole ARP
- Différence entre IP (couche 3) et MAC (couche 2)
- Types de paquets ARP : Request, Reply, RARP, InARP, Gratuitous, Proxy
- Fonctionnement étape par étape en broadcast/unitcast
- Commandes ARP sous Linux, macOS et Windows
- Sécurité : ARP spoofing, Dynamic ARP Inspection, entrées statiques
- Exemple de trame Scapy

---

##  Fichiers

- [`arp_hackers_tchad.py`](arp_hackers_tchad.py) — application principale
- [`requirements_arp_hackers_tchad.txt`](requirements_arp_hackers_tchad.txt) — dépendances
- [`README_ARP_HACKERS_TCHAD.md`](README_ARP_HACKERS_TCHAD.md) — documentation

---

---

## Licence

MIT — Auto education hackers tchad.
