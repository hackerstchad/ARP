#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARP-(hackers_tchad)
===================
Scanner ARP avancé, éducatif et graphique.
Thème : Terminal Green / Alert Red.
Auteur  : hackers_tchad (Projet éducatif)
Version : 1.0.0

Usage éthique uniquement : audit de réseaux dont vous êtes propriétaire
ou pour lesquels vous disposez d'une autorisation écrite explicite.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import platform
import re
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk
from typing import Any, Dict, List, Optional, Tuple

import colorama
import customtkinter as ctk
import psutil
import yaml
from colorama import Back, Fore, Style
from mac_vendor_lookup import MacLookup
from PIL import Image, ImageDraw, ImageTk
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from scapy.all import ARP, Ether, conf, get_if_addr, get_if_hwaddr, srp

# ---------------------------------------------------------------------------
# Constantes & style
# ---------------------------------------------------------------------------
APP_NAME = "ARP-(hackers_tchad)"
APP_VERSION = "1.0.0"
APP_AUTHOR = "hackers_tchad"
APP_DESC = "Scanner ARP avancé et éducatif pour réseaux locaux"

THEME_BG = "#0a0a0a"
THEME_FG = "#00ff41"
THEME_RED = "#ff3333"
THEME_DARK_GREEN = "#003300"
THEME_GRAY = "#1a1a1a"
THEME_ACCENT = "#00cc00"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

colorama.init(autoreset=True)

console = Console()

# ---------------------------------------------------------------------------
# Types de paquets ARP
# ---------------------------------------------------------------------------
class ARPOpcode(Enum):
    REQUEST = 1
    REPLY = 2
    RARP_REQUEST = 3
    RARP_REPLY = 4
    DRARP_REQUEST = 5
    DRARP_REPLY = 6
    DRARP_ERROR = 7
    INARP_REQUEST = 8
    INARP_REPLY = 9


ARP_TYPES: Dict[int, str] = {
    1: "ARP Request (Qui a cette IP ?)",
    2: "ARP Reply (Voici mon MAC)",
    3: "RARP Request",
    4: "RARP Reply",
    5: "DRARP Request",
    6: "DRARP Reply",
    7: "DRARP Error",
    8: "InARP Request",
    9: "InARP Reply",
}


# ---------------------------------------------------------------------------
# Modèle de données
# ---------------------------------------------------------------------------
@dataclass
class ARPEntry:
    ip: str
    mac: str
    vendor: str = "Inconnu"
    hostname: str = ""
    interface: str = ""
    first_seen: str = ""
    last_seen: str = ""
    status: str = "up"
    is_gateway: bool = False
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "hostname": self.hostname,
            "interface": self.interface,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "status": self.status,
            "is_gateway": self.is_gateway,
            "notes": self.notes,
        }


@dataclass
class AppConfig:
    interface: str = ""
    timeout: int = 2
    retries: int = 2
    resolve_vendor: bool = True
    resolve_hostname: bool = True
    theme: str = "green"
    auto_save: bool = True
    export_dir: str = "./arp_reports"


# ---------------------------------------------------------------------------
# Helpers réseau
# ---------------------------------------------------------------------------
class NetworkHelper:
    """Fonctions utilitaires réseau cross-platform."""

    @staticmethod
    def get_default_interface() -> str:
        try:
            gateways = psutil.net_if_addrs()
            for name, addrs in gateways.items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                        return name
        except Exception:
            pass
        return "eth0" if os.name != "nt" else "Ethernet"

    @staticmethod
    def get_interfaces() -> List[str]:
        try:
            return list(psutil.net_if_addrs().keys())
        except Exception:
            return []

    @staticmethod
    def get_interface_info(iface: str) -> Dict[str, str]:
        info: Dict[str, str] = {"ip": "", "mask": "", "mac": "", "broadcast": ""}
        try:
            addrs = psutil.net_if_addrs().get(iface, [])
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    info["ip"] = addr.address
                    info["mask"] = addr.netmask
                    info["broadcast"] = addr.broadcast or ""
                elif addr.family == psutil.AF_LINK:
                    info["mac"] = addr.address
        except Exception as e:
            info["error"] = str(e)
        return info

    @staticmethod
    def get_network_cidr(iface: str) -> str:
        info = NetworkHelper.get_interface_info(iface)
        ip = info.get("ip")
        mask = info.get("mask")
        if not ip or not mask:
            return "192.168.1.0/24"
        try:
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            return str(network)
        except Exception:
            return "192.168.1.0/24"

    @staticmethod
    def resolve_hostname(ip: str, timeout: float = 1.0) -> str:
        try:
            socket.setdefaulttimeout(timeout)
            host, _, _ = socket.gethostbyaddr(ip)
            return host
        except Exception:
            return ""

    @staticmethod
    def ping_host(ip: str, timeout: int = 1) -> bool:
        param = "-n" if os.name == "nt" else "-c"
        devnull = open(os.devnull, "w")
        try:
            result = subprocess.call(["ping", param, "1", "-W", str(timeout), ip], stdout=devnull, stderr=devnull)
            return result == 0
        except Exception:
            return False
        finally:
            devnull.close()


# ---------------------------------------------------------------------------
# Scanner ARP
# ---------------------------------------------------------------------------
class ARPScanner:
    """Moteur de scan ARP avec Scapy."""

    def __init__(self, config: AppConfig):
        self.config = config
        self.running = False
        self.vendor_lookup = None
        if config.resolve_vendor:
            try:
                self.vendor_lookup = MacLookup()
                self.vendor_lookup.load_vendors()
            except Exception:
                self.vendor_lookup = None

    def scan(self, target_cidr: str, progress_callback: Optional[callable] = None) -> List[ARPEntry]:
        self.running = True
        entries: List[ARPEntry] = []
        try:
            network = ipaddress.IPv4Network(target_cidr, strict=False)
            hosts = list(network.hosts())
            total = len(hosts)

            # Envoi ARP via Scapy
            answered, unanswered = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(target_cidr)),
                timeout=self.config.timeout,
                retry=self.config.retries,
                verbose=False,
                iface=self.config.interface if self.config.interface else None,
                inter=0.005,
            )

            gateway_ip = NetworkHelper.get_interface_info(self.config.interface).get("ip", "")

            for i, (sent, received) in enumerate(answered):
                if not self.running:
                    break
                ip = received.psrc
                mac = received.hwsrc
                vendor = self._lookup_vendor(mac)
                hostname = NetworkHelper.resolve_hostname(ip) if self.config.resolve_hostname else ""
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                is_gw = (ip == gateway_ip)
                entry = ARPEntry(
                    ip=ip,
                    mac=mac,
                    vendor=vendor,
                    hostname=hostname,
                    interface=self.config.interface,
                    first_seen=now,
                    last_seen=now,
                    status="up",
                    is_gateway=is_gw,
                )
                entries.append(entry)
                if progress_callback:
                    progress_callback(i + 1, total, entry)

        except Exception as e:
            console.print(f"[bold red]Erreur scan ARP : {e}[/bold red]")
        self.running = False
        return entries

    def _lookup_vendor(self, mac: str) -> str:
        if not self.vendor_lookup:
            return "Inconnu"
        try:
            return self.vendor_lookup.lookup(mac)
        except Exception:
            return "Inconnu"

    def stop(self) -> None:
        self.running = False


# ---------------------------------------------------------------------------
# ARP Cache / Table ARP
# ---------------------------------------------------------------------------
class ARPCacheManager:
    """Lecture et gestion de la table ARP système."""

    @staticmethod
    def read_cache() -> List[Dict[str, str]]:
        results: List[Dict[str, str]] = []
        system = platform.system().lower()
        try:
            if system == "linux" or system == "darwin":
                output = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
                for line in output.splitlines():
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[1].strip("()") if "(" in parts[1] else parts[1]
                        mac = parts[3]
                        if re.match(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac):
                            results.append({"ip": ip, "mac": mac, "interface": parts[-1] if len(parts) > 4 else ""})
            elif system == "windows":
                output = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
                iface = ""
                for line in output.splitlines():
                    if "Interface:" in line:
                        iface = line.split("Interface:")[1].split("---")[0].strip()
                    parts = line.split()
                    if len(parts) >= 2 and re.match(r"([0-9]{1,3}\.){3}[0-9]{1,3}", parts[0]):
                        mac = parts[1]
                        if re.match(r"([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}", mac):
                            results.append({"ip": parts[0], "mac": mac.replace("-", ":"), "interface": iface, "type": parts[2] if len(parts) > 2 else ""})
        except Exception as e:
            console.print(f"[yellow]Impossible de lire le cache ARP : {e}[/yellow]")
        return results

    @staticmethod
    def flush_cache() -> bool:
        system = platform.system().lower()
        try:
            if system == "linux":
                subprocess.check_call(["ip", "neigh", "flush", "all"])
            elif system == "darwin":
                subprocess.check_call(["sudo", "arp", "-a", "-d"])
            elif system == "windows":
                subprocess.check_call(["arp", "-d"])
            return True
        except Exception as e:
            console.print(f"[red]Impossible de vider le cache ARP : {e}[/red]")
            return False


# ---------------------------------------------------------------------------
# Export / rapport
# ---------------------------------------------------------------------------
class ReportExporter:
    """Export des résultats ARP."""

    @staticmethod
    def to_json(entries: List[ARPEntry], path: str) -> None:
        import json
        data = [e.to_dict() for e in entries]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    @staticmethod
    def to_csv(entries: List[ARPEntry], path: str) -> None:
        import csv
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["ip", "mac", "vendor", "hostname", "interface", "first_seen", "last_seen", "status", "is_gateway", "notes"])
            writer.writeheader()
            for e in entries:
                writer.writerow(e.to_dict())

    @staticmethod
    def to_txt(entries: List[ARPEntry], path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"Rapport ARP - {datetime.now()}\n")
            f.write("=" * 60 + "\n")
            for e in entries:
                f.write(f"{e.ip:16} {e.mac:18} {e.vendor:24} {e.hostname}\n")


# ---------------------------------------------------------------------------
# Visualisation 3D simplifiée (canvas tkinter)
# ---------------------------------------------------------------------------
class ARP3DVisualizer:
    """Visualisation conceptuelle du fonctionnement ARP en 3D simplifiée."""

    def __init__(self, parent: ctk.CTkFrame):
        self.parent = parent
        self.canvas = tk.Canvas(parent, bg=THEME_BG, highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.width = 800
        self.height = 400
        self.angle = 0
        self.devices: List[Dict[str, Any]] = []
        self._draw_static()

    def _draw_static(self):
        self.canvas.delete("all")
        cx, cy = self.width // 2, self.height // 2
        # Routeur central
        self.canvas.create_rectangle(cx - 40, cy - 40, cx + 40, cy + 40, fill=THEME_RED, outline=THEME_FG, width=2, tags="router")
        self.canvas.create_text(cx, cy, text="GATEWAY\nARP", fill="white", font=("Consolas", 10, "bold"), justify="center")

        # Périphériques autour
        positions = [(150, 100), (650, 100), (150, 300), (650, 300), (cx, 80)]
        labels = ["PC-A\n192.168.1.10", "PC-B\n192.168.1.20", "PC-C\n192.168.1.30", "PC-D\n192.168.1.40", "ATTACKER"]
        for (x, y), label in zip(positions, labels):
            color = THEME_RED if "ATTACKER" in label else THEME_FG
            self.canvas.create_oval(x - 30, y - 30, x + 30, y + 30, fill=color, outline="white", width=2, tags=f"device_{x}_{y}")
            self.canvas.create_text(x, y + 45, text=label, fill=THEME_FG, font=("Consolas", 9))
            # Lien vers le routeur
            self.canvas.create_line(cx, cy, x, y, fill="#004400", width=1, tags="link")

        # Légende
        self.canvas.create_text(20, 20, anchor="w", text="[REQ] Qui a 192.168.1.20 ? -> Broadcast ff:ff:ff:ff:ff:ff", fill=THEME_FG, font=("Consolas", 10))
        self.canvas.create_text(20, 40, anchor="w", text="[REP] 192.168.1.20 est aa:bb:cc:dd:ee:ff -> Unicast", fill=THEME_ACCENT, font=("Consolas", 10))

    def animate_packet(self):
        cx, cy = self.width // 2, self.height // 2
        targets = [(150, 100), (650, 100), (150, 300), (650, 300)]
        for tx, ty in targets:
            packet = self.canvas.create_oval(cx - 5, cy - 5, cx + 5, cy + 5, fill="yellow", outline="white", tags="packet")
            steps = 30
            for i in range(steps + 1):
                x = cx + (tx - cx) * (i / steps)
                y = cy + (ty - cy) * (i / steps)
                self.canvas.coords(packet, x - 5, y - 5, x + 5, y + 5)
                self.parent.update()
                time.sleep(0.02)
            self.canvas.delete(packet)


# ---------------------------------------------------------------------------
# Interface graphique principale
# ---------------------------------------------------------------------------
class ARPApp(ctk.CTk):
    """Application ARP-(hackers_tchad) avec interface moderne."""

    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1200x800")
        self.configure(fg_color=THEME_BG)
        self.resizable(True, True)

        self.config = AppConfig()
        self.config.interface = NetworkHelper.get_default_interface()
        self.scanner = ARPScanner(self.config)
        self.entries: List[ARPEntry] = []
        self.scan_thread: Optional[threading.Thread] = None

        self._build_ui()
        self._load_settings()

    def _build_ui(self):
        # === Header ===
        header = ctk.CTkFrame(self, fg_color=THEME_GRAY, corner_radius=0)
        header.pack(fill="x", pady=0)

        title = ctk.CTkLabel(header, text=f"{APP_NAME}", text_color=THEME_FG, font=("Consolas", 28, "bold"))
        title.pack(side="left", padx=20, pady=10)

        subtitle = ctk.CTkLabel(header, text=f"v{APP_VERSION} | {APP_AUTHOR} | {APP_DESC}", text_color="gray60", font=("Consolas", 12))
        subtitle.pack(side="left", padx=10, pady=10)

        # === Onglets ===
        self.tabview = ctk.CTkTabview(self, fg_color=THEME_BG, segmented_button_fg_color=THEME_GRAY, segmented_button_selected_color=THEME_FG, segmented_button_selected_hover_color=THEME_ACCENT, text_color=THEME_FG)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_scan = self.tabview.add("Scan ARP")
        self.tab_cache = self.tabview.add("Table ARP")
        self.tab_learn = self.tabview.add("Apprendre ARP")
        self.tab_log = self.tabview.add("Logs")

        self._build_scan_tab()
        self._build_cache_tab()
        self._build_learn_tab()
        self._build_log_tab()

        # === Barre d'état ===
        self.status = ctk.CTkLabel(self, text="Prêt", text_color=THEME_FG, font=("Consolas", 11))
        self.status.pack(fill="x", side="bottom", padx=10, pady=5)

    def _build_scan_tab(self):
        frame = ctk.CTkFrame(self.tab_scan, fg_color=THEME_GRAY)
        frame.pack(fill="x", padx=10, pady=10)

        # Interface
        ctk.CTkLabel(frame, text="Interface :", text_color=THEME_FG, font=("Consolas", 12)).grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.iface_combo = ctk.CTkComboBox(frame, values=NetworkHelper.get_interfaces(), width=200, fg_color=THEME_BG, border_color=THEME_FG, text_color=THEME_FG)
        self.iface_combo.set(self.config.interface)
        self.iface_combo.grid(row=0, column=1, padx=10, pady=10, sticky="w")

        # CIDR
        ctk.CTkLabel(frame, text="Réseau CIDR :", text_color=THEME_FG, font=("Consolas", 12)).grid(row=0, column=2, padx=10, pady=10, sticky="w")
        self.cidr_entry = ctk.CTkEntry(frame, width=180, fg_color=THEME_BG, border_color=THEME_FG, text_color=THEME_FG)
        self.cidr_entry.insert(0, NetworkHelper.get_network_cidr(self.config.interface))
        self.cidr_entry.grid(row=0, column=3, padx=10, pady=10, sticky="w")

        # Timeout / Retries
        ctk.CTkLabel(frame, text="Timeout :", text_color=THEME_FG, font=("Consolas", 12)).grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.timeout_entry = ctk.CTkEntry(frame, width=80, fg_color=THEME_BG, border_color=THEME_FG, text_color=THEME_FG)
        self.timeout_entry.insert(0, str(self.config.timeout))
        self.timeout_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")

        ctk.CTkLabel(frame, text="Retries :", text_color=THEME_FG, font=("Consolas", 12)).grid(row=1, column=2, padx=10, pady=10, sticky="w")
        self.retries_entry = ctk.CTkEntry(frame, width=80, fg_color=THEME_BG, border_color=THEME_FG, text_color=THEME_FG)
        self.retries_entry.insert(0, str(self.config.retries))
        self.retries_entry.grid(row=1, column=3, padx=10, pady=10, sticky="w")

        # Boutons
        btn_frame = ctk.CTkFrame(self.tab_scan, fg_color=THEME_BG)
        btn_frame.pack(fill="x", padx=10, pady=5)

        self.btn_scan = ctk.CTkButton(btn_frame, text="▶ LANCER LE SCAN ARP", fg_color=THEME_FG, text_color="black", hover_color=THEME_ACCENT, font=("Consolas", 14, "bold"), command=self._start_scan)
        self.btn_scan.pack(side="left", padx=5)

        self.btn_stop = ctk.CTkButton(btn_frame, text="■ STOPPER", fg_color=THEME_RED, text_color="white", hover_color="#cc0000", font=("Consolas", 14, "bold"), command=self._stop_scan, state="disabled")
        self.btn_stop.pack(side="left", padx=5)

        ctk.CTkButton(btn_frame, text="📁 Exporter JSON", fg_color=THEME_GRAY, text_color=THEME_FG, command=self._export_json).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="📄 Exporter CSV", fg_color=THEME_GRAY, text_color=THEME_FG, command=self._export_csv).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="🗑 Vider cache ARP", fg_color=THEME_RED, text_color="white", command=self._flush_cache).pack(side="left", padx=5)

        # Progress bar
        self.progress = ctk.CTkProgressBar(self.tab_scan, progress_color=THEME_FG, fg_color=THEME_DARK_GREEN, height=20)
        self.progress.set(0)
        self.progress.pack(fill="x", padx=10, pady=10)

        self.progress_label = ctk.CTkLabel(self.tab_scan, text="En attente...", text_color=THEME_FG, font=("Consolas", 11))
        self.progress_label.pack(padx=10, pady=0)

        # Tableau de résultats
        table_frame = ctk.CTkFrame(self.tab_scan, fg_color=THEME_BG)
        table_frame.pack(fill="both", expand=True, padx=10, pady=10)

        cols = ("IP", "MAC", "Vendor", "Hostname", "Interface", "Gateway", "Status")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=15)
        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=140, anchor="center")
        self.tree.pack(fill="both", expand=True, side="left")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background=THEME_BG, fieldbackground=THEME_BG, foreground=THEME_FG, rowheight=25, font=("Consolas", 10))
        style.configure("Treeview.Heading", background=THEME_GRAY, foreground=THEME_FG, font=("Consolas", 11, "bold"))
        style.map("Treeview", background=[("selected", THEME_DARK_GREEN)])

        scrollbar = ctk.CTkScrollbar(table_frame, command=self.tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)

    def _build_cache_tab(self):
        frame = ctk.CTkFrame(self.tab_cache, fg_color=THEME_BG)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkButton(frame, text="🔄 Actualiser la table ARP système", fg_color=THEME_FG, text_color="black", command=self._refresh_cache).pack(pady=10)

        self.cache_text = ctk.CTkTextbox(frame, fg_color=THEME_GRAY, text_color=THEME_FG, font=("Consolas", 11), wrap="none")
        self.cache_text.pack(fill="both", expand=True, padx=10, pady=10)

    def _build_learn_tab(self):
        frame = ctk.CTkFrame(self.tab_learn, fg_color=THEME_BG)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        text = """
=== PROTOCOLE ARP (Address Resolution Protocol) ===

But : traduire une adresse IP (couche 3) en adresse MAC (couche 2).

Fonctionnement en 4 étapes :
1. La machine A veut envoyer un paquet à 192.168.1.20.
2. Elle consulte sa table ARP ; si l'entrée n'existe pas, elle envoie
   une requête ARP en broadcast (destinataire ff:ff:ff:ff:ff:ff).
3. Toutes les machines du réseau reçoivent la requête.
   Seule la machine possédant l'IP 192.168.1.20 répond.
4. La réponse ARP est envoyée en unicast à A avec le MAC correspondant.

Types de paquets ARP :
- ARP Request  (opcode 1) : demande de résolution IP -> MAC
- ARP Reply    (opcode 2) : réponse contenant le MAC
- RARP         (opcodes 3-4) : résolution inverse MAC -> IP
- InARP        (opcodes 8-9) : Inverse ARP (Frame Relay)
- Gratuitous ARP            : annonce sans sollicitation
- Proxy ARP                 : réponse au nom d'une autre machine
- RARP/DRARP                : anciens protocoles BOOTP/DHCP

Commandes utiles :
  Linux/macOS :
    arp -a                     # afficher le cache ARP
    ip neigh                   # voisinage IPv4/IPv6
    sudo ip neigh flush all    # vider le cache
    sudo arp -d <ip>           # supprimer une entrée

  Windows :
    arp -a                     # afficher le cache ARP
    arp -d *                   # vider le cache
    arp -s <ip> <mac>          # ajouter une entrée statique

Sécurité :
- ARP spoofing / poisoning : fausse réponse ARP pour intercepter du trafic.
- Dynamic ARP Inspection (DAI) : filtre les réponses ARP sur switchs manageables.
- Static ARP entries : empêchent la modification du cache.

Exemple de trame Scapy :
  Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.0/24")
        """
        self.learn_text = ctk.CTkTextbox(frame, fg_color=THEME_GRAY, text_color=THEME_FG, font=("Consolas", 11), wrap="word")
        self.learn_text.insert("0.0", text)
        self.learn_text.configure(state="disabled")
        self.learn_text.pack(fill="both", expand=True, padx=10, pady=10)

        # Visualisation 3D simplifiée
        self.visualizer = ARP3DVisualizer(frame)
        self.visualizer.canvas.configure(width=800, height=250)
        self.visualizer.canvas.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkButton(frame, text="▶ Animer un paquet ARP", fg_color=THEME_RED, text_color="white", command=self.visualizer.animate_packet).pack(pady=10)

    def _build_log_tab(self):
        frame = ctk.CTkFrame(self.tab_log, fg_color=THEME_BG)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.log_text = ctk.CTkTextbox(frame, fg_color=THEME_GRAY, text_color=THEME_FG, font=("Consolas", 10), wrap="none")
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)
        self._log("Application démarrée.")

    # -----------------------------------------------------------------------
    # Actions
    # -----------------------------------------------------------------------
    def _start_scan(self):
        self.config.interface = self.iface_combo.get()
        self.config.timeout = int(self.timeout_entry.get() or 2)
        self.config.retries = int(self.retries_entry.get() or 2)
        cidr = self.cidr_entry.get().strip()

        if not cidr:
            messagebox.showerror("Erreur", "Veuillez saisir un réseau CIDR.")
            return

        self.entries.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.btn_scan.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.progress.set(0)
        self._log(f"Scan ARP lancé sur {cidr} via {self.config.interface}")

        def progress(current, total, entry):
            self.after(0, lambda: self._on_progress(current, total, entry))

        def run_scan():
            self.scanner = ARPScanner(self.config)
            results = self.scanner.scan(cidr, progress_callback=progress)
            self.after(0, lambda: self._scan_finished(results))

        self.scan_thread = threading.Thread(target=run_scan, daemon=True)
        self.scan_thread.start()

    def _on_progress(self, current: int, total: int, entry: ARPEntry):
        self.entries.append(entry)
        gateway = "OUI" if entry.is_gateway else "NON"
        self.tree.insert("", "end", values=(entry.ip, entry.mac, entry.vendor, entry.hostname, entry.interface, gateway, entry.status))
        pct = current / max(1, total)
        self.progress.set(pct)
        self.progress_label.configure(text=f"Découverts : {current} hôtes")
        self.status.configure(text=f"Scan en cours... {current}/{total}")
        self._log(f"[{entry.ip}] {entry.mac} ({entry.vendor})")

    def _scan_finished(self, results: List[ARPEntry]):
        self.btn_scan.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.progress.set(1.0)
        self.status.configure(text=f"Scan terminé : {len(results)} hôte(s) découvert(s)")
        self._log(f"Scan terminé : {len(results)} hôte(s) découvert(s)")

    def _stop_scan(self):
        self.scanner.stop()
        self.status.configure(text="Scan arrêté par l'utilisateur")
        self._log("Scan arrêté par l'utilisateur")
        self.btn_scan.configure(state="normal")
        self.btn_stop.configure(state="disabled")

    def _refresh_cache(self):
        entries = ARPCacheManager.read_cache()
        self.cache_text.delete("0.0", "end")
        if not entries:
            self.cache_text.insert("0.0", "Aucune entrée dans le cache ARP ou accès refusé.")
            return
        self.cache_text.insert("0.0", f"{'IP':<16} {'MAC':<20} {'Interface/Type'}\n")
        self.cache_text.insert("end", "=" * 60 + "\n")
        for e in entries:
            iface = e.get("interface", "")
            typ = e.get("type", "")
            self.cache_text.insert("end", f"{e['ip']:<16} {e['mac']:<20} {iface} {typ}\n")
        self._log("Table ARP système actualisée")

    def _flush_cache(self):
        if messagebox.askyesno("Confirmation", "Vider le cache ARP système ?"):
            ok = ARPCacheManager.flush_cache()
            if ok:
                self._log("Cache ARP vidé")
                self._refresh_cache()
            else:
                self._log("Échec du vidage du cache ARP (droits administrateur requis)")

    def _export_json(self):
        if not self.entries:
            messagebox.showwarning("Export", "Aucun résultat à exporter.")
            return
        os.makedirs(self.config.export_dir, exist_ok=True)
        path = os.path.join(self.config.export_dir, f"arp_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        ReportExporter.to_json(self.entries, path)
        self._log(f"Export JSON : {path}")
        messagebox.showinfo("Export", f"Rapport sauvegardé :\n{path}")

    def _export_csv(self):
        if not self.entries:
            messagebox.showwarning("Export", "Aucun résultat à exporter.")
            return
        os.makedirs(self.config.export_dir, exist_ok=True)
        path = os.path.join(self.config.export_dir, f"arp_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        ReportExporter.to_csv(self.entries, path)
        self._log(f"Export CSV : {path}")
        messagebox.showinfo("Export", f"Rapport sauvegardé :\n{path}")

    def _log(self, message: str):
        now = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{now}] {message}\n")
        self.log_text.see("end")

    def _load_settings(self):
        path = Path("arp_settings.yaml")
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data:
                        self.config.timeout = data.get("timeout", 2)
                        self.config.retries = data.get("retries", 2)
                        self.config.resolve_vendor = data.get("resolve_vendor", True)
                        self.config.resolve_hostname = data.get("resolve_hostname", True)
            except Exception as e:
                self._log(f"Impossible de charger les paramètres : {e}")


# ---------------------------------------------------------------------------
# Mode CLI
# ---------------------------------------------------------------------------
def run_cli():
    parser = argparse.ArgumentParser(prog=APP_NAME, description=APP_DESC)
    parser.add_argument("--cidr", "-c", help="Réseau CIDR à scanner", required=True)
    parser.add_argument("--interface", "-i", help="Interface réseau", default=NetworkHelper.get_default_interface())
    parser.add_argument("--timeout", "-t", type=int, default=2, help="Timeout ARP")
    parser.add_argument("--retries", "-r", type=int, default=2, help="Nombre de retries")
    parser.add_argument("--no-vendor", action="store_true", help="Ne pas résoudre les vendeurs MAC")
    parser.add_argument("--no-hostname", action="store_true", help="Ne pas résoudre les noms d'hôte")
    parser.add_argument("--export", "-o", help="Exporter le résultat en JSON")
    args = parser.parse_args()

    cfg = AppConfig(
        interface=args.interface,
        timeout=args.timeout,
        retries=args.retries,
        resolve_vendor=not args.no_vendor,
        resolve_hostname=not args.no_hostname,
    )

    console.print(Panel.fit(f"[bold green]{APP_NAME}[/bold green] [yellow]v{APP_VERSION}[/yellow]\n[dim]{APP_DESC}[/dim]", border_style="green"))
    console.print(f"[green]Réseau :[/green] {args.cidr}")
    console.print(f"[green]Interface :[/green] {args.interface}\n")

    scanner = ARPScanner(cfg)

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), console=console) as progress:
        task = progress.add_task("Scan ARP en cours...", total=None)

        def cb(current, total, entry):
            progress.update(task, description=f"[green]{entry.ip}[/green] {entry.mac} ({entry.vendor})")

        results = scanner.scan(args.cidr, progress_callback=cb)
        progress.update(task, completed=True, description="Terminé")

    table = Table(title="Résultats ARP", header_style="bold green")
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="magenta")
    table.add_column("Vendor", style="green")
    table.add_column("Hostname", style="white")
    table.add_column("Gateway", style="red")

    for e in results:
        gw = "OUI" if e.is_gateway else "NON"
        table.add_row(e.ip, e.mac, e.vendor, e.hostname, gw)

    console.print(table)
    console.print(f"\n[bold green]{len(results)} hôte(s) découvert(s)[/bold green]")

    if args.export:
        ReportExporter.to_json(results, args.export)
        console.print(f"[green]Export JSON :[/green] {args.export}")


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("--cidr", "-c"):
        run_cli()
    elif len(sys.argv) > 1 and sys.argv[1] in ("--help", "-h"):
        run_cli()
    else:
        app = ARPApp()
        app.mainloop()


if __name__ == "__main__":
    main()
