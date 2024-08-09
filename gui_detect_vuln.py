import os
import subprocess
import nmap
import hashlib
import socket
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
from concurrent.futures import ThreadPoolExecutor, as_completed

# Fichier pour l'adresse autorisée
ADDRESS_FILE = 'authorized_address.txt'

def validate_target(target):
    """Vérifie si la cible est une adresse IP ou un nom de domaine valide."""
    try:
        socket.gethostbyname(target)
        return True
    except socket.error:
        return False

def load_authorized_address():
    """Charge l'adresse autorisée à partir d'un fichier si elle existe."""
    if os.path.exists(ADDRESS_FILE):
        with open(ADDRESS_FILE, 'r') as file:
            return file.read().strip()
    return None

def save_authorized_address(address):
    """Enregistre la première adresse utilisée dans un fichier."""
    with open(ADDRESS_FILE, 'w') as file:
        file.write(address)

def run_nmap_script(target, options):
    """Exécute un scan Nmap avec les options spécifiées et retourne les résultats."""
    try:
        result = subprocess.run(['nmap'] + options + [target], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode('utf-8') + result.stderr.decode('utf-8')
    except Exception as e:
        return f"Erreur lors de l'exécution du script Nmap avec options {options}: {e}\n"

def detect_vulnerabilities(target):
    """Exécute différents scripts Nmap pour détecter les vulnérabilités sur la cible."""
    scripts = [
        ['-v', '-sV', '--script', 'vulners'],
        ['-v', '-Pn'],
        ['-v', '-g', '53'],
        ['-v', '-sS', '-O'],
        ['-v', '-p-', '--script', 'default'],
        ['-v', '-sU'],  # Scan UDP pour la couche transport
        ['-v', '-sT']   # Scan TCP pour la couche transport
    ]
    vuln_info = {}
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_script = {executor.submit(run_nmap_script, target, script): ' '.join(script) for script in scripts}
        for future in as_completed(future_to_script):
            script = future_to_script[future]
            try:
                data = future.result()
                vuln_info[script] = data
            except Exception as exc:
                vuln_info[script] = f"Erreur: {exc}"
    return vuln_info

def save_results_to_file(results, target):
    """Sauvegarde les résultats dans un fichier texte."""
    file_name = simpledialog.askstring("Nom du fichier", "Entrez le nom du fichier pour sauvegarder les résultats:")
    if file_name:
        with open(file_name, 'w') as file:
            file.write(f"Résultats de l'analyse de la cible : {target}\n\n")
            for script, result in results.items():
                file.write(f"Résultats du script {script} :\n")
                file.write(result + "\n\n")
        messagebox.showinfo("Fichier Sauvegardé", f"Les résultats ont été sauvegardés dans {file_name}")

def start_scan():
    """Démarre le processus de scan et de détection des vulnérabilités."""
    target = target_entry.get()
    if not validate_target(target):
        messagebox.showerror("Erreur", "Adresse IP ou nom de domaine non valide. Veuillez réessayer.")
        return

    authorized_address = load_authorized_address()
    if authorized_address is None:
        save_authorized_address(target)
    elif authorized_address != target:
        messagebox.showerror("Erreur", "Cible non autorisée. Le script va s'effacer.")
        os.remove(sys.argv[0])
        sys.exit(1)

    log_text.insert(tk.END, f"Début de l'analyse pour la cible : {target}\n")
    log_text.insert(tk.END, "Veuillez patienter pendant que nous analysons les ports et détectons les vulnérabilités...\n")

    vuln_info = detect_vulnerabilities(target)
    log_text.insert(tk.END, "Analyse terminée. Voici les résultats :\n")
    for script, result in vuln_info.items():
        log_text.insert(tk.END, f"\nRésultats du script {script} :\n")
        log_text.insert(tk.END, result + "\n")

    if messagebox.askyesno("Sauvegarder les résultats", "Voulez-vous sauvegarder les résultats dans un fichier texte?"):
        save_results_to_file(vuln_info, target)

# Création de l'interface graphique
root = tk.Tk()
root.title("EchoScan - Scanner de Vulnérabilités Réseau")
root.geometry("800x600")

frame = tk.Frame(root)
frame.pack(pady=10)

tk.Label(frame, text="Entrez l'adresse IP ou le nom de domaine de la cible :").pack(side=tk.LEFT, padx=5)
target_entry = tk.Entry(frame, width=30)
target_entry.pack(side=tk.LEFT, padx=5)

start_button = tk.Button(frame, text="Démarrer le Scan", command=start_scan)
start_button.pack(side=tk.LEFT, padx=5)

log_text = scrolledtext.ScrolledText(root, width=100, height=30, wrap=tk.WORD)
log_text.pack(pady=10)

root.mainloop()
