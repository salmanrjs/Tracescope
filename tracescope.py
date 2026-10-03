import os
import sys
import json
import hashlib
import socket
import colorama
from colorama import Fore, Style

# Attempt to import Pillow for image metadata analysis
try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# Enable command history (Up/Down arrows) and Tab auto-completion across the CLI
try:
    import readline
    import glob

    def global_completer(text, state):
        commands = ['init', 'check', 'update', 'scan', 'analyze', 'show options', 'options', 'back', 'exit', 'quit']
        expanded = os.path.expanduser(text)
        path_matches = glob.glob(expanded + '*')
        cmd_matches = [c for c in commands if c.startswith(text)]
        matches = path_matches + cmd_matches
        try:
            return matches[state]
        except IndexError:
            return None

    readline.set_completer_delims(' \t\n;')
    readline.parse_and_bind("tab: complete")
    readline.set_completer(global_completer)
except ImportError:
    pass

colorama.init(autoreset=True)

# ==============================================================================
# [UI & BANNER]
# ==============================================================================
def print_banner_once():
    os.system("clear" if os.name == "posix" else "cls")
    c_box = Fore.CYAN + Style.BRIGHT
    c_white = Fore.WHITE + Style.BRIGHT
    c_yellow = Fore.YELLOW + Style.BRIGHT
    
    # Inner box width
    w = 62
    
    line1 = "  ▀█▀ █▀█ █▀█ █▀▀ █▀▀ █▀▀ █▀▀ █▀█ █▀█ █▀▀"
    line2 = "   █  █▀▄ █▀█ █▄▄ ██▄ ▄██ █▄▄ █▄█ █▀▀ ██▄"
    info_plain = "  [>] TraceScope Framework v1.0 | Created By Salman Rajab"
    
    pad1 = " " * (w - len(line1))
    pad2 = " " * (w - len(line2))
    pad_info = " " * (w - len(info_plain))
    
    print(f"{c_box} ┌{'─' * w}┐")
    print(f"{c_box} │{c_white}{line1}{pad1}{c_box}│")
    print(f"{c_box} │{c_white}{line2}{pad2}{c_box}│")
    print(f"{c_box} │{' ' * w}│")
    print(f"{c_box} │{c_yellow}  [>]{c_white} TraceScope Framework v1.0 {c_box}| Created By Salman Rajab{pad_info}{c_box}│")
    print(f"{c_box} └{'─' * w}┘\n")

def show_main_menu():
    print(f"\n{Style.BRIGHT}--- [ Main Menu ] ---")
    print(f"  {Fore.GREEN}[1]{Fore.RESET} ❯ File Integrity Monitor (FIM)")
    print(f"  {Fore.GREEN}[2]{Fore.RESET} ❯ Local Listening Ports Auditor")
    print(f"  {Fore.GREEN}[3]{Fore.RESET} ❯ Extension Validator")
    print(f"  {Fore.GREEN}[4]{Fore.RESET} ❯ Image Metadata & GPS Forensics")
    print(f"  {Fore.RED}[0]{Fore.RESET} ❯ Exit Framework\n")


# ==============================================================================
# [MODULE 1: FIM - FILE & DIRECTORY INTEGRITY MONITOR]
# ==============================================================================
BASELINE_FILENAME = ".baseline"

def normalize_path(path):
    if not path:
        return ""
    expanded = os.path.expanduser(path.strip())
    return os.path.abspath(os.path.realpath(expanded))

def calculate_hash(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def scan_directory_state(target_dir):
    state = {"files": {}, "dirs": set()}
    for root, dirs, files in os.walk(target_dir):
        for d in dirs:
            dir_path = normalize_path(os.path.join(root, d))
            state["dirs"].add(dir_path)
            
        for f in files:
            if f == BASELINE_FILENAME:
                continue
            file_path = normalize_path(os.path.join(root, f))
            f_hash = calculate_hash(file_path)
            if f_hash:
                state["files"][file_path] = f_hash
    return state

def initialize_baseline(target_directory):
    target_directory = normalize_path(target_directory)
    if not os.path.isdir(target_directory):
        print(Fore.RED + f"[!] Error: Directory not found: {target_directory}")
        return

    baseline_path = os.path.join(target_directory, BASELINE_FILENAME)
    print(Fore.CYAN + f"[*] Scanning directory: {target_directory}...")

    current_state = scan_directory_state(target_directory)
    data_to_save = {
        "files": current_state["files"],
        "dirs": list(current_state["dirs"])
    }

    try:
        with open(baseline_path, 'w') as f:
            json.dump(data_to_save, f, indent=4)
        if os.name == 'nt':
            os.system(f'attrib +h "{baseline_path}"')
        print(Fore.GREEN + Style.BRIGHT + "[SUCCESS] Baseline created!")
        print(Fore.GREEN + f"[*] Registered: {len(data_to_save['files'])} files, {len(data_to_save['dirs'])} subdirectories.")
        print(Fore.GREEN + f"[*] Baseline saved to: {baseline_path}")
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"[FATAL ERROR] Could not save baseline: {e}")

def update_baseline(target_directory):
    target_directory = normalize_path(target_directory)
    if not os.path.isdir(target_directory):
        print(Fore.RED + f"[!] Error: Directory not found: {target_directory}")
        return

    baseline_path = os.path.join(target_directory, BASELINE_FILENAME)
    if not os.path.exists(baseline_path):
        print(Fore.YELLOW + f"[*] No previous baseline found. Creating new baseline...")
        initialize_baseline(target_directory)
        return

    print(Fore.CYAN + f"[*] Updating baseline for: {target_directory}...")
    current_state = scan_directory_state(target_directory)
    data_to_save = {
        "files": current_state["files"],
        "dirs": list(current_state["dirs"])
    }
    with open(baseline_path, 'w') as f:
        json.dump(data_to_save, f, indent=4)
    print(Fore.GREEN + Style.BRIGHT + "[SUCCESS] Baseline updated successfully with current state.")

def check_integrity(target_directory):
    target_directory = normalize_path(target_directory)
    if not os.path.isdir(target_directory):
        print(Fore.RED + f"[!] Error: Directory not found: {target_directory}")
        return

    baseline_path = os.path.join(target_directory, BASELINE_FILENAME)
    try:
        with open(baseline_path, 'r') as f:
            baseline_raw = json.load(f)
    except FileNotFoundError:
        print(Fore.RED + f"[!] Error: Baseline file '{BASELINE_FILENAME}' not found in {target_directory}")
        print(Fore.YELLOW + f"[*] Please run 'init <DIR>' first.")
        return
    except Exception as e:
        print(Fore.RED + f"[!] Error loading baseline file: {e}")
        return

    if "files" in baseline_raw and "dirs" in baseline_raw:
        baseline_files = {normalize_path(k): v for k, v in baseline_raw["files"].items()}
        baseline_dirs = set(normalize_path(d) for d in baseline_raw["dirs"])
    else:
        baseline_files = {normalize_path(k): v for k, v in baseline_raw.items()}
        baseline_dirs = set()

    print(Fore.CYAN + f"[*] Scanning current state in {target_directory}...")
    current_state = scan_directory_state(target_directory)
    
    current_files = current_state["files"]
    current_dirs = current_state["dirs"]

    deleted_files = set(baseline_files.keys()) - set(current_files.keys())
    new_files = set(current_files.keys()) - set(baseline_files.keys())
    common_files = set(baseline_files.keys()).intersection(set(current_files.keys()))
    modified_files = [f for f in common_files if baseline_files[f] != current_files[f]]

    new_dirs = current_dirs - baseline_dirs
    deleted_dirs = baseline_dirs - current_dirs

    print("\n" + Style.BRIGHT + "─── [ Integrity Check Report ] ───")
    has_changes = any([modified_files, new_files, deleted_files, new_dirs, deleted_dirs])
    if not has_changes:
        print(Fore.GREEN + Style.BRIGHT + "[+] SUCCESS: All files and directories are intact. No changes detected.")
        return

    if modified_files:
        print(Fore.RED + Style.BRIGHT + "\n[!] MODIFIED FILES (DANGER!):")
        for f in modified_files:
            print(f"  - {f}")
    if new_files:
        print(Fore.YELLOW + Style.BRIGHT + "\n[!] NEW FILES (SUSPICIOUS):")
        for f in new_files:
            print(f"  - {f}")
    if new_dirs:
        print(Fore.YELLOW + Style.BRIGHT + "\n[!] NEW DIRECTORIES (SUSPICIOUS):")
        for d in new_dirs:
            print(f"  - [DIR] {d}")
    if deleted_files:
        print(Fore.RED + Style.BRIGHT + "\n[!] DELETED FILES (NOTICE):")
        for f in deleted_files:
            print(f"  - {f}")
    if deleted_dirs:
        print(Fore.RED + Style.BRIGHT + "\n[!] DELETED DIRECTORIES (NOTICE):")
        for d in deleted_dirs:
            print(f"  - [DIR] {d}")

def run_fim_module():
    print(f"\n{Fore.GREEN}[*] Loaded Module: File Integrity Monitor (FIM){Fore.RESET}")
    print(f"Type {Fore.YELLOW}'show options'{Fore.RESET} for help, or {Fore.RED}'back'{Fore.RESET} to return.\n")
    
    while True:
        try:
            cmd_input = input(f"{Fore.CYAN}TraceScope {Fore.WHITE}({Fore.RED}fim{Fore.WHITE}) > {Fore.RESET}").strip()
            if not cmd_input:
                continue
            
            parts = cmd_input.split(maxsplit=1)
            action = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""

            if action in ["show", "options"] or "options" in cmd_input.lower():
                print(f"\n{Style.BRIGHT}Module Commands & Options:")
                print(f"  {Fore.GREEN}init <DIR>{Fore.RESET}          Generate a new baseline for a directory.")
                print(f"  {Fore.GREEN}check <DIR>{Fore.RESET}         Verify current files & folders against baseline.")
                print(f"  {Fore.GREEN}update <DIR>{Fore.RESET}        Update baseline to accept current state changes.")
                print(f"  {Fore.GREEN}back{Fore.RESET}                Return to the main menu.")
                print(f"\n{Style.BRIGHT}Examples:")
                print(f"  init ~/Desktop/salman")
                print(f"  check ~/Desktop/salman\n")

            elif action == "init":
                if not arg:
                    print(Fore.YELLOW + "[!] Missing argument. Usage: init <DIR>")
                else:
                    initialize_baseline(arg)

            elif action == "check":
                if not arg:
                    print(Fore.YELLOW + "[!] Missing argument. Usage: check <DIR>")
                else:
                    check_integrity(arg)

            elif action == "update":
                if not arg:
                    print(Fore.YELLOW + "[!] Missing argument. Usage: update <DIR>")
                else:
                    update_baseline(arg)

            elif action in ["back", "exit", "quit"]:
                break
            else:
                print(Fore.YELLOW + f"Unknown command: '{cmd_input}'. Type 'show options' for help.")
        except KeyboardInterrupt:
            print()
            break


# ==============================================================================
# [MODULE 2: LOCAL LISTENING PORTS AUDITOR]
# ==============================================================================
def decode_hex_ip(hex_str):
    if len(hex_str) == 8:
        octets = [str(int(hex_str[i:i+2], 16)) for i in (6, 4, 2, 0)]
        return ".".join(octets)
    return "IPv6/All"

def audit_listening_ports():
    print(Fore.CYAN + "\n[*] Auditing Local Listening Ports & Services...")
    proc_files = ['/proc/net/tcp', '/proc/net/tcp6']
    listening_records = []

    for pf in proc_files:
        if not os.path.exists(pf):
            continue
        try:
            with open(pf, 'r') as f:
                lines = f.readlines()[1:]
                for line in lines:
                    parts = line.strip().split()
                    if len(parts) >= 4 and parts[3] == '0A':  # 0A = TCP_LISTEN
                        local_addr = parts[1]
                        ip_hex, port_hex = local_addr.split(':')
                        port = int(port_hex, 16)
                        ip_addr = decode_hex_ip(ip_hex)
                        listening_records.append((ip_addr, port))
        except Exception:
            pass

    # Deduplicate port records
    unique_records = sorted(list(set(listening_records)), key=lambda x: x[1])

    if not unique_records:
        print(Fore.YELLOW + "[*] No active listening TCP ports detected via /proc.")
        return

    print("\n" + Style.BRIGHT + f"{'IP ADDRESS':<18} {'PORT':<10} {'SERVICE':<18} {'STATUS / RISK'}")
    print("─" * 65)

    known_risky_ports = [4444, 5555, 6667, 8888, 9001, 1337, 31337]

    for ip, port in unique_records:
        try:
            service = socket.getservbyport(port, 'tcp')
        except Exception:
            service = "Unknown"

        # Risk assessment
        if port in known_risky_ports or (port > 1024 and service == "Unknown" and ip in ["0.0.0.0", "IPv6/All"]):
            status_text = f"{Fore.RED}[!] SUSPICIOUS (Exposed Port)"
        elif ip == "127.0.0.1":
            status_text = f"{Fore.GREEN}[+] Localhost Only (Safe)"
        else:
            status_text = f"{Fore.CYAN}[*] Active Service"

        print(f"{ip:<18} {port:<10} {service:<18} {status_text}")
    print()

def run_ports_module():
    print(f"\n{Fore.GREEN}[*] Loaded Module: Local Listening Ports Auditor{Fore.RESET}")
    print(f"Type {Fore.YELLOW}'show options'{Fore.RESET} or {Fore.RED}'back'{Fore.RESET}.\n")
    while True:
        try:
            cmd = input(f"{Fore.CYAN}TraceScope {Fore.WHITE}({Fore.RED}ports_auditor{Fore.WHITE}) > {Fore.RESET}").strip()
            if not cmd:
                continue
            if "options" in cmd.lower():
                print(f"\n{Style.BRIGHT}Module Commands & Options:")
                print(f"  {Fore.GREEN}scan{Fore.RESET}                Audit all active listening ports & bindings on Linux.")
                print(f"  {Fore.GREEN}back{Fore.RESET}                Return to the main menu.\n")
            elif cmd.lower() == "scan":
                audit_listening_ports()
            elif cmd.lower() in ["back", "exit", "quit"]:
                break
            else:
                print(Fore.YELLOW + f"Unknown command: '{cmd}'. Type 'show options'.")
        except KeyboardInterrupt:
            print()
            break


# ==============================================================================
# [MODULE 3: EXTENSION VALIDATOR]
# ==============================================================================
def check_single_file_signature(full_path, target_extensions):
    _, ext = os.path.splitext(full_path.lower())
    if ext not in target_extensions:
        return False, None

    try:
        with open(full_path, "rb") as file_obj:
            header = file_obj.read(16)

        if not header:
            return False, None

        if header.startswith(b'MZ'):
            msg = (f"{Fore.RED}{Style.BRIGHT}[!] MISMATCH DETECTED:\n"
                   f"    File: {full_path}\n"
                   f"    Claimed Extension: {ext}\n"
                   f"    Actual Signature : Windows Executable (.exe)")
            return True, msg

        elif header.startswith(b'\x7fELF'):
            msg = (f"{Fore.RED}{Style.BRIGHT}[!] MISMATCH DETECTED (ELF Binary in Disguise):\n"
                   f"    File: {full_path}\n"
                   f"    Claimed Extension: {ext}\n"
                   f"    Actual Signature : Linux Executable (Magic: \\x7fELF)")
            return True, msg

        elif (ext in ['.png', '.jpg', '.jpeg', '.pdf']) and (header.startswith(b'#!') or header.startswith(b'<?php')):
            msg = (f"{Fore.YELLOW}{Style.BRIGHT}[!] SUSPICIOUS SCRIPT DISGUISE:\n"
                   f"    File: {full_path}\n"
                   f"    Claimed Extension: {ext}\n"
                   f"    Actual Signature : Executable Script (Shebang/PHP)")
            return True, msg

    except Exception:
        pass

    return False, None

def validate_file_extensions(target_path):
    target_path = normalize_path(target_path)
    if not os.path.exists(target_path):
        print(Fore.RED + f"[!] Path does not exist: {target_path}")
        return

    target_extensions = {
        '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.bmp',
        '.txt', '.csv', '.docx', '.xlsx', '.zip'
    }

    # 1. Target is a single file
    if os.path.isfile(target_path):
        print(Fore.CYAN + f"\n[*] Validating file: {target_path}...")
        is_mismatch, alert_msg = check_single_file_signature(target_path, target_extensions)
        if is_mismatch:
            print(f"\n{alert_msg}")
        else:
            print(Fore.GREEN + f"[+] Legitimate File: Header matches expected format for {os.path.basename(target_path)}.")
        return

    # 2. Target is an entire directory
    print(Fore.CYAN + f"\n[*] Validating file signatures & extensions in: {target_path}...")
    flagged_count = 0

    for root, dirs, files in os.walk(target_path):
        for f in files:
            full_path = os.path.join(root, f)
            is_mismatch, alert_msg = check_single_file_signature(full_path, target_extensions)
            if is_mismatch:
                flagged_count += 1
                print(f"\n{alert_msg}")

    if flagged_count == 0:
        print(Fore.GREEN + f"[+] All checked files match their claimed extensions in {target_path}.")
    else:
        print(Fore.RED + Style.BRIGHT + f"\n[!] Audit finished: Detected {flagged_count} file(s) with mismatched signatures!")

def run_hunter_module():
    print(f"\n{Fore.GREEN}[*] Loaded Module: Extension Validator{Fore.RESET}")
    print(f"Type {Fore.YELLOW}'show options'{Fore.RESET} or {Fore.RED}'back'{Fore.RESET}.\n")
    while True:
        try:
            cmd = input(f"{Fore.CYAN}TraceScope {Fore.WHITE}({Fore.RED}validator{Fore.WHITE}) > {Fore.RESET}").strip()
            if not cmd:
                continue
            parts = cmd.split(maxsplit=1)
            action = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""

            if "options" in cmd.lower():
                print(f"\n{Style.BRIGHT}Module Commands & Options:")
                print(f"  {Fore.GREEN}scan <FILE/DIR>{Fore.RESET}     Validate file header vs extension (single file or full directory).")
                print(f"  {Fore.GREEN}back{Fore.RESET}                Return to the main menu.\n")
                print(f"{Style.BRIGHT}Examples:")
                print(f"  scan ~/Desktop/example.pdf\n")
            elif action == "scan":
                if not arg:
                    print(Fore.YELLOW + "[!] Missing path. Usage: scan <FILE or DIR>")
                else:
                    validate_file_extensions(arg)
            elif action in ["back", "exit", "quit"]:
                break
            else:
                print(Fore.YELLOW + f"Unknown command: '{cmd}'. Type 'show options'.")
        except KeyboardInterrupt:
            print()
            break

# ==============================================================================
# [MODULE 4: IMAGE METADATA & FORENSICS]
# ==============================================================================
def convert_to_degrees(value):
    """Convert degrees, minutes, and seconds tuple to decimal coordinates."""
    try:
        d = float(value[0])
        m = float(value[1])
        s = float(value[2])
        return d + (m / 60.0) + (s / 3600.0)
    except Exception:
        return None

def analyze_image_metadata(img_path):
    if not HAS_PIL:
        print(Fore.RED + "[!] Pillow library not found. Please install it using:")
        print("    pip install pillow --break-system-packages")
        return

    try:
        image = Image.open(img_path)
        exif_raw = image._getexif()

        if not exif_raw:
            print(Fore.YELLOW + f"[-] No EXIF metadata discovered in: {os.path.basename(img_path)}")
            return

        exif_data = {}
        for tag_id, value in exif_raw.items():
            tag_name = TAGS.get(tag_id, tag_id)
            exif_data[tag_name] = value

        print("\n" + Style.BRIGHT + f"─── [ Forensic Metadata: {os.path.basename(img_path)} ] ───")
        
        # Extract camera and software information
        print(f"  {Fore.CYAN}[+] Camera Make   :{Fore.RESET} {exif_data.get('Make', 'N/A')}")
        print(f"  {Fore.CYAN}[+] Camera Model  :{Fore.RESET} {exif_data.get('Model', 'N/A')}")
        print(f"  {Fore.CYAN}[+] Date Taken    :{Fore.RESET} {exif_data.get('DateTimeOriginal', exif_data.get('DateTime', 'N/A'))}")
        print(f"  {Fore.CYAN}[+] Software Used :{Fore.RESET} {exif_data.get('Software', 'N/A')}")

        # Extract GPS metadata
        gps_info = exif_data.get("GPSInfo")
        if gps_info:
            gps_tags = {}
            for t in gps_info:
                sub_tag = GPSTAGS.get(t, t)
                gps_tags[sub_tag] = gps_info[t]

            lat_val = gps_tags.get("GPSLatitude")
            lat_ref = gps_tags.get("GPSLatitudeRef")
            lon_val = gps_tags.get("GPSLongitude")
            lon_ref = gps_tags.get("GPSLongitudeRef")

            if lat_val and lon_val and lat_ref and lon_ref:
                lat = convert_to_degrees(lat_val)
                lon = convert_to_degrees(lon_val)

                if lat_ref != "N":
                    lat = -lat
                if lon_ref != "E":
                    lon = -lon

                print(f"  {Fore.GREEN}[+] GPS Coordinates:{Fore.RESET} {lat:.6f}, {lon:.6f}")
                print(f"  {Fore.GREEN}[+] Google Maps Link:{Fore.RESET} {Fore.YELLOW}https://www.google.com/maps?q={lat:.6f},{lon:.6f}{Fore.RESET}")
            else:
                print(f"  {Fore.YELLOW}[-] Incomplete GPS coordinates tags.")
        else:
            print(f"  {Fore.YELLOW}[-] No GPS geolocation metadata embedded.")

    except Exception as e:
        print(Fore.RED + f"[!] Error parsing image: {e}")

def run_metadata_module():
    print(f"\n{Fore.GREEN}[*] Loaded Module: Image Metadata Forensics{Fore.RESET}")
    print(f"Type {Fore.YELLOW}'show options'{Fore.RESET} or {Fore.RED}'back'{Fore.RESET}.\n")
    while True:
        try:
            cmd = input(f"{Fore.CYAN}TraceScope {Fore.WHITE}({Fore.RED}metadata{Fore.WHITE}) > {Fore.RESET}").strip()
            if not cmd:
                continue
            parts = cmd.split(maxsplit=1)
            action = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""

            if "options" in cmd.lower():
                print(f"\n{Style.BRIGHT}Module Commands & Options:")
                print(f"  {Fore.GREEN}analyze <IMG_PATH>{Fore.RESET}  Extract EXIF, Camera, and GPS Google Maps link.")
                print(f"  {Fore.GREEN}back{Fore.RESET}                Return to the main menu.\n")
                print(f"{Style.BRIGHT}Example:")
                print(f"  analyze ~/Desktop/sample.jpg\n")
            elif action == "analyze":
                target_img = normalize_path(arg)
                if not arg or not os.path.isfile(target_img):
                    print(Fore.RED + f"[!] Please provide a valid image path: {arg}")
                else:
                    analyze_image_metadata(target_img)
            elif action in ["back", "exit", "quit"]:
                break
            else:
                print(Fore.YELLOW + f"Unknown command: '{cmd}'. Type 'show options'.")
        except KeyboardInterrupt:
            print()
            break


# ==============================================================================
# [MAIN ENGINE]
# ==============================================================================
def main():
    print_banner_once()
    while True:
        show_main_menu()
        try:
            choice = input(f"{Fore.CYAN}TraceScope ❯ {Fore.RESET}").strip()
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n[*] Exiting TraceScope. Stay safe!")
            sys.exit(0)

        if choice == "1":
            run_fim_module()
        elif choice == "2":
            run_ports_module()
        elif choice == "3":
            run_hunter_module()
        elif choice == "4":
            run_metadata_module()
        elif choice in ["0", "exit", "quit"]:
            print(Fore.YELLOW + "\n[*] Exiting TraceScope. Stay safe!")
            sys.exit(0)
        else:
            print(Fore.RED + "[!] Invalid option. Please select 1, 2, 3, 4, or 0.")

if __name__ == "__main__":
    main()
