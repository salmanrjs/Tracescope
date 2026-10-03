# TraceScope Framework v1.0

**A Modular Blue Team Digital Forensics & Incident Response (DFIR) Framework**  
Created by **Salman Rajab**

---

## Overview

TraceScope is a lightweight, interactive CLI framework designed for Blue Teams, Incident Responders, and Digital Forensic analysts. It streamlines artifact discovery, system state auditing, masqueraded executable detection, and image metadata extraction in Linux environments.

---

## Key Modules & Capabilities

### 1. File Integrity Monitor (FIM)
* Generates cryptographic baselines using SHA-256 hashing.
* Recursively tracks file modifications, unauthorized file creation, and deletions.
* Monitors subdirectory structures and handles hidden state baselines.

### 2. Local Listening Ports Auditor
* Inspects low-level Linux networking sockets directly via /proc/net/tcp and /proc/net/tcp6.
* Resolves hex-encoded IPs and ports to identify listening services without external network scanners.
* Highlights exposed listeners (0.0.0.0) and flags suspicious non-standard ports.

### 3. Extension Validator
* Detects file extension spoofing and disguised malware using Magic Bytes inspection.
* Identifies disguised Windows PE binaries (MZ) and Linux ELF executables (\x7fELF) masquerading as documents (.pdf, .docx, .xlsx) or images (.jpg, .png).
* Flags executable scripts (Shebang #!, <?php) posing as media assets.
* Supports recursive directory audits as well as single-file forensic inspection.

### 4. Image Metadata & GPS Forensics
* Extracts detailed EXIF metadata including camera manufacturer, device model, creation timestamp, and software versions.
* Decodes embedded GPS coordinates into decimal format.
* Generates direct Google Maps links for physical location attribution.

---

## Installation & Setup

### Prerequisites
* Linux environment (Tested on Kali Linux / Debian / Ubuntu)
* Python 3.8+

### 1. Clone the Repository
git clone https://github.com/salmanrjs/Tracescope.git
cd Tracescope

### 2. Install Dependencies
pip install -r requirements.txt

Note for Kali Linux users: If your environment uses PEP 668 externally managed packages, install dependencies with:
pip install -r requirements.txt --break-system-packages

---

## Usage

Launch the framework console:
python3 tracescope.py

### Command Examples

* File Integrity Monitor:
  TraceScope (fim) > init /path/to/target
  TraceScope (fim) > check /path/to/target
  TraceScope (fim) > update /path/to/target

* Local Ports Auditor:
  TraceScope (ports_auditor) > scan

* Extension Validator:
  TraceScope (validator) > scan ~/Desktop/invoice.pdf
  TraceScope (validator) > scan ~/Desktop/Downloads

* Image Forensics:
  TraceScope (metadata) > analyze ~/Desktop/evidence.jpg
