# integrity-check
A lightweight, local File and Directory Integrity Monitor (FIM) written in Python using SHA-256 to detect file tampering and unauthorized modifications.

# 🛡️ integrity-check

`integrity-check` is a lightweight, local **File and Directory Integrity Monitor (FIM)** written in Python. It establishes a secure baseline of your critical files using SHA-256 hashing, allowing you to easily detect unauthorized modifications, tampering, or deletions.

Perfect for monitoring log files, configuration directories, or critical system assets.

---

## 🚀 Features

* **Recursive Monitoring:** Initialize and check individual files or entire directory trees effortlessly.
* **Secure Hash Store:** Saves data locally at `~/.integrity_check/hashstore.json` with restrictive file permissions (`chmod 600`) to prevent unauthorized tampering of the baseline.
* **Visual Integrity Alerts:** Uses clear, color-coded terminal outputs to flag **[TAMPERED]**, **[MISSING]**, and **[NEW]** untracked files.
* **SIEM/Script Friendly:** Exits with unique non-zero status codes when integrity violations are found, making it easy to integrate into automated security alerts or cron jobs.

---

## 🛠️ Requirements

* Python 3.7+
* Linux, macOS, or Windows (WSL recommended for terminal coloring)

---

## 💻 Installation & Setup

Clone the repository and make the script executable:

```bash
git clone [https://github.com/Cyber-Dipesh/integrity-check.git](https://github.com/Cyber-Dipesh/integrity-check.git)
cd integrity-check
chmod +x integrity-check
