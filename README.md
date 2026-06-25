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

📖 Usage Guide
1. Initialize a Baseline
Compute and store initial SHA-256 hashes for a file or directory.

Bash
./integrity-check init /path/to/monitor
Use --force if you want to overwrite already tracked files.

2. Verify System Integrity
Check the current state of files against your stored baseline.

Bash
./integrity-check check /path/to/monitor
3. Update Stored Baselines
If you intentionally modified a file, update its baseline hash so it doesn't flag an alert.

Bash
./integrity-check update /path/to/monitor
4. List Tracked Files
View all currently tracked assets, their tracking initialization date, and last check times.

Bash
./integrity-check list
5. Reset the Database
Wipe the entire local hash database to start fresh (requires typing YES to confirm).

Bash
./integrity-check reset

⚙️ How It Works
init: Reads files in 64 KB chunks to efficiently calculate SHA-256 hashes regardless of file size.

Storage: Writes entries to JSON format, applying strict owner read/write permissions so other local users can't edit your verification baselines.

Alerting: During a check, it cross-references current file system states with the JSON data, automatically computing missing records and altered outputs.
