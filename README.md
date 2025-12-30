# 🛡️ Sentinel Core (ShoMap)
### AI-Powered Autonomous Infrastructure Auditor

**Sentinel Core** is an advanced Bash-based reconnaissance agent that orchestrates **Shodan**, **Nmap**, **Nuclei**, and **OpenAI (GPT-4o)** to perform deep-dive infrastructure auditing. 

Unlike static scanners, Sentinel Core uses a **Recursive AI Logic Loop** to analyze findings in real-time, self-correct scan arguments, and validate vulnerabilities dynamically.

---

## 🚀 Key Features

* **🧠 Recursive AI Logic:** The script analyzes scan results and decides if it needs to run deeper, targeted scans (up to 2 recursion loops).
* **🤖 Dual-Model Engine:** Choose between **Fast (GPT-4o-mini)** for cost efficiency or **High-Reliability (GPT-4o)** for complex reasoning.
* **🔍 Multi-Stage Recon:**
    1.  **Passive:** Shodan Intelligence (ISP, OS, CVEs).
    2.  **Active:** Nmap Aggressive Scan (Service versioning, OS detection).
    3.  **Vulnerability:** Nuclei (CVEs, Misconfigurations, Default Logins).
    4.  **Validation:** Dynamic CVE confirmation using Nmap scripts.
* **💰 Cost Accounting:** Tracks token usage and calculates exact session cost in USD.
* **🛡️ Safety Guardrails:** Prevents destructive commands and validates input targets strictly.

---

## 🛠️ Prerequisites

The script automatically checks for these dependencies. If missing, please install them:

* `curl` & `wget` (Network requests)
* `jq` (JSON parsing)
* `nmap` (Port scanning)
* `xmllint` (XML parsing, usually part of `libxml2-utils`)
* `openssl` (SSL analysis)
* `unzip` & `tar` (Archives)

**Nuclei** is installed automatically by the script if not found.

### API Keys Required
You need API keys for **OpenAI** and **Shodan**. You can export them in your `.bashrc` or enter them when prompted.

```bash
export OPENAI_API_KEY="sk-..."
export SHODAN_API_KEY="..."
