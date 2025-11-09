![ANTS Logo](https://img.shields.io/badge/ANTS-Network%20Security-blue) ![Python](https://img.shields.io/badge/Python-3.8+-green) ![License](https://img.shields.io/badge/License-MIT-yellow)


# ANTS - Advanced Network Traffic Security Analyzer

### *Intelligent Layer-7 AI-Driven Firewall with Deep Packet Inspection and Adaptive Threat Mitigation*

**Team:** import ants
## Team Members
Shivam Aryan, 
Nishant Mohan,
Tanmay Paul,
Shreyansh Gangwar


---

## 🚀 Overview

Modern networks hide threats inside encrypted traffic (HTTPS). ANTS is a next-generation Layer-7 firewall that combines **Deep Packet Inspection (DPI)**, lightweight AI models, and adaptive rule generation to detect and mitigate threats that bypass traditional signature-based systems. ANTS performs secure decryption/re-encryption to inspect application-layer payloads while preserving end-to-end confidentiality.

---

## 🧩 Core Innovations

* **Secure LLM Payload Analysis** — A secure LLM inspects decrypted payloads to detect novel or obfuscated threats (e.g., token exfiltration, stealthy extensions, zero-days).
* **Autonomous Rule Designer** — An LLM-powered rule designer generates deterministic regex/metadata rules for newly discovered attack vectors; rules are validated before being added to the rule engine.
* **Selective LLM Invocation** — LLM analysis is triggered deterministically (metadata/payload triggers) to control compute and privacy costs.

---

## ⚙️ System Flow

```plaintext
Live/File Data
  ↓
Deep Packet Inspection (DPI)
  ↓
Static Firewall
  ↓
Custom Rule Engine
  ↓
Classification by Model 1 (ML/RL)
  ↓
Classification Output
  ↓
Packet Filtering by Static Rules
  ↓
Analyze Payload by Model 2 (LLM)
  ↓
Model 2 Output → Action Decision
  ↓
 ┌────────────┬───────────┬──────────────┬────────┬────────┬────────┐
 │ Allow      │ Block     │ Reject       │ Log    │ Warn   │ Alert  │
 └────────────┴───────────┴──────────────┴────────┴────────┴────────┘
  ↓
Save to SQLite Database

Parallel:
Model 3 Rule Designer → Input Schema → Rule Designer LLM → Rule Functions Output → Generate New Custom Rules → Custom Rule Engine
```

---

## 🧠 Architecture Highlights

* **DPI Engine** – HTTPS decryption and payload parsing
* **Static Firewall** – Baseline signature filtering
* **Custom Rule Engine** – Applies static + AI-generated rules
* **ML/RL Classifier (Model 1)** – Metadata-based behavioral detection
* **LLM Analyzer (Model 2)** – Semantic payload inspection
* **Rule Designer LLM (Model 3)** – Generates new deterministic rules
* **SQLite** – Decision logs and threat intelligence storage

---

## 🧰 Tech Stack

* mitmproxy
* Llama Instruct 8B
* PyShark
* Python
* SQLite
* React (for dashboards & visualization)

---

## 🔒 Key Features

* Secure HTTPS inspection using in-house certificate
* Multi-model pipeline: ML/RL + LLMs for layered detection
* Adaptive rule generation with human/automated validation
* Triggered LLM analysis to optimize cost and privacy
* Persistent logging for audit and threat hunting

---

## 📊 Visualization

The flowchart for the network packet processing flow is included below. Save it under `./assets/flowchart.png` in the repository so it renders on GitHub.

---<img width="1660" height="465" alt="Screenshot 2025-11-09 103541" src="https://github.com/user-attachments/assets/a009966e-c6f0-4399-bd3c-21ed3c8818f3" />

## 👥 Team

**Team Name:** `import ants`
**Project:** ANTS - Advanced Network Traffic Security Analyzer
**Members:** (Add names here)

---

> By combining DPI with AI-driven learning, ANTS transforms network defense from a static gate into an adaptive, evolving shield.
