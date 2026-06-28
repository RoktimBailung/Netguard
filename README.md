#  NetGuard: Asynchronous Network Intrusion Detection System (IDS)

NetGuard is a lightweight, asynchronous Intrusion Detection System engineered to monitor live network traffic and mathematically detect malicious behavioral patterns. Designed with a decoupled architecture, it guarantees zero packet loss during high-volume volumetric attacks by utilizing a high-speed persistence layer.

##  Key Architectural Features

* **Live Hardware Interception:** Utilizes raw socket programming and NIC Promiscuous Mode to intercept OSI Layer 3/4 frames directly from the physical medium, bypassing standard OS filtering.
* **Decoupled Data Pipeline:** Separates the ingestion engine (Sniffer) from the analytical engine. Raw metadata is streamed into a high-speed MySQL buffer, ensuring the sniffer is never blocked by computationally heavy analysis.
* **Temporal Behavioral Analytics:** Abandons static signature matching. NetGuard employs SQL-based time-window aggregation to mathematically detect anomalies based on traffic volume, frequency, and structural irregularities.

##  Threat Detection Capabilities
NetGuard actively monitors and alerts on the following network anomalies:
1. **DDoS/Volumetric Exhaustion:** Detects massive inbound packet floods designed to crash network buffers.
2. **SSH Brute-Force:** Identifies rapid, consecutive authentication attempts indicative of credential stuffing.
3. **Reconnaissance (Port Scanning):** Flags sequential port probing across a wide range of standard and non-standard ports.
4. **DNS Tunneling (C2 Beacons):** Monitors UDP Port 53 for high-frequency queries indicative of data exfiltration or Command & Control communication.

##  Technology Stack
* **Ingestion:** Python 3, Scapy (Raw Socket Manipulation)
* **Persistence:** MySQL (High-Speed Append-Only Buffer)
* **Analysis:** Python, SQL Temporal Aggregation
* **Presentation (SOC Dashboard):** Flask, AJAX (Real-time polling), Chart.js, Bootstrap 5

##  Disclaimer
**Educational & Authorized Use Only:** This system includes a Red Team Simulator (`live_attacker.py`). This project was developed in an isolated, dual-node lab environment. Do not deploy the attacker scripts against networks or infrastructure you do not explicitly own or have permission to test.
