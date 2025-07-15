# DOS Detection System

This project is a simple Denial of Service (DOS) detection system implemented in **Python** using the **Scapy** library. It monitors live network traffic and detects suspicious behavior by counting the number of packets sent from individual IP addresses over a short time window.

## 📌 Features

- 📡 Live packet sniffing using `scapy`
- 🔢 Tracks packet frequency per source IP
- 🚨 Triggers alerts for suspected DOS attempts
- 🕒 Adjustable time window and packet threshold

## ⚙️ How It Works

The system:
1. Monitors packets using `scapy.sniff()`
2. Tracks timestamps of packets received from each IP
3. If an IP sends more than a set threshold within 10 seconds, it raises an alert

## 🛠️ Requirements

- Python 3.x
- scapy

Install dependencies using:

```bash
pip install -r requirements.txt
