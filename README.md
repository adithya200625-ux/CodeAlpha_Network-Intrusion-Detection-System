# CodeAlpha_Network-Intrusion-Detection-System
# CodeAlpha Network Intrusion Detection System

## Overview

This project implements a Network Intrusion Detection System (NIDS) using Suricata on Ubuntu Linux.

The system monitors network traffic, analyzes packets using detection rules, generates security alerts, and uses a Python-based monitor to record detected incidents for SOC investigation.

## Architecture

Network Traffic
       ↓
    Suricata
       ↓
 Detection Rules
       ↓
 Security Alert
       ↓
 Python NIDS Monitor
       ↓
 Incident Response Log

## Technologies Used

- Ubuntu Linux
- Suricata
- Suricata-Update
- Python 3
- JSON
- ICMP
- NIDS detection rules

## Project Structure

```text
CodeAlpha_Network-Intrusion-Detection-System/
│
├── nids_monitor.py
├── suricata.yaml
├── README.md
│
└── rules/
    └── local.rules
