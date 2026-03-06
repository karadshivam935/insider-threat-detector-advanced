# Insider Threat Detector Advanced

## Overview

**Insider Threat Detector Advanced** is a cybersecurity monitoring system designed to detect suspicious internal network activity inside an organization.
The project captures network traffic, analyzes behavioral patterns, generates alerts, and can automatically block suspicious IP addresses.

This project simulates a real corporate environment using **Admin VM** and **Employee VM** where employee traffic is monitored for abnormal behavior.

---

## Features

* Real-time network traffic monitoring
* Detection of abnormal internal activity
* Behavior-based anomaly detection
* Automatic alert generation
* Automatic IP blocking using iptables
* Web dashboard for monitoring alerts
* SQLite database for event storage
* Designed for enterprise insider threat simulation

---

## Project Architecture

Admin VM (Monitoring Server)

* Runs the detector system
* Captures and analyzes traffic
* Generates alerts
* Blocks malicious IPs

Employee VM (User System)

* Generates network activity
* Traffic is monitored by the Admin VM

---

## Technology Stack

* Python
* Flask + SocketIO
* SQLite
* Linux networking tools
* iptables
* Virtual Machine environment

---

## Project Structure

```
insider_threat_detector_advanced/
│
├── app/                    # Main application code
│   ├── core/               # Detection logic
│   ├── web/                # Web dashboard
│   └── main.py             # Application entry point
│
├── data/                   # SQLite database
├── logs/                   # Log files
├── config.yaml             # Project configuration
├── config.example.yaml     # Example configuration
├── itdctl                  # Project control script
├── setup_admin.sh          # Setup script
└── venv/                   # Python virtual environment
```

---

## Installation

Clone the repository

```
git clone https://github.com/karadshivam935/insider-threat-detector-advanced.git
cd insider-threat-detector-advanced
```

Create virtual environment

```
python3 -m venv venv
source venv/bin/activate
```

Install dependencies

```
pip install -r requirements.txt
```

---

## Run the Project

Start the detector:

```
sudo -E venv/bin/python -m app.main
```

The web dashboard will start and show detected alerts.

---

## Configuration

Edit the configuration file:

```
config.yaml
```

Example settings:

* Network interface
* Detection thresholds
* Auto block settings
* Database location

---

## Example Detection

The system detects behaviors such as:

* New destination ports
* Sudden traffic spikes
* Abnormal data transfer
* Suspicious internal connections

When a threshold is exceeded:

* Alert is generated
* IP can be automatically blocked

---

## Educational Purpose

This project is built for:

* Cybersecurity learning
* Insider threat detection simulation
* Network monitoring research
* Security lab experiments

---

## Author

Shivam Karad
Cybersecurity Student
