# Web Antivirus

## Overview
Web Antivirus is a web-based application for scanning files for malware. It uses ClamAV, YARA rules, and VirusTotal API for comprehensive threat detection.

## Features
- File upload and scanning
- Real-time scan results and alerts
- Email notifications
- User authentication
- Secure file handling

## Setup Instructions

### Prerequisites
- Python 3.8+
- Docker (optional for containerization)

### Local Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/ZemarKhos/web_antivirus.git
   cd web_antivirus
2. Install dependencies:
```bash
   pip install -r requirements.txt
```
3. Run the application:
```bash
flask run
```

### Docker Setup

Build and run the Docker containers:
```bash
docker-compose up --build
```
Usage
Visit http://localhost:8000 in your web browser.

Register and log in.
Upload a file to scan for malware.

### API Documentation
File Upload
Endpoint: /upload

Method: POST
Parameters: file (multipart/form-data)
Response: JSON with scan results
