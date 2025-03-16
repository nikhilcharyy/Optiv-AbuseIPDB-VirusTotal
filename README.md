# AbuseIPDB & VirusTotal Automation

## 📌 Overview
This project automates the retrieval of **blacklisted IPs from AbuseIPDB**, performs **IP reputation checks using VirusTotal**, stores results in **MongoDB**, and sends **automated email reports** with an attached Excel file and a formatted summary.

## 🚀 Features
- **Fetch Blacklisted IPs**: Retrieves IPs with `abuseConfidenceScore > 97` from AbuseIPDB.
- **VirusTotal IP Reputation Check**: Retrieves country, detected URLs, detected & undetected downloaded samples.
- **MongoDB Storage**: Saves VirusTotal results under the `AbuseVT` collection.
- **Automated Email Reports**: Sends formatted reports with an Excel attachment.
- **Error Handling & Logging**: Implements retry mechanisms, exponential backoff, and structured logging.

## 📂 Project Structure
```
project-folder/
│── abuseIPDB_VirusTotal.py       # Main script
│── requirements.txt              # Required dependencies
│── data/                         # Directory for output files
│   ├── abuseipdb_blacklist.json  # Cached AbuseIPDB data
│   ├── AbuseIPDB_data.xlsx       # Excel report
│── abuseIPDB_VirusTotal.log      # Log file
│── README.md                     # Project documentation
```

## 🛠️ Prerequisites
### **1. Install Dependencies**
```bash
pip install -r requirements.txt
```
### **2. Configure AWS CLI (for Secrets Manager)**
```bash
aws configure
```
Enter:
- AWS Access Key ID
- AWS Secret Access Key
- Default Region Name (e.g., `us-east-1`)

### **3. MongoDB Setup**
Ensure MongoDB is running (Local/Cloud). Update credentials in **AWS Secrets Manager**.

### **4. Get API Keys & Store in AWS Secrets Manager**
#### **Obtain API Keys**
- **AbuseIPDB API Key:** Sign up at [AbuseIPDB](https://www.abuseipdb.com/) and get your API key from the dashboard.
- **VirusTotal API Key:** Register at [VirusTotal](https://www.virustotal.com/) and retrieve the API key from your account.

#### **Save API Keys in AWS Secrets Manager**
```bash
aws secretsmanager create-secret --name optiv/project/abuseIPDBVirusTotal --secret-string '{"AbuseIPDB": "your_abuseipdb_api_key", "VirusTotal": "your_virustotal_api_key", "MongoUserName": "your_mongo_username", "MongoPassword": "your_mongo_password", "SenderMail": "your_email", "SenderPassword": "your_email_password"}'
```
Replace the placeholder values with your actual credentials.

## 🏗️ Usage
### **Run the Script**
```bash
python abuseIPDB_VirusTotal.py
```
### **Expected Outputs**
- **MongoDB Collection:** `AbuseVT` stores VirusTotal reputation data.
- **Excel File:** `data/AbuseIPDB_data.xlsx` containing blacklist details.
- **Email Report:** Sents an email with results.
- **Logs:** Stored in `abuseIPDB_VirusTotal.log`.

## ❗ Error Handling
- Implements **exponential backoff** for API rate limits.
- Logs all errors & exits safely if **critical failures occur**.
- Handles **MongoDB connection failures** & **email sending issues**.

## 📧 Contact
**Author:** Nikhil Yadavaram  
**Email:** [nikhil.yadavaram@outlook.com](mailto:nikhil.yadavaram@outlook.com)  

---
This project ensures an **efficient, automated, and error-handled approach** to cybersecurity intelligence. 🚀

