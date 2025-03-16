import boto3
import json
import requests
import sys
import logging
import pymongo
import urllib.parse
import os
import pytz
import time
import smtplib
import pandas as pd
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from botocore.exceptions import ClientError
from datetime import datetime, timedelta

# Function to fetch data from AWS Secrets Manager
def get_credentials():
    secret_name = "optiv/project/abuseIPDBVirusTotal"
    region_name = "us-east-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    # Fetching credentials from AWS Secret Manager
    try:
        response = client.get_secret_value(
            SecretId=secret_name
        )
        logging.info("Credentials fetched successfully")
    except ClientError as e:
        logging.error(f"Failed to fetch credentials: {str(e)}")
        sys.exit(1)

    return json.loads(response['SecretString'])

# Function to check local AbuseIPDB blacklist data
def check_abuseipdb_local_data():
    global data_dir
    json_file = os.path.join(data_dir, 'abuseipdb_blacklist.json')
    if os.path.exists(json_file):
        logging.info("Local AbuseIPDB blacklist data found")
        with open(json_file, 'r') as f:
            data = json.loads(f.read())
        # Gets data generated timestamp
        timestamp_dt = datetime.fromisoformat(data['meta']['generatedAt'])
        now_utc = datetime.now(pytz.utc)

        # Check if the timestamp is at least 24 hours from now
        if timestamp_dt >= now_utc - timedelta(hours=24):
            return data['data']
        else:
            logging.info("It's been more than 24 hours since the data was retrieved.")
            return False
    else:
        logging.info("Local AbuseIPDB blacklist data not found")
        return False

# Function to retrieve blacklist data
def get_abuseIPDB_blasklist_data(api_key):
    global data_dir

    local_data = check_abuseipdb_local_data()
    if local_data:
        logging.info("Using local AbuseIPDB blacklist data")
        return local_data

    logging.info("Fetching new abuseIPDB blacklist data")
    url = 'https://api.abuseipdb.com/api/v2/blacklist'
    querystring = {
        'confidenceMinimum': '97'
    }
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    try:
        response = requests.get(url, headers=headers, params=querystring)
        response.raise_for_status()
        response = response.json()
        logging.info("AbuseIPDB blacklist data fetched successfully")
        json_file = os.path.join(data_dir, 'abuseipdb_blacklist.json')
        with open(json_file, 'w') as f:
            f.write(json.dumps(response))
        return response['data']
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch AbuseIPDB blacklist data: {str(e)}")
        sys.exit(1)

# Function to retrieve VirusTotal IP reputation data for AbuseIPDB blacklist IP's
def get_virustotal_ip_reputation_check_results(ip_addrs, api_key):
    url = "https://www.virustotal.com/api/v3/ip_addresses/"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    vt_ip_rep_data = []
    max_retries = 5
    base_sleep_time = 15

    for ip_addr in ip_addrs:
        attempt = 0
        sleep_time = base_sleep_time
        while attempt < max_retries:
            try:
                logging.info(f"Fetching VirusTotal IP reputation data for {ip_addr}")
                response = requests.get(url + ip_addr, headers=headers)

                if response.status_code == 429:
                    logging.warning(
                        f"Rate limit hit for {ip_addr}. Retrying in {sleep_time} seconds...")
                    time.sleep(sleep_time)
                    # Exponential backoff increases sleep time exponentially to handle rate limit effectively.
                    sleep_time *= 2
                    attempt += 1
                    continue

                response.raise_for_status()
                data = response.json().get('data', {}).get('attributes', {})
                logging.info(f"VirusTotal IP reputation data fetched successfully for {ip_addr}")
                vt_ip_rep_data.append({
                    'ip_address': ip_addr,
                    'country': data.get('country', ''),
                    'detected_urls': data.get('last_analysis_stats', {}).get('malicious', 0),
                    'detected_downloaded_samples': data.get('last_analysis_stats', {}).get('suspicious', 0),
                    'undetected_downloaded_samples': data.get('last_analysis_stats', {}).get('harmless', 0),
                    'undetected_urls': data.get('last_analysis_stats', {}).get('undetected', 0)
                })

                time.sleep(base_sleep_time)
                break
            except requests.exceptions.RequestException as e:
                logging.error(f'Error fetching virus total IP reputation data for IP {ip_addr}: {e}')
                attempt += 1
                if attempt == max_retries:
                    logging.error(f"Max retries reached for {ip_addr}, skipping...")

    return vt_ip_rep_data

# Function to save Virus Total IP reputations data to mongodb
def save_to_mongodb(client, data):
    try:
        db = client['optiv']
        collection = db['AbuseVT']
        collection.insert_many(data)
        logging.info('Virus Total IP reputation check data for AbuseIPDB Blacklist IP\'s is saved to AbuseVT collection under optiv database in MongoDB.')
    except Exception as e:
        logging.error(f"Failed to save data to MongoDB: {str(e)}")


# Function to send email with VirusTotal IP reputation report and AbuseIPDB Blacklist IP's excel attached
def mail_vt_ip_report(email_recipient, vt_ip_rep_data, sender_email, sender_password):
    global data_dir

    subject = "VirusTotal IP Reputation Report"

    # Convert data to DataFrame and creates HTML table
    df = pd.DataFrame(vt_ip_rep_data)
    table_html = df.to_html(index=False, border=1, justify="center")
    
    # Gets file path
    file_name = "AbuseIPDB_data.xlsx"
    excel_filename = os.path.join(data_dir, file_name)

    # Create Email
    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = email_recipient
    msg["Subject"] = subject


    logging.info("Composing Email Message")

    email_body = f"""
    <html>
    <body>
        <p>Hello Lokesh,</p>

        <p>Good day!</p>

        <p>
            Please find attached the <b>AbuseIPDB blacklist report</b>, which contains IP addresses with an 
            <b>abuse confidence score greater than 97</b>. And, the <b>VirusTotal reputation check</b> has been performed 
            on 1st {len(vt_ip_rep_data)} IPs, and the results are presented below.
        </p>

        <p>
            <b>VirusTotal IP Reputation Summary:</b>
        </p>

        {table_html} 

        <p>
            For a detailed list of all blacklisted IPs, please refer to the attached <b>Excel report</b>.
        </p>

        <br>
        Best Regards,<br>
        <b>Nikhil Yadavaram</b><br>
        <a href='mailto:nikhil.yadavaram@outlook.com'>nikhil.yadavaram@outlook.com</a><br>
        +91-8919151662</p>
    </body>
    </html>

    """
    msg.attach(MIMEText(email_body, "html"))
    # Attaching Excel File
    with open(excel_filename, "rb") as attachment:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition",
                        f"attachment; filename={file_name}")
        msg.attach(part)

    # Sending Email
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)  # Gmail SMTP
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email_recipient, msg.as_string())
        logging.info(f"Email sent successfully to {email_recipient}")
        server.quit()
    except Exception as e:
        logging.error(f"Failed to send email: {str(e)}")


if __name__ == '__main__':
    # Configure logging
    logfile = 'abuseIPDB_VirusTotal.log'
    logging.basicConfig(filename=logfile, level=logging.INFO,
                        format='%(asctime)s:%(levelname)s:%(message)s')
    logging.info('Starting AbuseIPDB_VirusTotal.py script')
    print(f'Log file created: {logfile}')

    # Fetch AWS Secrets Manager credentials
    credentials = get_credentials()

    username = credentials['MongoUserName']
    password = credentials['MongoPassword']

    # Encode username and password avoids conflicts with special characters
    encoded_username = urllib.parse.quote_plus(username)
    encoded_password = urllib.parse.quote_plus(password)

    # Connecting to MongoDB
    uri = f"mongodb+srv://{encoded_username}:{encoded_password}@optiv.gy68s.mongodb.net/?retryWrites=true&w=majority&appName=Optiv"
    client = pymongo.MongoClient(uri)
    try:
        client.admin.command("ping")
        logging.info("MongoDB connection established")
    except Exception as e:
        logging.error(f"Failed to connect to MongoDB: {str(e)}")
        sys.exit(1)

    # Creates a data directory to save excel and json files.
    current_path = os.getcwd()
    data_dir = os.path.join(current_path, 'data')
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)

    abuseipdb_data = get_abuseIPDB_blasklist_data(credentials['AbuseIPDB'])
    df = pd.DataFrame(abuseipdb_data)
    df.to_excel('data/AbuseIPDB_data.xlsx',
                sheet_name='AbuseIPDB_Blacklist', index=False)
    logging.info("Blacklist data saved to Excel file")

    # Get the first 50 IP addresses from the dataframe as VirusTotal as a rate limit of 500 per day and it does not support batch requests. Considering a sample of 50 IP addresses.
    ip_addr_list = df['ipAddress'].tolist()[:50]
    vt_ip_rep_data = get_virustotal_ip_reputation_check_results(
        ip_addr_list, credentials['VirusTotal'])

    mail_vt_ip_report("lokesh.kumawat@optiv.com", vt_ip_rep_data, credentials['SenderMail'], credentials['senderPassword'])
    save_to_mongodb(client, vt_ip_rep_data)

    print("script completed")