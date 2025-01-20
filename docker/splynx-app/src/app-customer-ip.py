import csv
import logging
import os
import ipaddress
import hmac
import hashlib
import time
import requests
from dotenv import load_dotenv

# Load environment variables from .creds file
load_dotenv(dotenv_path='/opt/akvorado/.creds')

# Configuration
BASE_URL = os.getenv("SPLYNX_URL")
API_KEY = os.getenv("SPLYNX_API_KEY")
API_SECRET = os.getenv("SPLYNX_API_SECRET")
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "/opt/akvorado/config/customers.csv")
LOG_LEVEL = os.getenv("SPLYNX_LOG_LEVEL", "INFO").upper()

# Ensure required environment variables are set
if not BASE_URL or not API_KEY or not API_SECRET:
    logging.error("Required environment variables BASE_URL, API_KEY, or API_SECRET are not set. Waiting for 24 hours before retrying.")
    time.sleep(86400)  # Wait for 24 hours before retrying

# Ensure BASE_URL ends with a slash
if not BASE_URL.endswith('/'):
    BASE_URL += '/'

# Set up logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.DEBUG),
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def generate_signature(nonce, api_key, api_secret):
    """Generate HMAC-SHA256 signature."""
    message = f"{nonce}{api_key}"
    return hmac.new(api_secret.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).hexdigest().upper()

def authenticate():
    """Authenticate with the Splynx API to retrieve an access token."""
    nonce = str(int(time.time()))
    signature = generate_signature(nonce, API_KEY, API_SECRET)

    payload = {
        "auth_type": "api_key",
        "key": API_KEY,
        "nonce": nonce,
        "signature": signature
    }

    logging.info("Authenticating to Splynx API")
    response = requests.post(f"{BASE_URL}admin/auth/tokens", data=payload)
    logging.info("Authentication response status: %s", response.status_code)

    if response.status_code != 201:  # Expecting 201 Created
        logging.error("Authentication failed: %s", response.text)
        raise Exception(f"Authentication failed with status {response.status_code}")

    # Extract the token from the correct JSON path
    token = response.json().get("access_token")
    if not token:
        logging.error("No token received during authentication")
        raise Exception("No token received")

    # Return the complete Authorization header value
    return f"Splynx-EA (access_token={token})"

def fetch_customers(headers):
    """Fetch customers from the Splynx API."""
    logging.info("Fetching customers from Splynx API")
    response = requests.get(f"{BASE_URL}admin/customers/customer", headers=headers)

    if response.status_code != 200:
        logging.error("Failed to fetch customers: %s", response.text)
        raise Exception(f"Failed to fetch customers with status {response.status_code}")

    response_json = response.json()
    if isinstance(response_json, list):
        customers = response_json
    else:
        customers = response_json.get("data", [])

    if not customers:
        logging.warning("No customers found")
        return [], []

    customer_ids = [customer['id'] for customer in customers]
    customer_data = [
        {
            "id": customer['id'],
            "name": customer.get('name', 'N/A'),
            "gps": customer.get('gps', 'N/A')
        }
        for customer in customers
    ]

    logging.info("Fetched customer IDs: %s", customer_ids)
    return customer_ids, customer_data

def fetch_internet_services(customer_id, headers):
    """Fetch internet services for a given customer ID from the Splynx API."""
    logging.info("Fetching internet services for customer ID: %s", customer_id)
    response = requests.get(f"{BASE_URL}admin/customers/customer/{customer_id}/internet-services", headers=headers)

    if response.status_code != 200:
        logging.error("Failed to fetch internet services for customer ID %s: %s", customer_id, response.text)
        raise Exception(f"Failed to fetch internet services for customer ID {customer_id} with status {response.status_code}")

    services = response.json()
    return [
        {
            "ipv4": service.get("ipv4"),
            "ipv6_delegated": service.get("ipv6_delegated"),
            "description": service.get("description"),
            "ipv4_route": service.get("ipv4_route")
        }
        for service in services
    ]

def process_customer_data(customer_data, internet_services):
    """Process customer data and internet services into CSV-compatible format."""
    data = []
    for customer in customer_data:
        customer_name = customer.get("name", "NA")
        gps = customer.get("gps", "NA")
        latitude, longitude = ('NA', 'NA')
        if gps and ',' in gps:
            latitude, longitude = gps.split(',')

        for service in internet_services.get(customer["id"], []):
            ipv4 = service.get("ipv4", "")
            ipv6 = service.get("ipv6_delegated", "")
            ipv4_route = service.get("ipv4_route", "")
            ipv4_addresses = []
            
            if ipv4_route:
                try:
                    ipv4_network = ipaddress.ip_network(ipv4_route)
                    ipv4_addresses = [str(ip) for ip in ipv4_network.hosts()]
                except ValueError as e:
                    logging.warning("Invalid IPv4 route for customer %s: %s", customer_name, e)

            # Append to data list
            if ipv4:
                data.append([f"::ffff:{ipv4}", customer_name, latitude, longitude])
            if ipv6:
                data.append([ipv6, customer_name, latitude, longitude])
            for ip in ipv4_addresses:
                data.append([f"::ffff:{ip}", customer_name, latitude, longitude])
    
    return data

def write_customer_data_to_csv(data, output_file):
    """Write processed customer data to CSV."""
    try:
        logging.info("Saving customer data to %s", output_file)
        with open(output_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["addr", "customerName", "latitude", "longitude"])
            writer.writerows(data)
    except OSError as e:
        logging.error("Failed to write to %s: %s", output_file, e)
        raise

def main():
    try:
        logging.info("Script started")
        token = authenticate()
        headers = {"Authorization": token}
        customer_ids, customer_data = fetch_customers(headers)
        internet_services = {
            cid: fetch_internet_services(cid, headers) for cid in customer_ids
        }
        processed_data = process_customer_data(customer_data, internet_services)
        write_customer_data_to_csv(processed_data, OUTPUT_FILE)
        logging.info("Script completed successfully")
        
        # Wait for 24 hours before running again
        logging.info("Waiting for 24 hours before next run")
        time.sleep(86400)  # 24 hours in seconds
        main()  # Run the script again after the delay
    except Exception as e:
        logging.error("An error occurred: %s", e)

if __name__ == "__main__":
    main()
