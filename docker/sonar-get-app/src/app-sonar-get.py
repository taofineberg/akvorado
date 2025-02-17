#!/usr/bin/env python3
import os
import json
import requests
from dotenv import load_dotenv
import logging
import csv
import ipaddress
import yaml  # Requires PyYAML. Install via `pip install pyyaml`
import time

# Load environment variables from .creds file
load_dotenv(dotenv_path='/opt/akvorado/.creds')

# Configuration
SONAR_API_URL = os.environ.get("GRAPHQL_URL", "https://your-sonar-endpoint/graphql")
SONAR_API_KEY = os.environ.get("AUTH_TOKEN", "your_auth_token_here")

#OUTPUT_FILE_CUSTOMERS = os.getenv("OUTPUT_FILE_CUSTOMERS", "/opt/akvorado/config/customers.csv")
OUTPUT_FILE_IP_ASSIGNMENTS = os.getenv("OUTPUT_FILE_IP_ASSIGNMENTS", "/opt/akvorado/config/customers.csv")
OUTPUT_FILE_CUSTOMERS_SUBNET = os.getenv("OUTPUT_FILE_CUSTOMERS_SUBNET", "/opt/akvorado/config/customers_subnet.csv")
OUTPUT_FILE_NETWORKS_YAML = os.getenv("OUTPUT_FILE_NETWORKS_YAML", "/opt/akvorado/config/networks.yaml")
OUTPUT_FILE_SCHEMA_YAML = os.getenv("OUTPUT_FILE_SCHEMA_YAML", "/opt/akvorado/config/schema.yaml")

# Define the headers for the request
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {SONAR_API_KEY}"
}

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s: %(message)s',
    handlers=[logging.StreamHandler()]
)

def is_ipv4(address):
    """
    Determines if the provided address is IPv4.
    
    Args:
        address (str): The IP address to check.
        
    Returns:
        bool: True if IPv4, False otherwise.
    """
    try:
        ip = ipaddress.ip_address(address)
        return isinstance(ip, ipaddress.IPv4Address)
    except ValueError:
        return False

def fetch_sonar_data():
    """
    Fetches IP assignments from Sonar's GraphQL API and returns a list of subnets
    with the corresponding account details.

    Returns:
        list: A list of dictionaries containing:
            - 'addr'
            - 'name' (account name)
            - 'id' (account id)
            - 'service'
            - 'account_type'
            - 'account_status'
            - 'city'
            - 'zip'
            - 'latitude'
            - 'longitude'
            - 'description'
    """
    query = """
    {
      accounts(paginator: {page: 1, records_per_page: 10000}) {
        entities {
          name
          id
          account_services {
            entities {
              service {
                name
              }
            }
          }
          account_type { 
            name 
          }
          account_status {
            name
          }
          addresses {
            entities {
              city
              zip
              latitude
              longitude
              inventory_items {
                entities {
                  ip_assignments {
                    entities {
                      subnet
                      description
                      ip_pool {
                        id
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    """
    try:
        response = requests.post(
            SONAR_API_URL,
            headers=headers,
            json={"query": query},
            verify=False  # Consider setting to True in production
        )
        response.raise_for_status()
        data = response.json()

        extracted_list = []

        accounts = data.get("data", {}).get("accounts", {}).get("entities", [])
        for account in accounts:
            account_name = account.get("name")
            account_id = account.get("id")

            # Extract services
            account_services = account.get("account_services", {}).get("entities", [])
            services = [service_entity.get("service", {}).get("name") for service_entity in account_services if service_entity.get("service")]
            services = "; ".join(filter(None, services)) if services else "N/A"

            # Extract account type
            account_type = account.get("account_type", {}).get("name", "N/A")

            # Extract account status
            account_status = account.get("account_status", {}).get("name", "N/A")

            addresses = account.get("addresses", {}).get("entities", [])
            for address in addresses:
                city = address.get("city", "N/A")
                zip_code = address.get("zip", "N/A")
                latitude = address.get("latitude", "N/A")
                longitude = address.get("longitude", "N/A")

                inventory_items = address.get("inventory_items", {}).get("entities", [])
                for item in inventory_items:
                    ip_assignments = item.get("ip_assignments", {}).get("entities", [])
                    for ip_assignment in ip_assignments:
                        subnet = ip_assignment.get("subnet")
                        description = ip_assignment.get("description", "N/A")

                        if not subnet:
                            logging.warning(f"Missing subnet in account ID: {account_id}")
                            continue

                        # Determine if subnet is IPv4 and add prefix if necessary
                        if is_ipv4(subnet):
                            subnet_prefixed = f"::ffff:{subnet}"
                        else:
                            subnet_prefixed = subnet

                        if subnet_prefixed and account_name and account_id:
                            extracted_list.append({
                                "addr": subnet_prefixed,
                                "name": account_name,
                                "id": account_id,
                                "service": services,
                                "accounttype": account_type,
                                "accountstatus": account_status,
                                "city": city,
                                "zip": zip_code,
                                "latitude": latitude,
                                "longitude": longitude,
                                "description": description
                            })
                        else:
                            logging.warning(f"Missing data for subnet: {subnet} in account ID: {account_id}")

        return extracted_list

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching Sonar data: {e}")
        return []
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON response: {e}")
        return []
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return []

def write_ip_assignments_csv(data, filename):
    """
    Writes all IP assignment data to a CSV file.

    Args:
        data (list): List of dictionaries containing IP assignment data.
        filename (str): Name of the CSV file to create.
    """
    try:
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['addr', 'name', 'id', 'service', 'accounttype', 'accountstatus', 'city', 'zip', 'latitude', 'longitude', 'description'])
            for entry in data:
                writer.writerow([
                    entry.get('addr', ''),
                    entry.get('name', ''),
                    entry.get('id', ''),
                    entry.get('service', ''),
                    entry.get('accounttype', ''),
                    entry.get('accountstatus', ''),
                    entry.get('city', ''),
                    entry.get('zip', ''),
                    entry.get('latitude', ''),
                    entry.get('longitude', ''),
                    entry.get('description', '')
                ])
        logging.info(f"Data successfully written to {filename}")
    except Exception as e:
        logging.error(f"Error writing to CSV: {e}")

def write_customers_subnet_csv(data, filename='customers_subnet.csv'):
    """
    Writes filtered IPv6 subnet data to a CSV file.

    Args:
        data (list): List of dictionaries containing IP assignment data.
        filename (str): Name of the CSV file to create.
    """
    try:
        with open(filename, 'w', newline='') as subnet_file:
            subnet_writer = csv.writer(subnet_file)
            subnet_writer.writerow([
                'addr', 'name', 'id', 'service', 
                'accounttype', 'accountstatus', 
                'city', 'zip', 'latitude', 
                'longitude', 'description'
            ])
            
            for entry in data:
                subnet_addr = entry.get('addr', '')
                # Skip if the address starts with ::ffff: or has no prefix length
                if subnet_addr.startswith("::ffff:") or '/' not in subnet_addr:
                    continue
                try:
                    network = ipaddress.ip_network(subnet_addr, strict=False)
                    if network.version == 6 :
                        subnet_writer.writerow([
                            entry.get('addr', ''),
                            entry.get('name', ''),
                            entry.get('id', ''),
                            entry.get('service', ''),
                            entry.get('accounttype', ''),
                            entry.get('accountstatus', ''),
                            entry.get('city', ''),
                            entry.get('zip', ''),
                            entry.get('latitude', ''),
                            entry.get('longitude', ''),
                            entry.get('description', '')
                        ])
                except ValueError:
                    logging.warning(f"Invalid subnet format: {subnet_addr}. Skipping.")
                    continue
        logging.info(f"Data successfully written to {filename}")
    except Exception as e:
        logging.error(f"Error writing to customers_subnet.csv: {e}")

def save_to_yaml(data, filename='networks.yaml'):
    """
    Saves the IPv6 network data to a YAML file.

    Args:
        data (list): List of dictionaries containing extracted data.
        filename (str): Name of the YAML file to create.
    """
    yaml_dict = {}
    for entry in data:
        subnet_addr = entry.get("addr", "")
        if not subnet_addr:
            logging.warning("Missing addr in entry. Skipping.")
            continue

        # Skip if the address starts with ::ffff:, is a /128 subnet, or has no prefix length
        if subnet_addr.startswith("::ffff:") or subnet_addr.endswith("/128") or '/' not in subnet_addr:
            continue

        # Check if the subnet is valid
        try:
            network = ipaddress.ip_network(subnet_addr, strict=False)
        except ValueError:
            logging.warning(f"Invalid subnet format: {subnet_addr}. Skipping.")
            continue

        # Prepare YAML entry
        yaml_entry = {
            "name": entry.get("name", "N/A"),
            #"SonarID": entry.get("id", "N/A"),
            "tenant": entry.get("service", "N/A"),
            "role": entry.get("accounttype", "N/A"),
            #"SonarAccountStatus": entry.get("account_status", "N/A"),
            "city": entry.get("city", "N/A"),
            "state": entry.get("zip", "N/A"),
            #"SonarLatitude": entry.get("latitude", "N/A"),
            #"SonarLongitude": entry.get("longitude", "N/A"),
            #"SonarDescription": entry.get("description", "N/A")
        }

        yaml_dict[subnet_addr] = yaml_entry

    try:
        with open(filename, 'w', encoding='utf-8') as yamlfile:
            yaml.dump(yaml_dict, yamlfile, sort_keys=False)

        logging.info(f"Data successfully written to {filename}")

    except Exception as e:
        logging.error(f"Error writing to YAML: {e}")

#schema = {
#    'custom-dictionaries': {
#        'customers': {
#            'layout': 'complex_key_hashed',
#            'keys': [
#                {'name': 'addr', 'type': 'String'}
#            ],
#            'attributes': [
#                {'name': 'name', 'type': 'String', 'label': 'CustomerName'},
#                {'name': 'id', 'type': 'String', 'label': 'SonarID'},
#                {'name': 'service', 'type': 'String', 'label': 'SonarService'},
#                {'name': 'accounttype', 'type': 'String', 'label': 'SonarAccountType'},
#                {'name': 'accountstatus', 'type': 'String', 'label': 'SonarAccountStatus'},
#                {'name': 'city', 'type': 'String', 'label': 'SonarCity'},
#                {'name': 'zip', 'type': 'String', 'label': 'SonarZIP'},
#                {'name': 'latitude', 'type': 'String', 'label': 'SonarLatitude'},
#                {'name': 'longitude', 'type': 'String', 'label': 'SonarLongitude'},
#                {'name': 'description', 'type': 'String', 'label': 'SonarDescription'},
#            ],
#            'source': '/opt/akvorado/customers.csv',
#            'dimensions': ['SrcAddr', 'DstAddr']
#        }
#    }
#}

#with open(OUTPUT_FILE_SCHEMA_YAML, 'w') as schema_file:
#    yaml.dump(schema, schema_file)

def main():
    sonar_data = fetch_sonar_data()
    if (sonar_data):
        write_ip_assignments_csv(sonar_data, filename=OUTPUT_FILE_IP_ASSIGNMENTS)
        write_customers_subnet_csv(sonar_data, filename=OUTPUT_FILE_CUSTOMERS_SUBNET)
        save_to_yaml(sonar_data, filename=OUTPUT_FILE_NETWORKS_YAML)
    else:
        logging.info("No data to write to CSV or YAML.")

if __name__ == "__main__":
    while True:
        main()
        logging.info("Sleeping for 24 hours...")
        time.sleep(86400)  # Pause for 24 hours
        logging.info("Fetching Sonar data again...")