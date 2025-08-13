import requests
import xml.etree.ElementTree as ET
import csv
import os
from dotenv import load_dotenv
from tqdm import tqdm

load_dotenv("c.env")

# === User configuration ===
QUALYS_API_URL = os.getenv('QUALYS_API_URL')
USERNAME = os.getenv('USERNAME1')  
PASSWORD = os.getenv('PASSWORD')

# Request parameters: filter by confirmed vulnerabilities (vulnerability type)
# You can adjust other parameters like vm_processed_after, truncation_limit as needed
REQUEST_PARAMS = {
    'action': 'list',
    'output_format': 'XML',
    'truncation_limit': 100,  # adjust max results per request
    # 'status': 'Active,New,Re-Opened',    # by default shows Active, New, Re-Opened
    # Add other filters such as vm_processed_after='2023-01-01T00:00:00Z' if needed
    # 'detection_updated_since':'2025-08-08T07:00:00Z'
    'show_qds': '1',
    'show_qds_factors':'1'
}

def fetch_host_vm_detection():
    print("Fetching Host VM Detection data...")

    # Add required X-Requested-With header
    headers = {
        'X-Requested-With': 'requests'
    }

    response = requests.post(
        QUALYS_API_URL,
        auth=(USERNAME,PASSWORD),
        data=REQUEST_PARAMS,
        headers=headers
    )
    
    if response.status_code != 200:
        print(f"API call failed with status code {response.status_code}")
        print(response.text)
        return None

    return response.text

def parse_detection_xml(xml_data):
    """
    Parse VM detection XML data to extract host and vulnerability info.
    Returns list of dictionaries.
    """

    root = ET.fromstring(xml_data)
    results = []

    hosts = root.findall('.//HOST')

    # Parsing based on Qualys Host Detection XML structure:
    # HOST_LIST_VM_DETECTION_OUTPUT / RESPONSE / HOST_LIST / HOST / DETECTION_LIST / DETECTION
    for host in tqdm(hosts, desc="Parsing hosts", unit="host"):
        asset_id = host.findtext('ID')
        asset_ip = host.findtext('IP')
        asset_name = host.findtext('DNS')  # Changed from DNS_NAME to DNS
        netbios = host.findtext('NETBIOS')
        os_info = host.findtext('OS')
        
        # Handle asset tags if they exist
        asset_tags_elems = host.findall('TAG_LIST/TAG')
        asset_tags = ','.join([tag.findtext('NAME') for tag in asset_tags_elems if tag.findtext('NAME')]) if asset_tags_elems else ''

        # Get last scan information
        last_scan_datetime = host.findtext('LAST_SCAN_DATETIME')
        last_vm_scanned_date = host.findtext('LAST_VM_SCANNED_DATE')

        detections = host.findall('DETECTION_LIST/DETECTION')
        for det in detections:
            qid = det.findtext('QID')
            unique_vuln_id = det.findtext('UNIQUE_VULN_ID')
            vuln_type = det.findtext('TYPE')  # Confirmed, Potential, Information Gathered
            severity = det.findtext('SEVERITY')
            port = det.findtext('PORT')
            protocol = det.findtext('PROTOCOL')
            ssl = det.findtext('SSL')
            status = det.findtext('STATUS')  # Active, New, Fixed, Re-Opened
            first_found = det.findtext('FIRST_FOUND_DATETIME')  # Changed from FIRST_DETECTED
            last_found = det.findtext('LAST_FOUND_DATETIME')    # Changed from LAST_DETECTED
            last_test = det.findtext('LAST_TEST_DATETIME')
            last_update = det.findtext('LAST_UPDATE_DATETIME')
            times_found = det.findtext('TIMES_FOUND')
            results_text = det.findtext('RESULTS')
            
            # QDS (Qualys Detection Score) if available
            qds_elem = det.find('QDS')
            qds = qds_elem.text if qds_elem is not None else ''
            qds_severity = qds_elem.get('severity') if qds_elem is not None else ''

            # QDS Factors if available
            qds_factors = []
            qds_factors_elem = det.find('QDS_FACTORS')
            if qds_factors_elem is not None:
                for factor in qds_factors_elem.findall('QDS_FACTOR'):
                    factor_name = factor.get('name')
                    factor_value = factor.text
                    if factor_name and factor_value:
                        qds_factors.append(f"{factor_name}:{factor_value}")
            qds_factors_str = '; '.join(qds_factors)

            results.append({
                'AssetID': asset_id,
                'AssetIP': asset_ip,
                'AssetName': asset_name,
                'NetBIOS': netbios,
                'OS': os_info,
                'AssetTags': asset_tags,
                'LastScanDateTime': last_scan_datetime,
                'LastVMScannedDate': last_vm_scanned_date,
                'UniqueVulnID': unique_vuln_id,
                'QID': qid,
                'Type': vuln_type,
                'Severity': severity,
                'Port': port,
                'Protocol': protocol,
                'SSL': ssl,
                'Status': status,
                'FirstFoundDateTime': first_found,
                'LastFoundDateTime': last_found,
                'LastTestDateTime': last_test,
                'LastUpdateDateTime': last_update,
                'TimesFound': times_found,
                'Results': results_text,
                'QDS': qds,
                'QDSSeverity': qds_severity,
                'QDSFactors': qds_factors_str
            })

    return results

def save_to_csv(data, filename='host_vm_detections110.csv'):
    if not data:
        print("No data to save.")
        return
        
    fieldnames = ['AssetID', 'AssetIP', 'AssetName', 'NetBIOS', 'OS', 'AssetTags', 
                  'LastScanDateTime', 'LastVMScannedDate', 'UniqueVulnID', 'QID', 
                  'Type', 'Severity', 'Port', 'Protocol', 'SSL', 'Status', 
                  'FirstFoundDateTime', 'LastFoundDateTime', 'LastTestDateTime', 
                  'LastUpdateDateTime', 'TimesFound', 'Results', 'QDS', 'QDSSeverity', 'QDSFactors']
    
    with open(filename, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in tqdm(data, desc="Saving to CSV", unit="record"):
            writer.writerow(row)
    print(f"Saved {len(data)} records to {filename}")

def handle_truncation(xml_data):
    """
    Check if the response is truncated and return the next URL if needed.
    """
    root = ET.fromstring(xml_data)
    warning = root.find('.//WARNING')
    
    if warning is not None:
        code = warning.findtext('CODE')
        text = warning.findtext('TEXT')
        next_url = warning.findtext('URL')
        
        if code == '1980':  # Truncation warning code
            print(f"Warning: {text}")
            print(f"Next URL: {next_url}")
            return next_url
    
    return None

def fetch_all_detections():
    """
    Fetch all detections handling pagination/truncation.
    """
    all_detections = []
    next_url = None
    page_count = 1
    
    while True:
        print(f"Fetching page {page_count}...")
        
        if next_url:
            # Use the next URL provided by Qualys for pagination
            headers = {'X-Requested-With': 'requests'}
            response = requests.get(next_url, auth=(USERNAME, PASSWORD), headers=headers)
            
            if response.status_code != 200:
                print(f"API call failed with status code {response.status_code}")
                print(response.text)
                break
                
            xml_response = response.text
        else:
            # First request
            xml_response = fetch_host_vm_detection()
            if xml_response is None:
                print("Failed to retrieve data.")
                break

        # Parse the current page
        detections = parse_detection_xml(xml_response)
        if detections:
            all_detections.extend(detections)
            print(f"Page {page_count}: Found {len(detections)} detections")
        
        # Check for truncation and get next URL
        next_url = handle_truncation(xml_response)
        
        if not next_url:
            break
            
        page_count += 1
    
    return all_detections

def main():
    # Validate configuration
    if USERNAME == 'your_username' or PASSWORD == 'your_password':
        print("ERROR: Please update USERNAME and PASSWORD in the script configuration.")
        return
    
    print("Starting Qualys VM Detection data fetch...")
    
    # Fetch all detections (handling pagination)
    all_detections = fetch_all_detections()
    
    if not all_detections:
        print("No detections found.")
        return
    
    print(f"Total detections found: {len(all_detections)}")
    save_to_csv(all_detections)
    print("Data export completed successfully!")

if __name__ == '__main__':
    main()