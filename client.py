from flask import Flask, render_template, jsonify, request
import requests
import glob
import json
import logging
from datetime import datetime
from typing import Dict, Optional

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('nvd_data.log'),
        logging.StreamHandler()
    ]
)

class NVDClient:
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.output_file = f"nvd_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        logging.info("NVD Client initialized")

    def get_cve(self, cve_id: str) -> Dict:
        params = {"cveId": cve_id}
        response = requests.get(self.base_url, params=params)
        response.raise_for_status()
        data = response.json()
        self._save_to_file(data)
        return data

    def search_vulnerabilities(self, keyword: str) -> Dict:
        params = {"keywordSearch": keyword}
        response = requests.get(self.base_url, params=params)
        response.raise_for_status()
        data = response.json()
        self._save_to_file(data)
        return data

    def _save_to_file(self, data: Dict):
        with open(self.output_file, 'w') as f:
            json.dump(data, f, indent=4)
        logging.info(f"Data saved to {self.output_file}")

app = Flask(__name__)
nvd_client = NVDClient()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/search')
def search():
    cve_id = request.args.get('cve_id')
    keyword = request.args.get('keyword')

    if cve_id:
        return jsonify(nvd_client.get_cve(cve_id))
    elif keyword:
        return jsonify(nvd_client.search_vulnerabilities(keyword=keyword))

    return jsonify({'error': 'No search parameters provided'})

@app.route('/api/local-search')
def local_search():
    search_term = request.args.get('term', '').lower()
    results = []

    for json_file in glob.glob('*.json'):
        with open(json_file, 'r') as f:
            data = json.load(f)
            if search_term in json.dumps(data).lower():
                results.extend(data.get('vulnerabilities', []))

    return jsonify({'vulnerabilities': results})

if __name__ == '__main__':
    app.run(debug=True)
import requests
import json
import logging
from datetime import datetime
from typing import Dict, Optional

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('nvd_data.log'),
        logging.StreamHandler()
    ]
)

class NVDFetcher:
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.output_file = f"nvd_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        logging.info("NVD Fetcher initialized")

    def fetch_vulnerabilities(self, cve_id: Optional[str] = None, keyword: Optional[str] = None):
        params = {}
        if cve_id:
            params['cveId'] = cve_id
        if keyword:
            params['keywordSearch'] = keyword

        logging.info(f"Fetching data with parameters: {params}")

        try:
            response = requests.get(self.base_url, params=params)
            response.raise_for_status()
            data = response.json()

            # Save to file
            with open(self.output_file, 'w') as f:
                json.dump(data, f, indent=4)

            logging.info(f"Data saved to {self.output_file}")
            return data

        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching data: {e}")
            raise

def main():
    fetcher = NVDFetcher()

    print("\nNVD Data Fetcher")
    print("1. Search by CVE ID")
    print("2. Search by keyword")
    choice = input("Select option (1-2): ")

    if choice == '1':
        cve_id = input("Enter CVE ID (e.g., CVE-2021-44228): ")
        data = fetcher.fetch_vulnerabilities(cve_id=cve_id)
    elif choice == '2':
        keyword = input("Enter search keyword: ")
        data = fetcher.fetch_vulnerabilities(keyword=keyword)
    else:
        logging.error("Invalid choice")
        return

    # Display summary of results
    vulnerabilities = data.get('vulnerabilities', [])
    print(f"\nFound {len(vulnerabilities)} vulnerabilities")

    for vuln in vulnerabilities:
        cve = vuln.get('cve', {})
        print(f"\nCVE ID: {cve.get('id')}")
        print(f"Published: {cve.get('published')}")
        print(f"Description: {cve.get('descriptions', [{}])[0].get('value', 'No description available')}")
        print("-" * 80)

if __name__ == "__main__":
    main()
