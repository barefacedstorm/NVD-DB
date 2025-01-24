import glob

from flask import Flask, render_template, jsonify, request
import requests
import json
import logging
from datetime import datetime
import threading
import time
from typing import Dict
import psycopg2
from psycopg2.extras import Json
import os

# Constants
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 100  # Increased for better results

# Database configuration
DB_CONFIG = {
    "dbname": "nvd_db",
    "user": "postgres",
    "password": "postgres",
    "host": "localhost",
    "port": "5432"
}

# Create json directory
os.makedirs('json', exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('nvd.log'), logging.StreamHandler()]
)


class NVDClient:
    def __init__(self):
        self.headers = {
            "User-Agent": "CVE-Search-Tool/1.0",
            "Content-Type": "application/json"
        }
        self.db_conn = psycopg2.connect(**DB_CONFIG)
        self._init_db()
        logging.info("NVD Client initialized")

    def _init_db(self):
        with self.db_conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id SERIAL PRIMARY KEY,
                    cve_id TEXT UNIQUE,
                    data JSONB,
                    severity TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            self.db_conn.commit()
    def _check_existing_cves(self, query: str) -> set:
        """Get existing CVE IDs only for exact CVE matches"""
        existing_cves = set()
        if query and query.startswith('CVE-'):
            json_files = glob.glob('json/*.json')
            for file in json_files:
                try:
                    with open(file, 'r') as f:
                        data = json.load(f)
                        for vuln in data.get('vulnerabilities', []):
                            if vuln['cve']['id'] == query:
                                existing_cves.add(vuln['cve']['id'])
                except json.JSONDecodeError:
                    continue
        return existing_cves

    def search(self, query: str = None, page: int = 0) -> Dict:
        params = {
            "resultsPerPage": PAGE_SIZE,
            "startIndex": page * PAGE_SIZE
        }

        if query and query.startswith('CVE-'):
            params["cveId"] = query
            existing_cves = self._check_existing_cves(query)
        elif query:
            params["keywordSearch"] = query
            existing_cves = set()  # No filtering for keywords

        response = requests.get(BASE_URL, params=params, headers=self.headers)
        response.raise_for_status()
        data = response.json()

        if query and query.startswith('CVE-'):
            filtered_vulns = [
                vuln for vuln in data.get('vulnerabilities', [])
                if vuln['cve']['id'] not in existing_cves
            ]
            data['vulnerabilities'] = filtered_vulns

        self._save_to_db(data)
        self._save_to_json(data, query or 'latest')
        return data

    def _save_to_db(self, data: Dict):
        with self.db_conn.cursor() as cur:
            for vuln in data.get('vulnerabilities', []):
                severity = vuln.get('cve', {}).get('metrics', {}).get('cvssMetrics', [{}])[0].get('severity', 'UNKNOWN')
                cur.execute("""
                    INSERT INTO vulnerabilities (cve_id, data, severity)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (cve_id) DO UPDATE 
                    SET data = %s, severity = %s
                """, (
                    vuln['cve']['id'],
                    Json(vuln),
                    severity,
                    Json(vuln),
                    severity
                ))
            self.db_conn.commit()

    def _save_to_json(self, data: Dict, query: str):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"json/{query}_{timestamp}.json"

        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        logging.info(f"Results saved to {filename}")

    def search_local_json(self, term: str) -> Dict:
        """Search through stored JSON data in PostgreSQL"""
        with self.db_conn.cursor() as cur:
            query = """
                SELECT DISTINCT ON (cve_id) data 
                FROM vulnerabilities 
                WHERE 
                    data::text ILIKE %s OR
                    cve_id ILIKE %s
                ORDER BY cve_id, created_at DESC
            """
            search_term = f'%{term}%'
            cur.execute(query, (search_term, search_term))
            results = cur.fetchall()

            return {
                'vulnerabilities': [row[0] for row in results],
                'totalResults': len(results)
            }


app = Flask(__name__)
client = NVDClient()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/search')
def search():
    query = request.args.get('query')
    page = int(request.args.get('page', 0))
    try:
        data = client.search(query, page)
        return jsonify(data)
    except Exception as e:
        logging.error(f"Search error: {e}")
        return jsonify({'error': str(e), 'vulnerabilities': []}), 500


@app.route('/api/local-search')
def local_search():
    term = request.args.get('term', '').lower()
    try:
        results = client.search_local_json(term)
        return jsonify(results)
    except Exception as e:
        logging.error(f"Local search error: {e}")
        return jsonify({'vulnerabilities': [], 'totalResults': 0}), 500

if __name__ == '__main__':
    app.run(debug=True)
