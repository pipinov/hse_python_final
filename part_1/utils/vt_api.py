import requests
import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv('VT_API_KEY')

headers = {
  "x-apikey": VT_API_KEY
}

def upload_file(file_path):
  """
    Sends a file for scanning to VirusTotal and returns the results.

    :param file_path: The path to the file to be scanned.
    :return: JSON response from VirusTotal or None in case of an error.
  """
  with open(file_path, 'rb') as file:
    files = {"file": (os.path.basename(file_path), file)}
    response = requests.post('https://www.virustotal.com/api/v3/files', headers=headers, files=files)

    if response.status_code == 200:
      return response.json()
    else:
      print(f"Error scanning {file_path}: {response.text}")
      return None

def get_scan_results(analysis_id):
  """
  Get the analysis results of a file from VirusTotal.

  :param analysis_id: The ID of the analysis.
  :return: JSON response from VirusTotal or None in case of an error.
  """
  url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
  response = requests.get(url, headers=headers)
  
  if response.status_code == 200:
    return response.json()
  else:
    print(f"Error retrieving scan results for analysis ID {analysis_id}: {response.text}")
    return None

def get_sandbox_report(file_hash):
  """
  Get the sandbox report for a file from VirusTotal.

  :param file_hash: The SHA256 hash of the file for which to retrieve the sandbox report.
  :param api_key: Your VirusTotal API key.
  :return: The sandbox report in JSON format if available, or None if the report is not available or if there was an error.
  """
  url = f"https://www.virustotal.com/api/v3/files/{file_hash}/behaviour_summary"
  response = requests.get(url, headers=headers)
  
  if response.status_code == 200:
    return response.json()
  else:
    print(f"Failed to fetch sandbox report for hash {file_hash}. Status code: {response.status_code}")
    return None