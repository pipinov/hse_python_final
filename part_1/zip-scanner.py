import os
import argparse
import time

from utils.zip import unzip
from utils.vt_api import upload_file, get_scan_results, get_sandbox_report
from utils.reports import generate_table_report, get_detected_anriviruses, analyze_antiviruses, behavior_info, dns_lookups

script_dir = os.path.dirname(os.path.abspath(__file__))
QUARANTINE_DIRECTORY = os.path.join(script_dir, 'quarantine')

def unpack_archive(archive_path, extract_to_folder, archive_password=None):
  unzip(archive_path, extract_to_folder, archive_password)

def upload_files(directory):
  analysis_ids = []

  for root, dirs, files in os.walk(directory):
    for filename in files:
      file_path = os.path.join(root, filename)
      upload_result = upload_file(file_path)

      if upload_result:
        analysis_id = upload_result['data']['id']
        analysis_ids.append(analysis_id)
        print(f"Uploaded {filename} successfully. Analysis ID: {analysis_id}")
      else:
        print(f"Failed to upload {filename}")
  
  return analysis_ids

def check_scan_results(analysis_ids):
  for analysis_id in analysis_ids:
    while True:
      scan_results = get_scan_results(analysis_id)
      if scan_results and scan_results['data']['attributes']['status'] == 'completed':
        return scan_results
      else:
        print(f"Results for {analysis_id} are not ready yet. Retrying in 15 seconds...")
        time.sleep(15)

def check_sandbox_report(hash_id):
  while True:
    sandbox_report = get_sandbox_report(hash_id)

    if sandbox_report and 'data' in sandbox_report:
      print(f"Report for {hash_id} is ready.")
      return sandbox_report
    else:
      print(f"Report for {hash_id} is not ready yet. Retrying in 15 seconds...")
      time.sleep(15)

def main():
  parser = argparse.ArgumentParser(description="Unpack and scan files from an archive using VirusTotal API") 
  parser.add_argument("--source", dest="source", required=True, help="Path to the archive file")
  parser.add_argument("--password", dest="password", help="Optional password for the archive")
  args = parser.parse_args()

  # 1. Unpack archive
  print(f"Unzipping archive: {args.source}")
  unpack_archive(args.source, QUARANTINE_DIRECTORY, args.password)

  # 2. Upload files to VirusTotal and store the IDs for analysis
  print(f"Uploading files from directory {QUARANTINE_DIRECTORY}")
  analysis_ids = upload_files(QUARANTINE_DIRECTORY)

  # 3. Get scan results from VirusTotals by ids
  print("Getting scan results...")
  analysis_data = check_scan_results(analysis_ids)
  results = analysis_data['data']['attributes']['results']
  file_hash = analysis_data['meta']['file_info']['sha256']

  # 4. Display table report
  generate_table_report(results)

  # 5. Display detected antiviruses
  get_detected_anriviruses(results)
  
  # 6. Display the report for the specified antiviruses
  analyze_antiviruses(results, ['Fortinet', 'McAfee', 'Yandex', 'Sophos'])

  # 7. Get sandbox report
  print(f"Getting sandbox report for hash {file_hash}...")
  sandbox_report = check_sandbox_report(file_hash)
  behavior_info(sandbox_report['data'])
  
  # 8. Check dns_lookups
  dns_lookups(sandbox_report['data'])


if __name__ == '__main__':
  main()