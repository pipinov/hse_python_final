import json
import os
from utils.vulnaris_api import search_vulnerabilities

script_dir = os.path.dirname(os.path.abspath(__file__))

LOGS_DIRECTORY = os.path.join(script_dir, "logs")
REPORT_DIRECTORY = os.path.join(script_dir, "reports")

def check_directory(directory):
  if not os.path.exists(directory):
    os.makedirs(directory)

def save_to_file(directory, filename, data, is_json=True):
  check_directory(directory)
  filepath = os.path.join(directory, filename.replace(" ", "_"))
    
  with open(filepath, "w", encoding="utf-8") as file:
    if is_json:
      json.dump(data, file, ensure_ascii=False, indent=4)
    else:
      file.write(data)

def format_report(program, version, report):
  if report["result"] == "warning":
    return f"No vulnerabilities found for {program} version {version}\n"
  elif report["result"] == "OK":
    vulnerabilities_info = [f"Vulnerabilities found for {program} version {version}:\n"]

    for item in report["data"]["search"]:
      cve_list = ", ".join(item["_source"]["cvelist"])
      title = item["_source"].get("title", "-")
      href = item["_source"].get("href", "-")
      vulnerabilities_info.append(f"{cve_list}\nTITLE: {title}\nHREF: {href}\n\n")
    return "".join(vulnerabilities_info)
  else:
      return "An error occurred while fetching data.\n"

def analyze(software_list): 
  for software in software_list:
    program = software["Program"]
    version = software["Version"]
    print(f"Analyzing {program} {version}...")
    result = search_vulnerabilities(program, version)

    report_content = format_report(program, version, result)
    save_to_file(REPORT_DIRECTORY, f"{program}.txt", report_content, is_json=False)
    save_to_file(LOGS_DIRECTORY, f"{program}.json", result)

def main():
  software_list = [
    {"Program": "LibreOffice", "Version": "6.0.7"},
    {"Program": "7zip", "Version": "18.05"},
    {"Program": "Adobe Reader", "Version": "2018.011.20035"},
    {"Program": "nginx", "Version": "1.14.0"},
    {"Program": "Apache HTTP Server", "Version": "2.4.29"},
    {"Program": "DjVu Reader", "Version": "2.0.0.27"},
    {"Program": "Wireshark", "Version": "2.6.1"},
    {"Program": "Notepad++", "Version": "7.5.6"},
    {"Program": "Google Chrome", "Version": "68.0.3440.106"},
    {"Program": "Mozilla Firefox", "Version": "61.0.1"} 
  ] 

  analyze(software_list)

if __name__ == "__main__":
  main()