from tabulate import tabulate

def generate_table_report(scan_results):
  headers = ["Name", "Method", "Engine Name", "Engine Version", "Engine Update", "Category", "Result"]
  table_data = []

  for name, entry in scan_results.items():
    method = entry["method"]
    engine_name = entry["engine_name"]
    engine_version = entry["engine_version"]
    engine_update = entry["engine_update"]
    category = entry["category"]
    result = entry["result"]

    table_data.append([name, method, engine_name, engine_version, engine_update, category, result])

  print(tabulate(table_data, headers=headers, tablefmt="grid"))
  
def get_detected_anriviruses(scan_results):
  detected_antiviruses = []

  for antivirus, details in scan_results.items():
    if details["result"] != 0 and details["category"] == "malicious":
      detected_antiviruses.append(antivirus)

  print(", ".join(detected_antiviruses))

  
def analyze_antiviruses(scan_results, antiviruses):
  result = []

  for antivirus in antiviruses:
    detected = "Not Detected"
    if scan_results.get(antivirus) and scan_results[antivirus]["category"] == "malicious":
      detected = scan_results[antivirus]["result"]

      result.append([antivirus, detected])

  print(tabulate(result, headers=["Antivirus", "Detection"]))

def behavior_info(behavior_data):
  report = ""

  if "mitre_attack_techniques" in behavior_data:
    report += "MITRE ATT&CK techniques:\n"
    for technique in behavior_data["mitre_attack_techniques"]:
      report += f"- {technique["signature_description"]}\n"

  if "tags" in behavior_data:
    report += "\nTags:\n"
    for tag in behavior_data["tags"]:
      report += f"- {tag}\n"

  if "attack_techniques" in behavior_data:
    report += "\nAttack techniques:\n"
    for technique in behavior_data["attack_techniques"]:
      report += f"- {technique}\n"

  report += "\nKeys in behavior data:\n"

  for key in behavior_data.keys():
    report += f"- {key}\n"

  print(report)

def dns_lookups(behavior_data):
  domains_ips = set() 

  # Извлечение информации из dns_lookups
  if "dns_lookups" in behavior_data:
    for dns_lookup in behavior_data["dns_lookups"]:
      if "hostname" in dns_lookup:
        domains_ips.add(dns_lookup["hostname"])
      if "resolved_ips" in dns_lookup:
        for ip in dns_lookup["resolved_ips"]:
          domains_ips.add(ip)

  print(list(domains_ips))
