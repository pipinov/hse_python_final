import requests
import os
from dotenv import load_dotenv

load_dotenv()

VULNARIS_API_KEY = os.getenv('VULNARIS_API_KEY')
VULNARIS_URL = os.getenv('VULNARIS_URL')

def search_vulnerabilities(software, version):
  """
  Searches for vulnerabilities of a specific software version using the Vulners API.

  Parameters:
  - software (str): The name of the software for which to search vulnerabilities.
  - version (str): The version of the software.

  Returns:
  - dict: A dictionary containing the JSON response from the Vulners API if the request is successful.
  - None: If the request fails (e.g., due to a network issue or an invalid API response), the function returns None.
  """
  params = {
    "apiKey": VULNARIS_API_KEY,
    "software": software,
    "version": version,
    "type": 'software',
    "maxVulnerabilities": 100
  }

  response = requests.get(VULNARIS_URL, params=params)

  if response.status_code == 200:
      return response.json()
  else:
      return None