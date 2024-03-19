import zipfile

def unzip(archive_path, extract_path, password=None):
  """
  Unpacks the specified archive into the given directory.

  :param archive_path: The path to the archive to be unpacked.
  :param extract_to_folder: The directory where the files will be unpacked.
  :param password: Optional password
  """
  try:
    with zipfile.ZipFile(archive_path, 'r') as zip_ref:
      if zip_ref.namelist() and zip_ref.getinfo(zip_ref.namelist()[0]).flag_bits & 0x1:
        if password is not None:
          zip_ref.setpassword(password.encode()) 
        else:
          raise ValueError("Archive is encrypted, but no password was provided.")
           
      zip_ref.extractall(extract_path)
    print(f"Files extracted to {extract_path}")
  except zipfile.BadZipFile:
    print("Error: The file is not a zip file or it is corrupted.")
  except Exception as e:
    print(f"An error occurred: {e}") 