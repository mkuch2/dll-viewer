#!/usr/bin/env python3
import argparse
import os
import psutil
import sys
import subprocess
import time
import re
import hashlib


def get_file_hash(file_path, algorithm='sha256', chunk_size=8192):
    """
    Calculates the hash of a file using the specified algorithm.

    Args:
        file_path (str): The path to the file.
        algorithm (str): The hashing algorithm to use (e.g., 'md5', 'sha1', 'sha256').
        chunk_size (int): The size of chunks to read from the file.

    Returns:
        str: The hexadecimal representation of the file's hash.
    """
    hasher = hashlib.new(algorithm)
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()

def get_process_info(process: psutil.Process):
  p_attr = process.as_dict(attrs=['name', 'username', 'exe', 'cmdline', 'create_time'])

  print("Process attributes:")
  print("-" * 80)
  for key, value in p_attr.items():
     print (f"{key}: {value}")

  # Get process's memory maps
  memory_maps = str(process.memory_maps())

  # Get DLL file paths
  dll_files = re.findall(r"\'([^']+\.dll)\'", memory_maps)

  print("DLL File Paths: ")
  print("-" * 80)
  print(dll_files)

  # Get filename without path
  dll_filenames = [name.split('\\')[-1] for name in dll_files]

  print("DLL File Paths: ")
  print("-" * 80)
  print(dll_files)

  print(".dll file hashes:")
  print("-" * 80)
  for dll in dll_files:
     print(get_file_hash(dll))
   
   

def main():

  parser = argparse.ArgumentParser()

  parser.add_argument("pid", help="pid of process to inspect", type=int)

  args = parser.parse_args()

  pid = args.pid

  if not psutil.pid_exists(pid):
    sys.exit(f"PID {pid} does not exist")

  # Get process from PID
  process = psutil.Process(pid)

  get_process_info(process)











if __name__ == "__main__":
  main()
    

