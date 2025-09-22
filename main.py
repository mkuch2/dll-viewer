#!/usr/bin/env python3
import argparse
import os
import psutil
import sys
import subprocess
import time
import re
import hashlib
import csv


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

def get_pid_from_filepath(filepath):
    """
    Finds the PID of a process that has the given filepath open.

    Args:
        filepath (str): The absolute path to the file.

    Returns:
        int or None: The PID of the process if found, otherwise None.
    """
    absolute_filepath = os.path.abspath(filepath)
    for proc in psutil.process_iter(['pid', 'open_files']):
        try:
            for opened_file in proc.open_files():
                if opened_file.path == absolute_filepath:
                    return proc.pid
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Handle cases where the process no longer exists or access is denied
            continue
    return None

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

  print("DLL File Names: ")
  print("-" * 80)
  print(dll_filenames)

  print(".dll file hashes:")
  print("-" * 80)
  for dll in dll_files:
     print(get_file_hash(dll))
   
   

def main():

  parser = argparse.ArgumentParser()

  #Select method for process selection, mutually exclusive
  group = parser.add_mutually_exclusive_group(required = True)
  group.add_argument("-p", "--pid", help="pid of process to inspect", type=int)
  group.add_argument("-P", "--path", help="absolute path of process to inspect e.g 'chrome.exe", \
                       type = str)
  group.add_argument("-e", "--execute", help="absolute path to file that will be executed", type = str)

  parser.add_argument("-d", "--duration", help="Duration to execute a program \
                      Used only with -e. Do not set if you do not want to set " \
                      "a duration limit", type=int)

  args = parser.parse_args()

  # Get process by PID
  if args.pid:
     pid = args.pid
   
  # Get process by name
  if args.path:
     pid = get_pid_from_filepath(args.path)
     

  # Execute process
  if args.execute:
     file_path = args.execute
     if not os.path.exists(file_path):
        print(f"Executable not found at '{file_path}", file=sys.stderr)
        sys.exit(1)
     
     f_name = os.path.basename(file_path)
     try:
        if args.duration:
           # placeholder for duration-limited execution
           print(f"Launching '{f_name}' with {args.duration}s timeout")
           subp = subprocess.run([file_path], timeout=int(args.duration))
        else:
           print(f"Launching '{file_path}'")
           # shell=True to resolve symbolic links
           subp = subprocess.Popen(f'start \"\" \"{file_path}\"', shell=True)

           # Give process time to start
           time.sleep(1)
       
        # Get psutil process object from basename
        # Because we are using shell=True, we can't get the pid from Popen
        pid = get_pid_from_filepath(file_path)
     except subprocess.CalledProcessError as e:
        print(f"Error opening executable at '{file_path}'", file=sys.stderr)
        sys.exit(1)
     except psutil.NoSuchProcess as e:
        print(f"Error finding process with PID {subp.pid}", file=sys.stderr)
        sys.exit(1)
     except psutil.AccessDenied as e:
        print(f"Access denied to file {file_path}", file=sys.stderr)
        sys.exit(1)
  elif args.duration:
     print(f"Duration flag must be used in conjunction with -e", file=sys.stderr)
     sys.exit(1)

  # Get Process object 
  process = psutil.Process(pid)
  get_process_info(process)


if __name__ == "__main__":
  main()
    



