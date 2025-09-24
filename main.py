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
import datetime
from typing import List

IDX_P_NAME = 0
IDX_P_USERNAME = 1
IDX_P_EXE = 2
IDX_P_CMDLINE = 3
IDX_P_CREATETIME = 4
IDX_PROCESS = 3


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
    print("Entered get_file_hash")
    hasher = hashlib.new(algorithm)
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()

# def get_pid_from_filepath(filepath):
#     """
#     Finds the PID of a process that has the given filepath open.

#     Args:
#         filepath (str): The absolute path to the file.

#     Returns:
#         int or None: The PID of the process if found, otherwise None.
#     """
#     print("Entered get_pid_from_filepath")
#     absolute_filepath = os.path.abspath(filepath)
#     for proc in psutil.process_iter(['pid', 'open_files']):
#         try:
#             for opened_file in proc.open_files():
#                 if opened_file.path == absolute_filepath:
#                     print(f"Proc id found: {proc.pid}")
#                     return proc.pid
#         except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
#             # Handle cases where the process no longer exists or access is denied
#             continue
#     print("Proc id not found, returning none")
#     return None

def get_process_info(process: psutil.Process):
  print("Entered get_process_info")
  p_attr_dict = process.as_dict(attrs=['name', 'username', 'exe', 'cmdline', 'create_time'], \
                           ad_value="N/A")
  
 
  
  print("Process attributes:")
  print("-" * 80)
  for key, value in p_attr_dict.items():
     print (f"{key}: {value}")
   
  # Convert dict values to list, to include in return list
  p_attr_list = [
     p_attr_dict.get('name'),
     p_attr_dict.get('username'),
     p_attr_dict.get('exe'),
     p_attr_dict.get('cmdline'),
     datetime.datetime.fromtimestamp(p_attr_dict.get('create_time')).strftime("%Y-%m-%d %H:%M:%S")
  ]
  
  monitoring_start_time = time.time()

  dll_files = set()
  previous_dlls = set()
  load_times = {}
  
  # Poll process for loaded dlls
  while(process.is_running()):
    current_poll_time = f"{time.time() - monitoring_start_time:.2f}"
    # Get process's memory maps
    memory_maps = str(process.memory_maps())
    
    # Get DLL file paths
    current_dlls = set(re.findall(r"\'([^']+\.dll)\'", memory_maps))
    
    # Check for newly loaded DLLs
    new_dlls = current_dlls - previous_dlls
    for dll_file in new_dlls:
       load_times[dll_file] = current_poll_time
       print(f"New DLL {dll_file} loaded at poll time {current_poll_time}", flush=True)



    # Update sets    
    dll_files.update(current_dlls)
    previous_dlls = current_dlls

    time.sleep(1)
  
  dll_files_list = list(dll_files)
  print("DLL File Paths: ")
  print("-" * 80)
  print(dll_files_list)

    # Correlate dll load times to list order
  dll_relative_times = [load_times.get(dll, "0.0") for dll in dll_files_list]
  
  # Get filename without path
  dll_filenames = [os.path.basename(name) for name in dll_files]

  print("DLL File Names: ")
  print("-" * 80)
  print(dll_filenames)

  # Get hashes for each DLL
  print(".dll file hashes:")
  print("-" * 80)
  for dll in dll_files:
   print(get_file_hash(dll))



  return [dll_files_list, dll_filenames, dll_relative_times, p_attr_list]
   
def create_csv_file(pid: str, data: List[List[str]]):
   print("Entered create_csv_file")
   with open(f'{pid}.csv', mode='x', newline='') as csvfile:
      writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)

      # Headers
      writer.writerow(["Process name", "Username",  "Process path", \
                       "Command line", "Creation time", "DLL Path", "DLL Name", \
                       "Time loaded"])
      
      
      rows = []
      item_count = len(data[0])
      index = 0
      
      # Initialize formatted rows
      while index < item_count:
         rows.append([data[IDX_PROCESS][IDX_P_NAME], data[IDX_PROCESS][IDX_P_USERNAME],
                      data[IDX_PROCESS][IDX_P_EXE], data[IDX_PROCESS][IDX_P_CMDLINE],
                      data[IDX_PROCESS][IDX_P_CREATETIME], data[0][index], data[1][index], data[2][index]])
         index += 1

      writer.writerows(rows)
   
   print(f"{pid}.csv successfully created")

def main():

  print("Entered main")
  parser = argparse.ArgumentParser()

  #Select method for process selection, mutually exclusive
  group = parser.add_mutually_exclusive_group(required = True)
  group.add_argument("-p", "--pid", help="pid of process to inspect", type=int)
#   group.add_argument("-P", "--path", help="absolute path of process to inspect e.g 'chrome.exe", \
#                        type = str)
#   group.add_argument("-e", "--execute", help="absolute path to file that will be executed", type = str)

#   parser.add_argument("-d", "--duration", help="Duration to execute a program \
#                       Used only with -e. Do not set if you do not want to set " \
#                       "a duration limit", type=int)
  
  parser.add_argument("--csv", help="output data to csv file in current directory", \
                      action='store_true')

  args = parser.parse_args()
  print("After parse args")

  # Get process by PID
  if args.pid:
     print("args.pid")
     pid = args.pid
   
  # Get process by name
#   if args.path:
#      print("args.path")
#      pid = get_pid_from_filepath(args.path)
     

#   print("Right before args.execute")
#   # Execute process
#   if args.execute:
#      print("Right after args.execute")
#      file_path = args.execute
#      if not os.path.exists(file_path):
#         print(f"Executable not found at '{file_path}", file=sys.stderr)
#         sys.exit(1)
     
#      f_name = os.path.basename(file_path)
#      try:
#         if args.duration:
#            # placeholder for duration-limited execution
#            print(f"Launching '{f_name}' with {args.duration}s timeout")
#            subp = subprocess.run([file_path], timeout=int(args.duration))
#         else:
#            print(f"Launching '{file_path}'")
#            # shell=True to resolve symbolic links
#            subp = subprocess.Popen(f'start \"\" \"{file_path}\"', shell=True)

#            # Give process time to start
#            time.sleep(1)
       
#         # Get psutil process object from basename
#         # Because we are using shell=True, we can't get the pid from Popen
#         pid = get_pid_from_filepath(file_path)
#         print(f"After get_pid_from_filepath, pid is: {pid}")
#      except subprocess.CalledProcessError as e:
#         print(f"Error opening executable at '{file_path}'", file=sys.stderr)
#         sys.exit(1)
#      except psutil.NoSuchProcess as e:
#         print(f"Error finding process with PID {subp.pid}", file=sys.stderr)
#         sys.exit(1)
#      except psutil.AccessDenied as e:
#         print(f"Access denied to file {file_path}", file=sys.stderr)
#         sys.exit(1)
#   elif args.duration:
#      print(f"Duration flag must be used in conjunction with -e", file=sys.stderr)
#      sys.exit(1)

  # Get Process object 
  process = psutil.Process(pid)
  data = get_process_info(process)

  if args.csv:
     print("args.csv true")
     create_csv_file(pid, data)


if __name__ == "__main__":
  print("Running main")
  main()
    



