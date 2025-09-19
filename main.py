#!/usr/bin/env python3
import argparse
import os
import psutil
import sys
import subprocess
import time
import re


def get_process(pid: int) -> psutil.Process:
  return psutil.Process(pid)

def main():

  parser = argparse.ArgumentParser()

  parser.add_argument("pid", help="pid of process to inspect", type=int)

  args = parser.parse_args()

  pid = args.pid

  if not psutil.pid_exists(pid):
    sys.exit(f"PID {pid} does not exist")

  # Get process from PID
  process = psutil.Process(pid)

  # Get process's memory maps
  memory_maps = str(process.memory_maps())

  dll_files = re.findall(r"\'(.*?\.dll)\'", memory_maps)

  # Get filename without path
  dll_filenames = [name.split('\\')[-1] for name in dll_files]

  print(dll_filenames)



if __name__ == "__main__":
  main()
    

