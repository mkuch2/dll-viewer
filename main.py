#!/usr/bin/env python3
import argparse
import os
import psutil
import sys
import subprocess
import time


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
  memory_maps = process.memory_maps()

  print(memory_maps)



if __name__ == "__main__":
  main()
    

