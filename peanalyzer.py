import argparse
import csv
import json
import datetime
import hashlib
import os
import sys

import pefile
from collections import defaultdict

# Condition of sections (e.g writeable when it shouldn't be)
def get_sections_info(pe: pefile.PE):
  try:
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_READ = 0x40000000
    IMAGE_SCN_MEM_WRITE = 0x80000000
    
    sec_info = {}

    if not hasattr(pe, 'sections') or not pe.sections:
      print("Warning: No sections found in PE file")
      return {}

    for section in pe.sections:
      try:
        # Decode byte to string and strip null bytes to get just section name
        section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
        
        writeable = str(bool(section.Characteristics & IMAGE_SCN_MEM_WRITE))
        executable = str(bool(section.Characteristics & IMAGE_SCN_MEM_EXECUTE))
        readable = str(bool(section.Characteristics & IMAGE_SCN_MEM_READ))

        # Compute section hashes; pefile provides helpers but not guaranteed
        hashes = {}
        try:
          hashes['sha256'] = section.get_hash_sha256()
        except Exception:
          try:
            hashes['sha256'] = hashlib.sha256(section.get_data()).hexdigest()
          except Exception:
            hashes['sha256'] = None
        try:
          hashes['sha1'] = section.get_hash_sha1()
        except Exception:
          try:
            hashes['sha1'] = hashlib.sha1(section.get_data()).hexdigest()
          except Exception:
            hashes['sha1'] = None
        try:
          hashes['md5'] = section.get_hash_md5()
        except Exception:
          try:
            hashes['md5'] = hashlib.md5(section.get_data()).hexdigest()
          except Exception:
            hashes['md5'] = None

        sec_info[section_name] = {
          "hashes": hashes,
          "entropy": section.get_entropy(),
          "characteristics": ["R:" + readable, "W:" + writeable, "X:" + executable], 
          "virtual_size": section.Misc_VirtualSize,
          "sizeofrawdata": section.SizeOfRawData
        }
      except Exception as e:
        print(f"Error processing section {section}: {e}", file=sys.stderr)
        continue

    return sec_info
    
  except Exception as e:
    print(f"Error in get_sections_info: {e}", file=sys.stderr)
    return {}

# Get stub
def get_stub(pe: pefile.PE):
  try:
    # RVA of stub start
    stub_start = 0x40

    # Treat any rich headers as part of stub :P
    if not hasattr(pe, 'DOS_HEADER') or not hasattr(pe.DOS_HEADER, 'e_lfanew'):
      print("Warning: DOS header not found or incomplete")
      return None
      
    stub_end = pe.DOS_HEADER.e_lfanew

    if stub_end <= stub_start:
      print("Warning: Invalid stub boundaries")
      return None

    # Get raw stub bytes and return hex representation
    stub_data = pe.get_data(stub_start, stub_end - stub_start)
    if stub_data:
      try:
        return stub_data.hex()
      except Exception:
        return str(stub_data)
    return None
    
  except Exception as e:
    print(f"Error in get_stub: {e}", file=sys.stderr)
    return None

# TimeDateStamp in IMAGE_FILE_HEADER to check when file was created
def get_timedatestamp(pe: pefile.PE):
  try:
    # Get UNIX timestamp
    if not hasattr(pe, 'FILE_HEADER') or not hasattr(pe.FILE_HEADER, 'TimeDateStamp'):
      print("Warning: FILE_HEADER or TimeDateStamp not found")
      return None
      
    tds = pe.FILE_HEADER.TimeDateStamp

    # Convert to date (YYYY-MM-DD HH:MM:SS)
    date = datetime.datetime.fromtimestamp(tds)
    return date
    
  except (ValueError, OSError) as e:
    print(f"Error converting timestamp: {e}", file=sys.stderr)
    return None
  except Exception as e:
    print(f"Error in get_timedatestamp: {e}", file=sys.stderr)
    return None

def get_imports(pe: pefile.PE):
  try:
    # Check if imports directory exists
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
      print("No import directory found")
      return None
      
    # List of ImportDescData instances
    import_table = pe.DIRECTORY_ENTRY_IMPORT

    imp_dlls_and_symbols = defaultdict(list)
    # For each ImportDescData
    for imp_desc in import_table:
      try:
        if not hasattr(imp_desc, 'dll') or imp_desc.dll is None:
          print("Warning: Import descriptor has no DLL name")
          continue
          
        imp_desc_name = imp_desc.dll.decode('utf-8', errors='ignore')
        print("Name: " + imp_desc_name)

        # List of ImportData instances
        if not hasattr(imp_desc, 'imports'):
          print(f"Warning: No imports found for {imp_desc_name}")
          continue
          
        imports = imp_desc.imports

        for imp_data in imports:
          try:
            if imp_data.name is None:
              # Get ordinal if DLL not imported by name
              imp_data_name = str(imp_data.ordinal)
            else: 
              # Else get name
              imp_data_name = imp_data.name.decode('utf-8', errors='ignore')

            print("Imported symbols: " + imp_data_name)
            imp_dlls_and_symbols[imp_desc_name].append(imp_data_name)
          except Exception as e:
            print(f"Error processing import data: {e}", file=sys.stderr)
            continue
            
      except Exception as e:
        print(f"Error processing import descriptor: {e}", file=sys.stderr)
        continue
        
    return dict(imp_dlls_and_symbols)
    
  except Exception as e:
    print(f"Error in get_imports: {e}", file=sys.stderr)
    return None

def get_exports(pe: pefile.PE):
  try:
    # Check if exports directory exists
    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
      print("No export directory found")
      return None

    # ExportDirData instance
    exp_table = pe.DIRECTORY_ENTRY_EXPORT

    # List of ExportData instances
    if not hasattr(exp_table, 'symbols'):
      print("No export symbols found")
      return None

    exp_symbols = exp_table.symbols

    # name : (addr, forwarder)
    symbols = {}
    for symbol in exp_symbols:
      try:
        if symbol.name is None:
          # Get ordinal if symbol has no name
          smbl_name = str(symbol.ordinal)
        else:
          # Else get name
          smbl_name = symbol.name.decode('utf-8', errors='ignore')

        smbl_addr = symbol.address
        smbl_forwarder = symbol.forwarder

        symbols[smbl_name] = (smbl_addr, smbl_forwarder)

        print(f"Symbol name: {smbl_name}")
        print(f"Symbol address: {smbl_addr}")
        print(f"Symbol forwarder: {smbl_forwarder}")
      except Exception as e:
        print(f"Error processing export symbol: {e}", file=sys.stderr)
        continue

    return symbols
  except Exception as e:
    print(f"Error in get_exports: {e}", file=sys.stderr)
    return None

# TLS callbacks - threads set to run code before entry point is ran
def get_tls_callbacks(pe: pefile.PE):
  try:
    # No TLS Directory found
    if not hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
      print("No TLS directory found")
      return None

    # IMAGE_TLS_DIRECTORY struct
    tls_dir = pe.DIRECTORY_ENTRY_TLS.struct

    addr_of_callbacks = getattr(tls_dir, 'AddressOfCallBacks', None)
    if not addr_of_callbacks:
      print("PE has no TLS callbacks")
      return None

    # Determine pointer size (32 vs 64-bit)
    if not hasattr(pe, 'OPTIONAL_HEADER') or not hasattr(pe.OPTIONAL_HEADER, 'Magic'):
      print("Error: Cannot determine PE architecture")
      return None

    ptr_size = 8 if hex(pe.OPTIONAL_HEADER.Magic) == '0x20b' else 4

    imagebase = getattr(pe.OPTIONAL_HEADER, 'ImageBase', None)
    size_of_image = getattr(pe.OPTIONAL_HEADER, 'SizeOfImage', None)

    # Normalize AddressOfCallBacks to an RVA. AddressOfCallBacks can be either an RVA
    # or a VA depending on how it was obtained; prefer treating values within the image
    # range as VA and subtract ImageBase.
    if imagebase and size_of_image and (addr_of_callbacks >= imagebase and addr_of_callbacks < imagebase + size_of_image):
      cb_rva = addr_of_callbacks - imagebase
    else:
      cb_rva = addr_of_callbacks

    callbacks = []

    # Loop over the array of pointers (null-terminated)
    while True:
      try:
        # Convert RVA to file offset
        try:
          cb_offset = pe.get_offset_from_rva(cb_rva)
        except Exception as rva_error:
          print(f"Error converting callback RVA to file offset: {rva_error}")
          break

        # Ensure offset within file
        data_len = len(getattr(pe, '__data__', b''))
        if cb_offset is None or cb_offset < 0 or cb_offset >= data_len:
          print(f"Callback offset {cb_offset} out of range (file size {data_len})")
          break

        # Read pointer-sized data from file at cb_offset
        ptr_bytes = pe.get_data(cb_offset, ptr_size)
        if not ptr_bytes or len(ptr_bytes) < ptr_size:
          print(f"Failed to read pointer at offset {cb_offset}")
          break

        callback_addr = int.from_bytes(ptr_bytes, byteorder='little')
        # Null-terminated list: stop on 0
        if callback_addr == 0:
          break

        cb_info = {'address': callback_addr}

        # Try to read some bytes of the callback code (first 128 bytes) if it maps into the file
        if imagebase and size_of_image and callback_addr >= imagebase and callback_addr < imagebase + size_of_image:
          cb_code_rva = callback_addr - imagebase
          try:
            code_offset = pe.get_offset_from_rva(cb_code_rva)
            max_read = min(128, data_len - code_offset)
            if max_read > 0:
              code_bytes = pe.get_data(code_offset, max_read)
              cb_info['data'] = code_bytes
              cb_info['hex'] = code_bytes.hex()
          except Exception as code_err:
            # Non-fatal: include error info but continue
            cb_info['data_error'] = str(code_err)

        callbacks.append(cb_info)
        print(f"TLS Callback #{len(callbacks)}: 0x{callback_addr:x}")

        # Advance to next pointer in the callback array
        cb_rva += ptr_size

      except Exception as e:
        print(f"Error reading TLS callback: {e}", file=sys.stderr)
        break

    if not callbacks:
      print("No TLS callbacks found")
      return None

    print(f"Total TLS callbacks found: {len(callbacks)}")
    return callbacks

  except Exception as e:
    print(f"Error in get_tls_callbacks: {e}", file=sys.stderr)
    return None

# Delay-Load imports - only load DLLs when they are first called, check
# Delay Import Descriptor in Data Directory
def get_delay_imports(pe: pefile.PE):
  try:
    if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
      print("PE has Delay Import Directory entry")

      del_imp_dll_and_smbls = defaultdict(list)

      # Iterate through list of ImportDescData
      for dir_entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
        try:
          if not hasattr(dir_entry, 'dll') or dir_entry.dll is None:
            print("Warning: Delay import entry has no DLL name")
            continue
            
          dll_name = dir_entry.dll.decode('utf-8', errors='ignore')
          print(f"Delayed Imported DLL: {dll_name}")

          # Iterate through dir_entry's ImportData objects
          if hasattr(dir_entry, 'imports'):
            for imp_smbl in dir_entry.imports:
              try:
                if imp_smbl.name is None:
                  imp_smbl_name = str(imp_smbl.ordinal)
                else:  
                  imp_smbl_name = imp_smbl.name.decode('utf-8', errors='ignore')

                print(f"Imported functions: {imp_smbl_name}")
                del_imp_dll_and_smbls[dll_name].append(imp_smbl_name)
              except Exception as e:
                print(f"Error processing delay import symbol: {e}", file=sys.stderr)
                continue
          else:
            print(f"Warning: No imports found for delay-loaded DLL {dll_name}")
            
        except Exception as e:
          print(f"Error processing delay import entry: {e}", file=sys.stderr)
          continue
          
      return dict(del_imp_dll_and_smbls)
    else:
      print("PE does not have delay import directory entry")
      return None
      
  except Exception as e:
    print(f"Error in get_delay_imports: {e}", file=sys.stderr)
    return None
  
# Relocation Table
def get_reloc_data(pe: pefile.PE):
  try:
    if not hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"):
      print("PE file has no Base Relocation Table")
      return None
    
    # List of BaseRelocationData instances
    base_reloc_data = pe.DIRECTORY_ENTRY_BASERELOC

    data_entries = []
    for inst in base_reloc_data:
      try:
        # List of RelocationData instances
        if not hasattr(inst, 'entries'):
          print("Warning: Relocation instance has no entries")
          continue
          
        data = inst.entries

        for entry in data:
          try:
            if hasattr(entry, 'type') and hasattr(entry, 'rva'):
              # Check if entry type is valid
              if entry.type in pefile.relocation_types:
                reloc_type = pefile.relocation_types[entry.type]
              else:
                reloc_type = f"Unknown({entry.type})"
                
              data_entries.append((reloc_type, hex(entry.rva)))
            else:
              print("Warning: Invalid relocation entry")
          except Exception as e:
            print(f"Error processing relocation entry: {e}", file=sys.stderr)
            continue
            
      except Exception as e:
        print(f"Error processing relocation data: {e}", file=sys.stderr)
        continue
    
    return data_entries
    
  except Exception as e:
    print(f"Error in get_reloc_data: {e}", file=sys.stderr)
    return None

def get_pe_info(pe_file_path: str, write_csv: bool = False):
  print(f"Analyzing file: {pe_file_path}")

  # rows for CSV output: list of (category, field, value)
  csv_rows = []

  try:
    # Check if file exists
    if not os.path.exists(pe_file_path):
      print(f"Error: File '{pe_file_path}' does not exist.", file=sys.stderr)
      sys.exit(1)
    
    # Try to parse the PE file
    pe_file = pefile.PE(pe_file_path)
    print("PE file loaded successfully.")
  except pefile.PEFormatError as e:
    print(f"Error: Invalid PE file format - {e}", file=sys.stderr)
    sys.exit(1)
  except PermissionError:
    print(f"Error: Permission denied accessing '{pe_file_path}'", file=sys.stderr)
    sys.exit(1)
  except Exception as e:
    print(f"Error: Failed to load PE file - {e}", file=sys.stderr)
    sys.exit(1)

  try:
    info = get_sections_info(pe_file)
    print("Section info:", info)
    if write_csv and info is not None:
      for sname, sdata in info.items():
        csv_rows.append(("section", "name", sname))
        # include hashes and entropy
        hashes = sdata.get('hashes', {})
        for hname, hval in hashes.items():
          csv_rows.append(("section", f"{sname}.{hname}", hval))
        csv_rows.append(("section", f"{sname}.entropy", sdata.get('entropy')))
  except Exception as e:
    print(f"Error getting section info: {e}", file=sys.stderr)

  try:
    stub = get_stub(pe_file)
    print("Stub data retrieved successfully")
    if write_csv:
      csv_rows.append(("stub", "hex", stub))
  except Exception as e:
    print(f"Error getting stub: {e}", file=sys.stderr)
    
  try:
    timestamp = get_timedatestamp(pe_file)
    print(f"Timestamp: {timestamp}")
    if write_csv:
      csv_rows.append(("header", "timestamp", timestamp.isoformat() if timestamp else None))
  except Exception as e:
    print(f"Error getting timestamp: {e}", file=sys.stderr)
    
  try:
    imps = get_imports(pe_file)
    print("Imports retrieved successfully")
    if write_csv and imps:
      for dll, syms in imps.items():
        csv_rows.append(("import", "dll", dll))
        csv_rows.append(("import", f"{dll}.symbols", json.dumps(syms)))
  except Exception as e:
    print(f"Error getting imports: {e}", file=sys.stderr)
    
  try:
    exps = get_exports(pe_file)
    print("Exports retrieved successfully")
    if write_csv and exps:
      csv_rows.append(("export", "count", len(exps)))
      for name, (addr, forwarder) in exps.items():
        csv_rows.append(("export", name, json.dumps({'addr': addr, 'forwarder': forwarder})))
  except Exception as e:
    print(f"Error getting exports: {e}", file=sys.stderr)

  try:
    if hasattr(pe_file, 'get_resources_strings'):
      resource_strings = pe_file.get_resources_strings()
      if resource_strings:
        print(f"Resource strings found: {len(resource_strings)} entries")
        if write_csv:
          csv_rows.append(("resources", "count", len(resource_strings)))
      else:
        print("No resource strings found")
    else:
      print("pefile does not support get_resources_strings() in this version")
  except Exception as e:
    print(f"Error getting resource strings: {e}", file=sys.stderr)

  # Get overlay if any, and print
  try:
    overlay = pe_file.get_overlay()
    if overlay:
      print(f"Overlay found: {len(overlay)} bytes")
      if write_csv:
        csv_rows.append(("overlay", "size", len(overlay)))
    else:
      print("No overlay found")
  except Exception as e:
    print(f"Error getting overlay: {e}", file=sys.stderr)

  try:
    callbacks = get_tls_callbacks(pe_file)
    if callbacks:
      print(f"TLS callbacks: {callbacks}")
      if write_csv:
        for cb in callbacks:
          csv_rows.append(("tls_callback", "address", hex(cb.get('address')) if isinstance(cb.get('address'), int) else cb.get('address')))
    else:
      print("No TLS callbacks found")
  except Exception as e:
    print(f"Error getting TLS callbacks: {e}", file=sys.stderr)

  try:
    del_imports = get_delay_imports(pe_file)
    if del_imports:
      print("Delay imports retrieved successfully")
      if write_csv:
        for dll, syms in del_imports.items():
          csv_rows.append(("delay_import", dll, json.dumps(syms)))
    else:
      print("No delay imports found")
  except Exception as e:
    print(f"Error getting delay imports: {e}", file=sys.stderr)

  try:
    reloc_data = get_reloc_data(pe_file)
    if reloc_data:
      print(f"Relocation data: {len(reloc_data)} entries")
      if write_csv:
        for reloc_type, rva in reloc_data:
          csv_rows.append(("relocation", reloc_type, rva))
    else:
      print("No relocation data found")
  except Exception as e:
    print(f"Error getting relocation data: {e}", file=sys.stderr)

  # If requested, write CSV summary
  if write_csv:
    try:
      csv_filename = os.path.splitext(os.path.basename(pe_file_path))[0] + '.csv'
      with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['category', 'field', 'value'])
        for row in csv_rows:
          # Ensure all values are strings
          writer.writerow([row[0], row[1], '' if row[2] is None else str(row[2])])
      print(f"CSV summary written to {csv_filename}")
    except Exception as e:
      print(f"Error writing CSV file: {e}", file=sys.stderr)


def main():
  parser = argparse.ArgumentParser(prog='peanalyzer', 
                                   description="Analyze a PE for various items of interest.")

  parser.add_argument('path', help='Path to the PE file to analyze')
  parser.add_argument('--csv', action='store_true', help='Output CSV')

  args = parser.parse_args()
  pe_file_path = args.path
  get_pe_info(pe_file_path, write_csv=args.csv)
  
if __name__ == "__main__":
  main()



