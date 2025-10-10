import pefile
import sys
import datetime
import os
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

        sec_info[section_name] = {
          "hashes": {
            "sha256": section.get_hash_sha256(),
            "sha1": section.get_hash_sha1(),
            "md5": section.get_hash_md5()
          },
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

    # Get hex values of stub
    stub_data = pe.get_data(stub_start, stub_end - stub_start)
    
    return str(stub_data)
    
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
    symbols = defaultdict(list)
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

    if not hasattr(tls_dir, "AddressOfCallBacks"):
      print("PE has no TLS callbacks")
      return None
    
    # Is PE 64-bit?
    if not hasattr(pe, 'OPTIONAL_HEADER') or not hasattr(pe.OPTIONAL_HEADER, 'Magic'):
      print("Error: Cannot determine PE architecture")
      return None
      
    if hex(pe.OPTIONAL_HEADER.Magic) == "0x20b":
      ptr_size = 8
    else:
      ptr_size = 4

    callbacks = []
    cb_ptr = tls_dir.AddressOfCallBacks
    
    if not hasattr(pe.OPTIONAL_HEADER, 'ImageBase'):
      print("Error: Cannot find ImageBase")
      return None
    
    while True:
      try:
        # Convert virtual address to RVA
        cb_rva = cb_ptr - pe.OPTIONAL_HEADER.ImageBase
        
        # Validate RVA
        if cb_rva < 0:
          print(f"Warning: Invalid RVA calculated: {cb_rva}")
          break

        # Convert RVA to file offset
        try:
          cb_offset = pe.get_offset_from_rva(cb_rva)
        except Exception as rva_error:
          print(f"Error converting RVA to offset: {rva_error}")
          break

        # Read pointer-sized data from file
        try:
          callback_addr_bytes = pe.get_data(cb_offset, ptr_size)
          callback_addr = int.from_bytes(callback_addr_bytes, byteorder='little')
        except Exception as read_error:
          print(f"Error reading callback address: {read_error}")
          break

        # Check if we've reached the end (NULL pointer)
        if callback_addr == 0:
            break
            
        callbacks.append(hex(callback_addr))
        print(f"TLS Callback #{len(callbacks)}: 0x{callback_addr:x}")
        
        # Move to next pointer
        cb_ptr += ptr_size
          
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

def main():
  print("In main")
  if len(sys.argv) < 2:
    print("Usage: python peanalyzer.py <pe_file_path>", file=sys.stderr)
    print("No arguments provided, exiting.", file=sys.stderr)
    sys.exit(1)
  
  pe_files = []
  pe_file_path = sys.argv[1]
  print(f"Analyzing file: {pe_file_path}")
  
  try:
    # Check if file exists
    if not os.path.exists(pe_file_path):
      print(f"Error: File '{pe_file_path}' does not exist.", file=sys.stderr)
      sys.exit(1)
    
    # Try to parse the PE file
    pe_file = pefile.PE(pe_file_path)
    pe_files.append(pe_file)
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
    info = get_sections_info(pe_files[0])
    print("Section info:", info)
  except Exception as e:
    print(f"Error getting section info: {e}", file=sys.stderr)

  try:
    stub = get_stub(pe_files[0])
    print("Stub data retrieved successfully")
  except Exception as e:
    print(f"Error getting stub: {e}", file=sys.stderr)
    
  try:
    timestamp = get_timedatestamp(pe_files[0])
    print(f"Timestamp: {timestamp}")
  except Exception as e:
    print(f"Error getting timestamp: {e}", file=sys.stderr)
    
  try:
    imps = get_imports(pe_files[0])
    print("Imports retrieved successfully")
  except Exception as e:
    print(f"Error getting imports: {e}", file=sys.stderr)
    
  try:
    exps = get_exports(pe_files[0])
    print("Exports retrieved successfully")
  except Exception as e:
    print(f"Error getting exports: {e}", file=sys.stderr)

  ## TODO: EXPAND AND ENUMERATE THROUGH ALL RESOURCES IN RESOURCE DIR
  # resource_strings = pe_files[0].get_resources_strings()
  # print(str(resource_strings))

  # Get overlay if any, and print
  try:
    overlay = pe_files[0].get_overlay()
    if overlay:
      print(f"Overlay found: {len(overlay)} bytes")
    else:
      print("No overlay found")
  except Exception as e:
    print(f"Error getting overlay: {e}", file=sys.stderr)

  try:
    callbacks = get_tls_callbacks(pe_files[0])
    if callbacks:
      print(f"TLS callbacks: {callbacks}")
    else:
      print("No TLS callbacks found")
  except Exception as e:
    print(f"Error getting TLS callbacks: {e}", file=sys.stderr)

  try:
    del_imports = get_delay_imports(pe_files[0])
    if del_imports:
      print("Delay imports retrieved successfully")
    else:
      print("No delay imports found")
  except Exception as e:
    print(f"Error getting delay imports: {e}", file=sys.stderr)

  try:
    reloc_data = get_reloc_data(pe_files[0])
    if reloc_data:
      print(f"Relocation data: {len(reloc_data)} entries")
    else:
      print("No relocation data found")
  except Exception as e:
    print(f"Error getting relocation data: {e}", file=sys.stderr)

  # pe_files[0].print_info()

if __name__ == "__main__":
  main()



