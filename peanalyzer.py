import pefile
import sys
import datetime
from collections import defaultdict

# Things to analyze:

# Condition of sections (e.g writeable when it shouldn't be)
def section_info(pe: pefile.PE):
  IMAGE_SCN_MEM_EXECUTE = 0x20000000
  IMAGE_SCN_MEM_READ = 0x40000000
  IMAGE_SCN_MEM_WRITE = 0x80000000

  characteristics = []
  for section in pe.sections:
    writeable = bool(section.Characteristics & IMAGE_SCN_MEM_WRITE)
    executable = bool(section.Characteristics & IMAGE_SCN_MEM_EXECUTE)
    readable = bool(section.Characteristics & IMAGE_SCN_MEM_READ)

    # Decode byte to string and strip null bytes to get just section name
    section_name = section.Name.decode().strip('\\x00')

    characteristics.append((section_name, section.Misc_VirtualSize, 
                           section.SizeOfRawData, [writeable, executable, readable]))
  
  print("Returning: " + str(characteristics))
  
  return characteristics
  
# Get stub
def get_stub(pe: pefile.PE):
  # RVA of stub start
  stub_start = 0x40

  # Treat any rich headers as part of stub :P
  stub_end = pe.DOS_HEADER.e_lfanew

  # Get hex values of stub
  stub_data = pe.get_data(stub_start, stub_end) 
  
  return str(stub_data)


  

# Large difference between VirtualSize (size in memory) and SizeOfRawData (disk)

# TimeDateStamp in IMAGE_FILE_HEADER to check when file was created
def get_timedatestamp(pe: pefile.PE):
  # Get UNIX timestamp
  tds = pe.FILE_HEADER.TimeDateStamp

  # Convert to date (YYYY-MM-DD HH:MM:SS)
  date = datetime.datetime.fromtimestamp(tds)
  return date



# ExportTableAddress, ResourcesTable (get_resources_strings)
def get_imports(pe: pefile.PE):
  # List of ImportDescData instances
  import_table = pe.DIRECTORY_ENTRY_IMPORT

  imp_dlls_and_symbols = defaultdict(list)
  # For each ImportDescData
  for imp_desc in import_table:
    imp_desc_name = imp_desc.dll.decode('utf-8')
    print("Name: " + imp_desc_name)
    # List of ImportData instances
    imports = imp_desc.imports
    for imp_data in imports:
      imp_data_name = imp_data.name.decode('utf-8')
      print("Imported symbols: " + imp_data_name)
      imp_dlls_and_symbols[imp_desc_name].append(imp_data_name)
      
  
  return imp_desc_name

def get_exports(pe: pefile.PE):
  # ExportDirData instance
  exp_table = pe.DIRECTORY_ENTRY_EXPORT

  # List of ExportData instances
  exp_symbols = exp_table.symbols

  # name : (addr, forwarder)
  symbols = defaultdict(list)
  for symbol in exp_symbols:
    smbl_name = symbol.name.decode('utf-8')
    smbl_addr = symbol.address
    smbl_forwarder = symbol.forwarder

    symbols[smbl_name] = (smbl_addr, smbl_forwarder)
    
    print(f"Symbol name: {smbl_name}")
    print(f"Symbol address: {smbl_addr}")
    print(f"Symbol forwarder: {smbl_forwarder}")

  return symbols


def get_resource_strings(pe: pefile.PE):


# PE overlays - extra data appended to end of file

# TLS callbacks - threads set to run code before entry point is ran

# Delay-Load imports - only load DLLs when they are first called, check
# Delay Import Descriptor in Data Directory

# Check stub

def main():
  print("In main")
  if len(sys.argv) == 1:
    print("No arguments provided, exiting.", file=sys.stderr)
    exit(1)
  
  pe_files = []
  print(f"Argument: {sys.argv[1]}")
  for path in sys.argv:
    pe_files.append(pefile.PE(sys.argv[1]))

  section_info(pe_files[0])
  get_stub(pe_files[0])
  get_timedatestamp(pe_files[0])
  imps = get_imports(pe_files[0])
  exps = get_exports(pe_files[0])
  


  # pe_files[0].print_info()


main()