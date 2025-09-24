import pefile

# Things to analyze:

# Condition of sections (e.g writeable when it shouldn't be)
def section_info(path: str):
  IMAGE_SCN_MEM_EXECUTE = 0x20000000
  IMAGE_SCN_MEM_READ = 0x40000000
  IMAGE_SCN_MEM_WRITE = 0x80000000


  pe = pefile.PE(path)
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


# Large difference between VirtualSize (size in memory) and SizeOfRawData (disk)

# PE overlays - extra data appended to end of file

# TLS callbacks - threads set to run code before entry point is ran

# Delay-Load imports - only load DLLs when they are first called, check
# Delay Import Descriptor in Data Directory

# Check stub
