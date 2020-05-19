import os
import sys
import re
import ConfigParser
import hashlib
import addFilter

from sys import argv
from os import path

#args
def usage():
    print("USAGE: %s spam_file" % argv[0])
    print("")
    print("Try '%s -h' for more options." % argv[0])
    exit()

#help
def help():
    print("USAGE: %s spam_file" % argv[0])
    print("")
    print("optional arguments:")
    print("   -h                       print this help")
    print("")
    print("examples:")
    print("    removeFilter spam.eml             # removes filter relative to spam.eml")
    exit()


if len(argv) == 2:
  if str(argv[1]) == '-h':
    help()
  elif path.exists(argv[1]):
    file_path = argv[1]  
  else:
    usage()

if len(argv) == 3:
  if str(argv[1]) == '-h':
    help()
  else:
    usage()

if len(argv) > 3 or len(argv) < 2:
  usage()

# Calculating hash of file
hash_summary = addFilter.getHash(file_path).hexdigest()

# Searching for summary in the configuration file and removing filter
config = ConfigParser.RawConfigParser()
config.read("filters.cfg")
for section in config.sections()[1:]:
    if config.get(section, 'hash') == hash_summary:
        if os.path.exists("./filters/" + config.get(section, 'program')):
            os.remove("./filters/" + config.get(section, 'program'))
        config.remove_section(section)
        
# Writing our configuration file to 'filters.cfg'
with open('filters.cfg', 'wb') as configfile:
    config.write(configfile)