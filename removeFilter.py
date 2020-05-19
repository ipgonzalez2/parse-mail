import os
import sys
import re
import ConfigParser
import hashlib
import addFilter

from sys import argv
from os import path


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