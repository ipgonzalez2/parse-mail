import os
import sys
import re
import ConfigParser

from jinja2 import Environment, FileSystemLoader
from sys import argv
from os import path

#args
def usage():
    print("USAGE: %s [-p <percentage_characters>(4,5,6,7)] spam_file" % argv[0])
    print("")
    print("Try '%s -h' for more options." % argv[0])
    exit()

#help
def help():
    print("USAGE: %s [-p <percentage_characters>(4,5,6,7)] spam_file" % argv[0])
    print("")
    print("optional arguments:")
    print("   -h                       print this help")
    print("   -p percentage_characters               Checks certain number of characters. Default is 4%")
    print("")
    print("examples:")
    print("    addFilter spam.eml             # adds filter to spam.eml checking 4% of the email")
    print("    addFilter -p 5 spam.eml        # adds filter to spam.eml checking 5% of the email")
    exit()

#arguments
porcentaje = 4

if len(argv) == 2:
  if str(argv[1]) == '-h':
    help()
  elif path.exists(argv[1]):
    file_path = argv[1]  
  else:
    usage()

if len(argv) == 3:
  if str(argv[1]) == '-p':
    help()
  else:
    usage()

if len(argv) == 4:
  if str(argv[1]) == '-p' and path.exists(argv[3]):
    porcentaje = int(argv[2])
    file_path = argv[3]
  else:
    usage()

if len(argv) > 4 or len(argv) < 2:
  usage()

# Open given spam to be filtered 
fileSpam = open(file_path, 'r')

# Creates regular expression to find where the message begins
regex = re.compile('\n\n')
match = re.search(regex, fileSpam.read())

# Calculating where the message begins and his size
inicioMensaje = match.end()
tamanhoTotal = os.stat(file_path).st_size
tamanhoMensaje = tamanhoTotal - inicioMensaje

# Num of characters to match (max 30)
numCar = int(float(tamanhoMensaje*float((float(porcentaje)/100))))
if numCar > 30:
  numCar = 30

# Creating array of characters for the filter
car = []
x = int(float(tamanhoMensaje/numCar))
fileSpam = open(file_path, 'r')

for i in range(numCar):
    desp = inicioMensaje + (x * i)
    caracter = fileSpam.read()[desp]
    if caracter == "'":
      car.append(str("\\'"))
    else:
      car.append(caracter)
    fileSpam.seek(0,0)

print(car)
fileSpam.close()

# Updating the configuration file
config = ConfigParser.RawConfigParser()
config.read("filters.cfg")
if(len(config.sections()) > 0):
  numFilter = str(int(config.sections()[-1][6:]) + 1)
else:
  numFilter = str(0)

# Updating array to C
caracteres = str(car)
caracteres = caracteres[:0] + '{' + caracteres[0+1:]
caracteres = caracteres[:(len(caracteres)-1)] + '}' + caracteres[(len(caracteres)-1)+1:]

file_loader = FileSystemLoader('filters')
env = Environment(loader=file_loader)
template = env.get_template('filter_template.c')
output = template.render(id = numFilter, tam = tamanhoMensaje, numCar = numCar, caracteres = caracteres)
with open("./filters/filter"+numFilter+".c", "w") as fh:
    fh.write(output)


# Adding section to configuration file
config.add_section('Filter'+numFilter)
config.set('Filter'+numFilter, 'program', 'filter'+numFilter+'.c')
config.set('Filter'+numFilter, 'function', 'mail_filter_'+numFilter)

# Writing our configuration file to 'filters.cfg'
with open('filters.cfg', 'wb') as configfile:
    config.write(configfile)
