#Utils

import os
import sys
import re
import ConfigParser
import hashlib

from jinja2 import Environment, FileSystemLoader
from sys import argv
from os import path


BLOCK_SIZE = 65536
basepath = './spam/'
config = ConfigParser.RawConfigParser()


# Function that calculates hash summary of file
def getHash(file_path):
  file_hash = hashlib.sha256()
  with open(file_path, 'rb') as f:
    fb = f.read(BLOCK_SIZE)
    while len(fb) > 0:
        file_hash.update(fb)
        fb = f.read(BLOCK_SIZE)
  return file_hash


# Adds filter for a spam file given
def addFilter(file_path, file_conf):
    if path.exists(file_path):
        # Read configuration
        config = ConfigParser.RawConfigParser()
        config.read(file_conf)
        porcentaje = config.get('settings','percentage')
        numCar = -1 
        car = []

        try:
            # Open given spam to be filtered 
            fileSpam = open(file_path, 'r')

            # Creates regular expression to find where the message begins
            regex = re.compile('\n\n')
            match = re.search(regex, fileSpam.read())

            # Calculating where the message begins and his size
            inicioMensaje = match.end()
            tamanhoTotal = os.stat(file_path).st_size
            tamanhoMensaje = tamanhoTotal - inicioMensaje
            limit = False

            if tamanhoTotal > 15000:
                numCar = int(float(15000*float((float(porcentaje)/100))))
                limit = True
            else:
                # Num of characters to match (max 30)
                numCar = int(float(tamanhoMensaje*float((float(porcentaje)/100))))

            if numCar > 30:
                numCar = 30
            elif numCar == 0:
                numCar = tamanhoMensaje

            if limit:
                x = int(float((15000 - inicioMensaje)/numCar))
            else:
                x = int(float(tamanhoMensaje/numCar))

            fileSpam = open(file_path, 'r')


            # Getting characters to compare
            for i in range(numCar):
                desp = inicioMensaje + (x * i)
                caracter = fileSpam.read()[desp]
                if caracter == "'":
                    car.append(str('comilla'))
                else:
                    car.append(caracter)
                fileSpam.seek(0,0)

            fileSpam.close()

            # Searching filter id
            config = ConfigParser.RawConfigParser()
            config.read(file_conf)
            if(len(config.sections()) > 1):
                numFilter = str(int(config.sections()[-1][6:]) + 1)
            else:
                numFilter = str(0)

            # Updating array to C
            caracteres = str(car)
            caracteres = caracteres[:0] + '{' + caracteres[0+1:]
            caracteres = caracteres[:(len(caracteres)-1)] + '}' + caracteres[(len(caracteres)-1)+1:]

            # Adding filter to directory
            file_loader = FileSystemLoader('filters')
            env = Environment(loader=file_loader)
            template = env.get_template('filter_template.c')
            output = template.render(id = numFilter, tam = tamanhoMensaje, numCar = numCar, caracteres = caracteres.replace("comilla", "\\'"), x = x)
            with open("./filters/filter"+numFilter+".c", "w") as fh:
                fh.write(output)

            # Calculating hash of file
            file_hash = getHash(file_path)

            # Adding section to configuration file
            config.add_section('Filter'+numFilter)
            config.set('Filter'+numFilter, 'program', 'filter'+numFilter+'.c')
            config.set('Filter'+numFilter, 'function', 'mail_filter_'+numFilter)
            config.set('Filter'+numFilter, 'hash', file_hash.hexdigest())

            # Writing our configuration file to 'filters.cfg'
            with open(file_conf, 'wb') as configfile:
                config.write(configfile)

            return numCar, car
        except:
            print("Error adding filter (the file may not be a mail)...")
            return numCar, car
    else:
        print("File doesn't exist")


# Removes filter for spam file given
def removeFilter(file_conf):
    fd = -1 

    #get filters in directory
    hashes = []
    for entry in os.listdir(basepath):
      if os.path.isfile(os.path.join(basepath, entry)) and entry != '.gitkeep' :
        hash_summary = getHash(os.path.join(basepath, entry)).hexdigest()
        hashes.append(hash_summary)

    config.read(file_conf)

    #Removing filter missed in directory
    for section in config.sections()[1:]:
      if config.get(section, 'hash') not in hashes:
        if os.path.exists("./filters/" + config.get(section, 'program')):
            os.remove("./filters/" + config.get(section, 'program'))
        if(config.has_option(section,'fd')):
            fd = config.get(section, 'fd')
        config.remove_section(section)

    with open(file_conf, 'wb') as configfile:
      config.write(configfile)

    #returns socket descriptor
    return fd

        


