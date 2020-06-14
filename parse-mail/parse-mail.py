#eBPF application that parses SMTP packets

from __future__ import print_function
from bcc import BPF
from sys import argv

import sys
import asyncore
import threading
import socket
import os
import ConfigParser
import pyinotify
import hashlib
import utils
import time


# Configures notifier
wm = pyinotify.WatchManager()
mask = pyinotify.IN_MOVED_TO | pyinotify.IN_DELETE | pyinotify.IN_MODIFY


# BPF params
bpf = []
function_mail_filter = []
socket_fd = []
sock = []


# Get configuration
config = ConfigParser.RawConfigParser()
config.read('filters.cfg')
interface = config.get('settings', 'interface')
basepath = './spam'

def loadFilter(program, function):
  # initialize BPF - load source code from filters/program.c
  bpf.append(BPF(src_file = "filters/"+program,debug = 0))

  #load eBPF program function of type SOCKET_FILTER into the kernel eBPF vm
  function_mail_filter.append(bpf[-1].load_func(function, BPF.SOCKET_FILTER))

  #create raw socket, bind it to interface
  #attach bpf program to socket created
  BPF.attach_raw_socket(function_mail_filter[-1], interface)

  #get file descriptor of the socket previously created inside BPF.attach_raw_socket
  socket_fd.append(function_mail_filter[-1].sock)

  #create python socket object, from the file descriptor
  sock.append(socket.fromfd(socket_fd[-1],socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP))

  #set it as blocking socket
  sock[-1].setblocking(True)

  return socket_fd[-1]




# Events handler
class EventHandler(pyinotify.ProcessEvent):

  # Adds filter when file is moved to directory spam
  def process_IN_MOVED_TO(self, event):

    print("-> (+) Creating filter for ", event.pathname + "...\n")

    try:
      #Adds filter for file
      utils.addFilter(event.pathname, 'filters.cfg')

      config.read('filters.cfg')
      print("Currently filtering: " + str(len(config.sections()[1:])) + " mails\n\n")
      
      #Creates socket for filter
      config.read('filters.cfg')
      program = config.get(config.sections()[-1], 'program')
      function = config.get(config.sections()[-1], 'function')

      fd = loadFilter(program, function)

      config.set(config.sections()[-1], 'fd', fd)

      #writes configuration
      with open('filters.cfg', 'wb') as configfile:
        config.write(configfile)


    except:
      print("Error creating filter")

    print(socket_fd)



  # Deletes filter when file is deleted in directory spam
  def process_IN_DELETE(self, event):
    
    print("-> (-) Removing filter for ", event.pathname + "...\n")

    try:
      #get socket descriptor and remove it
      fd = utils.removeFilter('filters.cfg')
      if fd != -1:
        index = socket_fd.index(int(fd))
        os.close(int(fd))
        sock[index].close()
        del bpf[index]
        del function_mail_filter[index]
        del sock[index]
        del socket_fd[index]
    except:
      print("Error removing filter")

    print("Currently filtering: " + str(len(bpf)) + " mails\n\n")

  # Generic change in directory
  def process_IN_MODIFY(self, event):

    config.read('filters.cfg')

    hashes = []
    for section in config.sections()[1:]:
      config.remove_option(section, 'fd')
      hashes.append(config.get(section, 'hash'))

    # Adding filter for files in spam/ if needed
    for entry in os.listdir(basepath):
      if os.path.isfile(os.path.join(basepath, entry)) and entry != '.gitkeep' :
        hash_summary = utils.getHash(os.path.join(basepath, entry)).hexdigest()
        if hash_summary not in hashes:

          print("-> (+) Adding filter for " + str(entry) + "\n")
          utils.addFilter(os.path.join(basepath, entry), 'filters.cfg')
          #Creates socket for filter
          config.read('filters.cfg')
          program = config.get(config.sections()[-1], 'program')
          function = config.get(config.sections()[-1], 'function')

          fd = loadFilter(program, function)

          config.set(config.sections()[-1], 'fd', fd)

        else:
          hashes.remove(hash_summary)

         #writes configuration
        with open('filters.cfg', 'wb') as configfile:
          config.write(configfile)

    print("Currently filtering: " + str(len(bpf)) + " mails\n\n")

def filter():

  #Reading configuration
  config.read('filters.cfg')

  print("\n\nSTARTING PARSE-MAIL...\n\n")


  #Updates configuration
  hashes = []
  for section in config.sections()[1:]:
    config.remove_option(section, 'fd')
    hashes.append(config.get(section, 'hash'))


  # Adding filter for files in spam/ if needed
  for entry in os.listdir(basepath):
    if os.path.isfile(os.path.join(basepath, entry)) and entry != '.gitkeep' :
      hash_summary = utils.getHash(os.path.join(basepath, entry)).hexdigest()
      if hash_summary not in hashes:
        print("-> (+) Adding filter for " + str(entry) + "\n")
        utils.addFilter(os.path.join(basepath, entry), 'filters.cfg')
      else:
        hashes.remove(hash_summary)


  # Removing filters if not in directory spam/
  config.read('filters.cfg')
  for section in config.sections()[1:]:
    if config.get(section, 'hash') in hashes:
        if os.path.exists("./filters/" + config.get(section, 'program')):
            print("-> (-) Removing filter " + config.get(section, 'program') + "\n")
            os.remove("./filters/" + config.get(section, 'program'))
        config.remove_section(section)
  with open('filters.cfg', 'wb') as configfile:
    config.write(configfile)

  config.read('filters.cfg')

  print("\n**************************************************\n\n")
  print("Currently filtering " + str(len(config.sections()[1:])) + " mails\n\n")
  print("Binding socket to interface " + interface + "\n\n")
  print("Monitoring " + basepath + "\n\n")
  print("Press CTRL-C to exit\n\n")
  print("**************************************************\n\n")


  # Adds every filter in config
  for filter in config.sections()[1:]:
    program = config.get(filter,'program')
    print("Load filter " + program + "\n")
    function = config.get(filter,'function')

    fd = loadFilter(program, function)

    config.set(filter, 'fd', fd)

    with open('filters.cfg', 'wb') as configfile:
      config.write(configfile)

  print("Starting filtering...\n")


#Watches directory spam/ to seek for changes
def notifier():
  notifier = pyinotify.AsyncNotifier(wm, EventHandler())
  wdd = wm.add_watch(basepath, mask, rec=False)
  asyncore.loop()

#args
def usage():
    print("USAGE: %s " % argv[0])
    print("")
    print("Try '%s -h' for more options." % argv[0])
    exit()

#help
def help():
    print("USAGE: %s " % argv[0])
    print("")
    print("optional arguments:")
    print("   -h                       print this help")
    print("")
    print("examples:")
    print("    sudo python parse-mail.py              # bind socket to interface established in filters.cfg")
    exit()



def main():

  if len(argv) == 2:
    if str(argv[1]) == '-h':
      help()
    else:
      usage()

  if len(argv) > 2:
    usage()

  try:
    filter()
    notifier()
  except KeyboardInterrupt:
    sys.exit()


if __name__ == "__main__":
  main()