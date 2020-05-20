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


# Configures notifier
wm = pyinotify.WatchManager()
mask = pyinotify.IN_MOVED_FROM | pyinotify.IN_MOVED_TO


# BPF params
bpf = []
function_http_filter = []
socket_fd = []
sock = []


# Get configuration
config = ConfigParser.RawConfigParser()
config.read('filters.cfg')
interface = config.get('settings', 'interface')
basepath = '/home/inesp/contenedor/'


# Events handler
class EventHandler(pyinotify.ProcessEvent):

  def process_IN_MOVED_TO(self, event):
    print("Creating filter for:", event.pathname)
    utils.addFilter(event.pathname, 'filters.cfg')

    config.read('filters.cfg')
    program = config.get(config.sections()[-1], 'program')
    print(program)
    function = config.get(config.sections()[-1], 'function')
    print(function)
    bpf.append(BPF(src_file = "filters/"+program,debug = 0))
    function_http_filter.append(bpf[-1].load_func(function, BPF.SOCKET_FILTER))
    BPF.attach_raw_socket(function_http_filter[-1], interface)
    socket_fd.append(function_http_filter[-1].sock)
    config.set(config.sections()[-1], 'fd', function_http_filter[-1].sock)
    sock.append(socket.fromfd(socket_fd[-1],socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP))
    sock[-1].setblocking(True)
    print(socket_fd)
    with open('filters.cfg', 'wb') as configfile:
      config.write(configfile)

  
  def process_IN_MOVED_FROM(self, event):
    print("Removing filter for:", event.pathname)
    fd = utils.removeFilter(event.pathname, 'filters.cfg')
    socket_fd.remove(fd)


def filter():
  #Reading configuration
  config.read('filters.cfg')
  
  hashes = []
  for section in config.sections()[1:]:
    hashes.append(config.get(section, 'hash'))


  # Adding filter for files in spam/ if needed
  for entry in os.listdir(basepath):
    if os.path.isfile(os.path.join(basepath, entry)) and entry != '.gitkeep' :
      hash_summary = utils.getHash(os.path.join(basepath, entry)).hexdigest()
      if hash_summary not in hashes:
        print("adding filter for" + str(entry))
        utils.addFilter(os.path.join(basepath, entry), 'filters.cfg')
      else:
        hashes.remove(hash_summary)


  # Removing filters if not in directory spam/
  config.read('filters.cfg')
  for section in config.sections()[1:]:
    if config.get(section, 'hash') in hashes:
        if os.path.exists("./filters/" + config.get(section, 'program')):
            os.remove("./filters/" + config.get(section, 'program'))
        config.remove_section(section)
  with open('filters.cfg', 'wb') as configfile:
    config.write(configfile)

  
  print ("binding socket to '%s'" % interface)

  config.read('filters.cfg')


  # Creating sockets
  for filter in config.sections()[1:]:
    program = config.get(filter,'program')
    function = config.get(filter,'function')

    # initialize BPF - load source code from filters/program.c
    bpf.append(BPF(src_file = "filters/"+program,debug = 0))

    #load eBPF program function of type SOCKET_FILTER into the kernel eBPF vm
    #function_http_filter = bpf.load_func(function, BPF.SOCKET_FILTER)
    function_http_filter.append(bpf[-1].load_func(function, BPF.SOCKET_FILTER))

    #create raw socket, bind it to interface
    #attach bpf program to socket created
    BPF.attach_raw_socket(function_http_filter[-1], interface)

    #get file descriptor of the socket previously created inside BPF.attach_raw_socket
    socket_fd.append(function_http_filter[-1].sock)
    config.set(filter, 'fd', function_http_filter[-1].sock)

    #create python socket object, from the file descriptor
    sock.append(socket.fromfd(socket_fd[-1],socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP))

    #set it as blocking socket
    sock[-1].setblocking(True)


    with open('filters.cfg', 'wb') as configfile:
      config.write(configfile)

  while 1:
    for i in socket_fd:
      print(bytearray(os.read(i, 10000)))


# Watches directory spam/ to seek for changes
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

if len(argv) == 2:
  if str(argv[1]) == '-h':
    help()
  else:
    usage()

if len(argv) > 2:
  usage()


# Thread that loads filters and print them
thread1 = threading.Thread(target=filter)

# Thread that awaits for changes in directory
thread2 = threading.Thread(target=notifier)

# Start threads
thread1.start()
thread2.start()

# Join threads
thread1.join()
thread2.join()