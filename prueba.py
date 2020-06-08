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
mask = pyinotify.IN_MOVED_TO | pyinotify.IN_DELETE


# BPF params
bpf = ""
function_http_filter = ""
socket_fd = ""
sock = socket


# Get configuration
config = ConfigParser.RawConfigParser()
config.read('filters.cfg')
interface = config.get('settings', 'interface')
# CHANGE!!!!!!!!!!!!
basepath = '/home/inesp/contenedor/'


# Events handler
class EventHandler(pyinotify.ProcessEvent):

  def process_IN_MOVED_TO(self, event):
    fd = socket_fd
    sock.close()

  
  def process_IN_DELETE(self, event):
    print("Removing filter for ", event.pathname + "\n")


def filter():
  #Reading configuration
  config.read('filters.cfg')
  
  print("Binding socket to '%s'" % interface + "\n")
  print("Starting filtering...\n")

  config.read('filters.cfg')

  filter = config.sections()[1]

  program = config.get(filter,'program')
  print("Load filter " + program + "\n")
  function = config.get(filter,'function')

    # initialize BPF - load source code from filters/program.c
  bpf = BPF(src_file = "filters/"+program,debug = 0)

    #load eBPF program function of type SOCKET_FILTER into the kernel eBPF vm
    #function_http_filter = bpf.load_func(function, BPF.SOCKET_FILTER)
  function_http_filter = bpf.load_func(function, BPF.SOCKET_FILTER)

    #create raw socket, bind it to interface
    #attach bpf program to socket created
  BPF.attach_raw_socket(function_http_filter, interface)

    #get file descriptor of the socket previously created inside BPF.attach_raw_socket
  socket_fd = function_http_filter.sock
  config.set(filter, 'fd', function_http_filter.sock)

    #create python socket object, from the file descriptor
  sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)

    #set it as blocking socket
  sock.setblocking(True)


  with open('filters.cfg', 'wb') as configfile:
    config.write(configfile)

  while 1:
    print(str(os.read(socket_fd, 10000)))


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