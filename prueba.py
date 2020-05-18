#!/usr/bin/python
#
#Bertrone Matteo - Polytechnic of Turin
#November 2015
#
#eBPF application that parses HTTP packets
#and extracts (and prints on screen) the URL contained in the GET/POST request.
#
#eBPF program http_filter is used as SOCKET_FILTER attached to eth0 interface.
#only packet of type ip and tcp containing HTTP GET/POST are returned to userspace, others dropped
#
#python script uses bcc BPF Compiler Collection by iovisor (https://github.com/iovisor/bcc)
#and prints on stdout the first line of the HTTP GET/POST request containing the url

from __future__ import print_function
from bcc import BPF
from sys import argv

import sys
import threading
import socket
import os
import ConfigParser
import pyinotify

wm = pyinotify.WatchManager()
mask = pyinotify.IN_DELETE | pyinotify.IN_MOVED_TO
bpf = []
function_http_filter = []
socket_fd = []
sock = []
config = ConfigParser.RawConfigParser()
config.read('filters.cfg')
interface = config.get('settings', 'interface')

class EventHandler(pyinotify.ProcessEvent):
  def process_IN_MOVED_TO(self, event):
    print("Creating:", event.pathname)
    os.system("sudo python addFilter.py " + event.pathname)
    program = config.get(config.sections()[-1], 'program')
    function = config.get(config.sections()[-1], 'function')
    bpf.append(BPF(src_file = "filters/"+program,debug = 0))
    function_http_filter.append(bpf[-1].load_func(function, BPF.SOCKET_FILTER))
    BPF.attach_raw_socket(function_http_filter[-1], interface)
    socket_fd.append(function_http_filter[-1].sock)
    sock.append(socket.fromfd(socket_fd[-1],socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP))
    sock[-1].setblocking(True)
    print(socket_fd)
    while 1:
      for i in socket_fd:
        print(bytearray(os.read(i, 100000)))
    

  
  def process_IN_DELETE(self, event):
    print("Removing:", event.pathname)
    os.system("sudo python removeFilter.py " + event.pathname)


def filter():
  config = ConfigParser.RawConfigParser()
  config.read('filters.cfg')
  print ("binding socket to '%s'" % interface)

  for filter in config.sections()[1:]:
    program = config.get(filter,'program')
    function = config.get(filter,'function')

  # initialize BPF - load source code from http-parse-simple.c
    bpf.append(BPF(src_file = "filters/"+program,debug = 0))
    #bpf = BPF(src_file = "filters/"+program,debug = 0)

  #load eBPF program http_filter of type SOCKET_FILTER into the kernel eBPF vm
  #more info about eBPF program types
  #http://man7.org/linux/man-pages/man2/bpf.2.html
    #function_http_filter = bpf.load_func(function, BPF.SOCKET_FILTER)
    function_http_filter.append(bpf[-1].load_func(function, BPF.SOCKET_FILTER))

  #create raw socket, bind it to interface
  #attach bpf program to socket created
    BPF.attach_raw_socket(function_http_filter[-1], interface)

  #get file descriptor of the socket previously created inside BPF.attach_raw_socket
    #socket_fd = function_http_filter.sock
    socket_fd.append(function_http_filter[-1].sock)

  #create python socket object, from the file descriptor
    #sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
    sock.append(socket.fromfd(socket_fd[-1],socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP))
  #set it as blocking socket
    sock[-1].setblocking(True)



def notifier():
  notifier = pyinotify.AsyncNotifier(wm, EventHandler())
  wdd = wm.add_watch('/home/inesp', mask, rec=False)
  import asyncore
  asyncore.loop()



#args
def usage():
    print("USAGE: %s [-i <if_name>]" % argv[0])
    print("")
    print("Try '%s -h' for more options." % argv[0])
    exit()

#help
def help():
    print("USAGE: %s [-i <if_name>]" % argv[0])
    print("")
    print("optional arguments:")
    print("   -h                       print this help")
    print("   -i if_name               select interface if_name. Default is eth0")
    print("")
    print("examples:")
    print("    http-parse              # bind socket to eth0")
    print("    http-parse -i wlan0     # bind socket to wlan0")
    exit()

if len(argv) == 2:
  if str(argv[1]) == '-h':
    help()
  else:
    usage()

if len(argv) == 3:
  if str(argv[1]) == '-i':
    interface = argv[2]
  else:
    usage()

if len(argv) > 3:
  usage()


thread1 = threading.Thread(target=filter)
thread2 = threading.Thread(target=notifier)
thread1.start()
thread2.start()
thread1.join()
thread2.join()