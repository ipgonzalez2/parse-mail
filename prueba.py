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

  
  def process_IN_DELETE(self, event):
    print("Removing:", event.pathname)


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


while 1:
  notifier = pyinotify.AsyncNotifier(wm, EventHandler())
  wdd = wm.add_watch('/home/inesp', mask, rec=False)
  import asyncore
  asyncore.loop()
  #retrieve raw packet from socket
  for i in socket_fd:
    print(bytearray(os.read(i,100000)))

  

  #DEBUG - print raw packet in hex format
  #packet_hex = toHex(packet_str)
  #print ("%s" % packet_hex)

  #convert packet into bytearray
  #packet_bytearray = bytearray(packet_str)

  #ethernet header length
  """ETH_HLEN = 14

  #IP HEADER
  #https://tools.ietf.org/html/rfc791
  # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  # |Version|  IHL  |Type of Service|          Total Length         |
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #
  #IHL : Internet Header Length is the length of the internet header
  #value to multiply * 4 byte
  #e.g. IHL = 5 ; IP Header Length = 5 * 4 byte = 20 byte
  #
  #Total length: This 16-bit field defines the entire packet size,
  #including header and data, in bytes.

  #calculate packet total length
  total_length = packet_bytearray[ETH_HLEN + 2]               #load MSB
  total_length = total_length << 8                            #shift MSB
  total_length = total_length + packet_bytearray[ETH_HLEN+3]  #add LSB

  #calculate ip header length
  ip_header_length = packet_bytearray[ETH_HLEN]               #load Byte
  ip_header_length = ip_header_length & 0x0F                  #mask bits 0..3
  ip_header_length = ip_header_length << 2                    #shift to obtain length

  #TCP HEADER
  #https://www.rfc-editor.org/rfc/rfc793.txt
  #  12              13              14              15
  #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  # |  Data |           |U|A|P|R|S|F|                               |
  # | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
  # |       |           |G|K|H|T|N|N|                               |
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #
  #Data Offset: This indicates where the data begins.
  #The TCP header is an integral number of 32 bits long.
  #value to multiply * 4 byte
  #e.g. DataOffset = 5 ; TCP Header Length = 5 * 4 byte = 20 byte

  #calculate tcp header length
  tcp_header_length = packet_bytearray[ETH_HLEN + ip_header_length + 12]  #load Byte
  tcp_header_length = tcp_header_length & 0xF0                            #mask bit 4..7
  tcp_header_length = tcp_header_length >> 2                              #SHR 4 ; SHL 2 -> SHR 2

  #calculate payload offset
  payload_offset = ETH_HLEN + ip_header_length + tcp_header_length
  #print first line of the HTTP GET/POST request
  #line ends with 0xOD 0xOA (\r\n)
  #(if we want to print all the header print until \r\n\r\n)
  
  for i in range (payload_offset-1,len(packet_bytearray)-1):
    if (packet_bytearray[i]== '\n'):
      if (packet_bytearray[i-1] == '\n'):
        break
    print ("%c" % chr(packet_bytearray[i]), end = "")
  print("")"""

