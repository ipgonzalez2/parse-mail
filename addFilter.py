import os
import sys

#args
def usage():
    print("USAGE: %s [-p <percentage_characters>(4,5,6,7)%] spam_file" % argv[0])
    print("")
    print("Try '%s -h' for more options." % argv[0])
    exit()

#help
def help():
    print("USAGE: %s [-p <percentage_characters>(4,5,6,7)%] spam_file" % argv[0])
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
  else:
    usage()

if len(argv) == 3:
  if str(argv[1]) == '-p':
    help()
  else:
    usage()

if len(argv) == 4:
  if str(argv[1]) == '-p' and os.path.isFile(argv[3]):
    porcentaje = int(argv[2])
    file_path = argv[3]
  else:
    usage()

if len(argv) > 4:
  usage()



print(porcentaje)
print(file_path)