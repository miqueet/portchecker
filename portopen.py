#Useage Example
#python portopen.py 1.1.1.1 80
import socket;
import sys
import errno
import signal
import time
import timeout_decorator

@timeout_decorator.timeout(2)
def ptest():
    ip=sys.argv[1]
    port=int(sys.argv[2])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((ip,port))
    if result == 0:
       print "Port is open"
    else:
       print "Port is CLOSED"

if __name__ == '__main__':
    ptest()
