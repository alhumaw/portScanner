from multiprocessing import Semaphore
import optparse
from socket import *
from threading import Thread
import nmap

screenLock = Semaphore(value=1)
def connScan(tgtHost, tgtPort):
    try: 
        # open socket
        connSkt = socket(AF_INET, SOCK_STREAM)
        # connect to host
        connSkt.connect((tgtHost, tgtPort))
        results = connSkt.recv(100)
        screenLock.acquire()
        print('[+]%d/tcp open'% tgtPort)
        print(f"{str(results)}")
        connSkt.close()
    except:
        screenLock.acquire()
        print('[-]%d/tcp closed'% tgtPort)
    finally:
        screenLock.release()
        connSkt.close()

def portScan(tgtHost, tgtPorts):
    try:
        # try by host name
        tgtIP = gethostbyname(tgtHost)
    except:
        print("Cannot resolve host")
        return
    try:
        tgtName = gethostbyaddr(tgtIP)
        print(f"Scan results: {tgtName[0]}")
    except:
        print(f"Scan results for: {tgtIP}")
    setdefaulttimeout(1)
    for tgtPort in tgtPorts:
        t = Thread(target=connScan, args=(tgtHost, int(tgtPort)))
        t.start()

def nmapScan(tgtHost, tgtPort):
    nmScan = nmap.PortScanner()
    nmScan.scan(tgtHost,tgtPort)
    state = nmScan[tgtHost]['tcp'][int(tgtPort)]['state']
    print(" [*] " + tgtHost + " tcp/" + tgtPort + " " + state)


def main():
    parser = optparse.OptionParser('parse.py -H' + '<target host> -p <target port>')

    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option("-p", dest='tgtPort', type='string', help='specify target port')
    options,args = parser.parse_args()
    tgtHost = options.tgtHost
    tgtPorts = str(options.tgtPort).split(',')
    if tgtHost is None or tgtPorts is None:
        print(parser.usage)
        exit(0)
    portScan(tgtHost, tgtPorts)
    #nmapScan(tgtHost,tgtPorts)
if __name__=='__main__':
    main()

