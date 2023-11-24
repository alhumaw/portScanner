import nmap
import optparse

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
    tgtPort = options.tgtPort
    if tgtHost is None or tgtPort is None:
        print(parser.usage)
        exit(0)
    nmapScan(tgtHost,tgtPort)
if __name__=='__main__':
    main()