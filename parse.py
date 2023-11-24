import optparse
from socket import *

parser = optparse.OptionParser('parse.py -H' + '<target host> -p <target port>')

parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
parser.add_option("-p", dest='tgtPort', type='int', help='specify target port')
options,args = parser.parse_args()
tgtHost = options.tgtHost
tgtPort = options.tgtPort
if tgtHost is None or tgtPort is None:
    print(parser.usage)
    exit(0)

