from mitmproxy import ctx
from mitmproxy.proxy.config import HostMatcher
#from filterads import Filter
from iptables import IpTables
from xhostmatcher import XHostMatcher
import re

class MyHostMatcher(XHostMatcher):
    def __init__(self, allowedList):
        super().__init__()
        self.allowed = allowedList

    def __call__(self, address):
        if(self.allowed(address)):
            return False
        else:
            return super().__call__(address)

# Passthrough - For an SSL proxy, we don't need to snoop packets unless in the sitm list. Just pass through.
class Passthrough:
    def __init__(self):
        self.filter = IpTables()
        self.server_mitm_hosts = MyHostMatcher(XHostMatcher([l.rstrip('\n') for l in open('sitm.txt')]))

    def next_layer(self, layer):
        root = layer.ctx
        if(not isinstance(root.config.check_ignore,MyHostMatcher)):
            ctx.log.info("PASS: adding our special ignore list")
            root.config.check_ignore = self.server_mitm_hosts

    def serverconnect(self, conn):
        return self.filter.serverconnect(conn)

