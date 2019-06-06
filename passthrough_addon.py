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

# Passthrough - For an SSL proxy, we don't need to snoop packets. Just pass through.
class Passthrough:
    def __init__(self):
        self.filter = IpTables()
        self.server_mitm_hosts = MyHostMatcher(XHostMatcher([l for l in open('sitm.txt')]))

    def next_layer(self, layer):
        if(layer.server_conn.address is not None):
            server = layer.server_conn.address[0]

            if(server is not None):
                if(self.server_mitm_hosts(server)):
                    ctx.log.debug("PASS: server %s matched sitm host list" % server)
                    return
                if(not self.filter.checkSite(server)):
                    return

            root = layer.ctx
            if(self.refresh or root.config.check_ignore is None or len(root.config.check_ignore.regexes) == 0):
                root.config.check_ignore = self.server_mitm_hosts

    def serverconnect(self, conn):
        return self.filter.serverconnect(conn)

