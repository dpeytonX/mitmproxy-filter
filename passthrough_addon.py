from mitmproxy import ctx
from mitmproxy.proxy.config import HostMatcher
#from filterads import Filter
from iptables import IpTables
from xhostmatcher import XHostMatcher
import re

# Passthrough - For an SSL proxy, we don't need to snoop packets. Just pass through.
class Passthrough:
    def __init__(self):
        self.filter = IpTables()
        self.server_mitm_hosts = XHostMatcher([l for l in open('sitm.txt')])

    def next_layer(self, layer):
        if(layer.server_conn.address is not None):
            server = layer.server_conn.address[0]

            if(server is not None):
                if(self.server_mitm_hosts(server)):
                    return
                if(not self.filter.checkSite(server)):
                    #raise Exception('Filtering  %s' % server);
                    return

            root = layer.ctx
            if(root.config.check_ignore is None or len(root.config.check_ignore.regexes) == 0):
                root.config.check_ignore = XHostMatcher()

    def serverconnect(self, conn):
        return self.filter.serverconnect(conn)

passthrough_addon = Passthrough()
passthrough_addon.filter.restApp.start()
addons = [
    passthrough_addon
]
