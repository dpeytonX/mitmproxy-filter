from mitmproxy import ctx
from mitmproxy.proxy.config import HostMatcher
from filterads import Filter
import re
 

# Passthrough - For an SSL proxy, we don't need to snoop packets. Just pass through.
class XHostMatcher:

    def __init__(self):
        self.regexes = [re.compile('\w*')]

    def __call__(self, address):
        if not address:
            return False
        host = "%s:%s" % address
        if any(rex.search(host) for rex in self.regexes):
            return True
        else:
            return False

    def __bool__(self):
        return True

class Passthrough:
    def __init__(self):
        self.filter = Filter()

    def next_layer(self, layer):
        if(layer.server_conn.address is not None):
            server = layer.server_conn.address[0]

            if(server is not None):
                if(not self.filter.checkSite(server)):
                    #raise Exception('Filtering  %s' % server);
                    return

            root = layer.ctx
            if(root.config.check_ignore is None or len(root.config.check_ignore.regexes) == 0):
                root.config.check_ignore = XHostMatcher()

    def serverconnect(self, conn):
        return self.filter.serverconnect(conn)

addons = [
    Passthrough()
]
