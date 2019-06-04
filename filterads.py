from mitmproxy import ctx
from mitmproxy import exceptions

import re
 
# https://pgl.yoyo.org/adservers/serverlist.php?showintro=0;hostformat=hosts

class Filter:
    def __init__(self):
        self.sites = [line.rstrip('\n') for line in open('filters.txt')]
        self.blocked = {}
        self.allowed = {}

    def serverconnect(self, server_conn):
        if(server_conn.address is not None):
            server = server_conn.address[0].__str__()
        else:
            server = None

        if(server is not None):
            if(not self.checkSite(server)):
                ctx.log.info("Killing flow %s" % server)
                print(server_conn.address)
                server_conn.address = ("", server_conn.address[1])
                #raise exceptions.Kill()


    def checkSite(self, site):
        if(site in self.blocked):
            return False

        if(site not in self.allowed):
            for line in self.sites:
                p = re.compile(line, re.IGNORECASE)
                if(p.search(site) is not None):
                    ctx.log.info("server %s matched filter %s" % (site, line))
                    self.blocked[site] = True
                    return False
            self.allowed[site] = True

        return True


addons = [
    Filter()
]
