from mitmproxy import ctx
import re
 
# https://pgl.yoyo.org/adservers/serverlist.php?showintro=0;hostformat=hosts

class Filter:
    def __init__(self):
        self.sites = [line.rstrip('\n') for line in open('filters.txt')]
        self.blocked = {}
        self.allowed = {}

    def request(self, flow):
        client = flow.client_conn.address[0].__str__()
        server = flow.server_conn.address[0].__str__()

        self.checkSite(flow, client)
        self.checkSite(flow, server)

    def checkSite(self, flow, site):
        if(site in self.blocked):
            ctx.log.info("Killing flow %s from previous match" % site)
            flow.kill()
            return False

        if(site not in self.allowed):
            for line in self.sites:
                p = re.compile(line, re.IGNORECASE)
                if(site in self.blocked or p.search(site) is not None):
                    ctx.log.info("Killing flow %s matching %s" % (site, line))
                    self.blocked[site] = True
                    flow.kill()
                    return False
            self.allowed[site] = True
            return True


addons = [
    Filter()
]
