from mitmproxy import ctx
from mitmproxy import exceptions

import re
import socket
 
# https://pgl.yoyo.org/adservers/serverlist.php?showintro=0;hostformat=hosts

class Filter:
    def __init__(self):
        self.sites = [line.rstrip('\n') for line in open('filters.txt')]

        #for s in self.sites:
        #    ip = self.getIp(s.replace('\\',''))
        #    if(ip is not None):
        #        self.sites.extend([ip])

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

    def getIp(self, host):
            try:
                lookup = socket.getaddrinfo(host,443)
                if(lookup is not None and len(lookup) > 4):
                    return lookup[4][1];
            except socket.gaierror as e:
                print("%s : %s" % (e, host))
            return None


    def getHost(self, ip):
            try:
                lookup = socket.gethostbyaddr(ip)
                if(lookup is not None and len(lookup) > 0):
                    return lookup[0];
            except socket.herror as e:
                print("%s : %s" % (e, ip))
            return ip
        

    def checkSite(self, site):
        if(site in self.blocked):
            return False

        if(site not in self.allowed):
            host = self.getHost(site)

            for line in self.sites:
                p = re.compile(line, re.IGNORECASE)

                if(p.search(host) is not None):
                    ctx.log.info("server %s matched filter %s" % (host, line))
                    self.blocked[site] = True
                    return False
            self.allowed[site] = True

        return True


addons = [
    Filter()
]
