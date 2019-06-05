from mitmproxy import ctx
from mitmproxy import exceptions

import re
import socket
 
# https://pgl.yoyo.org/adservers/serverlist.php?showintro=0;hostformat=hosts

class Filter:
    def __init__(self):
        self.sites = [line.rstrip('\n') for line in open('filters.txt')]

        for s in self.sites:
            if(s.count('.') != 3 or s.count(':') > 0):
                ip = self.getIp(s.replace('\\',''))
                if(ip is not None and len(ip) > 0):
                    self.sites.extend(ip)
                    print("PASS: found %s for %s" % (ip, s))
                else:
                    print("PASS: did not find IP for %s" % s)

        self.blocked = {}
        self.allowed = {}

    def serverconnect(self, server_conn):
        if(server_conn.address is not None):
            server = server_conn.address[0].__str__()
        else:
            server = None

        if(server is not None):
            if(not self.checkSite(server)):
                ctx.log.info("PASS: Killing flow %s" % server)
                server_conn.address = ("", server_conn.address[1])
                #raise exceptions.Kill()

    def getIp(self, host):
            try:
                lookup = socket.getaddrinfo(host,443)
                if(lookup is not None and len(lookup) > 4):
                    return [i[4][0] for i in lookup];
            except socket.gaierror as e:
                ctx.log.info("PASS: %s : %s" % (e, host))
            return None


    def getHost(self, ip):
            try:
                lookup = socket.gethostbyaddr(ip)
                if(lookup is not None and len(lookup) > 0):
                    return lookup[0];
            except socket.herror as e:
                ctx.log.info("PASS: %s : %s" % (e, ip))
            return None
        

    def checkSite(self, site):
        host = self.getHost(site)
        if(host is None):
            host = site

        if(site in self.blocked or host in self.blocked):
            return False

        if(site not in self.allowed and host not in self.allowed):
            for line in self.sites:
                p = re.compile(line, re.IGNORECASE)

                if(p.search(host) is not None or p.search(site) is not None):
                    ctx.log.info("PASS: server %s,%s matched filter %s" % (host, site, line))
                    self.blocked[site] = True
                    self.blocked[host] = True
                    return False
            self.allowed[site] = True
            self.allowed[host] = True

        return True


addons = [
    Filter()
]
