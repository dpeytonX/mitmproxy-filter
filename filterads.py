from mitmproxy import ctx
from mitmproxy import exceptions
#from filterrest import FilterRest
#from rest import MitmRest

import re
import socket
 
# https://pgl.yoyo.org/adservers/serverlist.php?showintro=0;hostformat=hosts

class Filter:
    def __init__(self):
        self.sites = [line.rstrip('\n') for line in open('filters.txt')]
        self.good = [line.rstrip('\n') for line in open('whitelist.txt')]
        self.etc_hosts = [line.replace('127.0.0.1\t','').rstrip('\n') for line in open('etc_hosts')]
        self.blocked = {}
        self.allowed = {}
        self.addIpChains(self.good)
        for g in self.good:
            self.allowed[g] = True

        #self.addIpChains(self.sites)
        #self.restDelegate = FilterRest(self)
        #self.restApp = MitmRest('Filtering',self.restDelegate)

    def addIpChains(self, hostList):
        for s in hostList:
            if(s.count('.') != 3 or s.count(':') > 0):
                ip = self.getIp(s.replace('\\',''))
                if(ip is not None and len(ip) > 0):
                    hostList.extend(ip)
                    print("PASS: found %s for %s" % (ip, s))
                else:
                    print("PASS: did not find IP for %s" % s)

    def serverconnect(self, server_conn):
        if(server_conn.address is not None):
            server = server_conn.address[0].__str__()
        else:
            server = None

        if(server is not None):
            if(not self.checkSite(server)):
                ctx.log.info("PASS: Killing flow %s" % server)
                server_conn.address = ("", server_conn.address[1])
                return server

    def getIp(self, host):
            try:
                lookup = socket.getaddrinfo(host,443)
                if(lookup is not None and len(lookup) > 4):
                    return [i[4][0] for i in lookup];
            except socket.gaierror as e:
                ctx.log.info("PASS: error getting %s" % host)
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
        if(site in self.blocked):
            if(site not in self.etc_hosts): 
                f = open('etc_hosts', 'a')
                f.write('\n127.0.0.1\t%s' % site)
                f.close()
                self.etc_hosts.extend([site])
            return False
        if(site in self.allowed):
            ctx.log.info("PASS: %s has been allowed" % site)
            return True

        host = self.getHost(site)
        if(host is None):
            host = site
        if(host in self.blocked):
            return False
        if(host in self.allowed):
            return True

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

