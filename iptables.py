from mitmproxy import ctx
from mitmproxy import exceptions
from filterads import Filter

import subprocess

class IpTables(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.ipTableList = {}

    #todo: reset iptable rults on deconstruction
    def serverconnect(self, server_conn):
        result = Filter.serverconnect(self, server_conn)
        if(result is not None and result not in self.ipTableList):
            subprocess.call(["iptables","-A","OUTPUT","-d",result,"-j","REJECT"])
            subprocess.call(["iptables","-A","INPUT","-s",result,"-j","DROP"])
            self.ipTableList[result] = True

addons = [
    IpTables()
]
