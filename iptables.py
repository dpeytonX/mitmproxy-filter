from mitmproxy import ctx
from mitmproxy import exceptions
from filterads import Filter

import subprocess

class IpTables(Filter):
    def __init__(self):
        subprocess.call(["iptables","-F"])
        self.ipTableList = {}
        self.ipTableList['localhost']=True
        self.ipTableList['127.0.0.1']=True
        self.ipTableList['localhost.localdomain']=True
        super().__init__()

    #todo: reset iptable rults on deconstruction
    def serverconnect(self, server_conn):
        result = super().serverconnect(server_conn)
        if(result is not None and result not in self.ipTableList):
            subprocess.call(["iptables","-A","OUTPUT","-d",result,"-j","REJECT"])
            subprocess.call(["iptables","-A","INPUT","-s",result,"-j","DROP"])
            self.ipTableList[result] = True

