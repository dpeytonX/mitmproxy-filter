from mitmproxy import ctx
from xhostmatcher import XHostMatcher
import re

class YouTube:
    def __init__(self):
        self.server_mitm_hosts = XHostMatcher(['youtube.com'])

    def request(self, flow):
        if(flow.server_conn.address is None):
            return

        ctx.log.info("YOUTUBE: checking midroll on %s" % flow.server_conn.address[0])
        if(not self.server_mitm_hosts(flow.server_conn.address)):
            return

        if(re.compile('get_midroll_info').search(flow.request.path)):
            ctx.log.info("YOUTUBE: midroll flow killed")
            flow.kill()
