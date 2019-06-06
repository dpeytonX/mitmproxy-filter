from mitmproxy import ctx
from xhostmatcher import XHostMatcher
import re

# Alter Uplynk m3u8 playlist to remove ad segments
class Uplynk:
    def __init__(self):
        self.server_mitm_hosts = XHostMatcher(['uplynk'])

    def response(self, flow):
        if(flow.server_conn.address is None):
            return

        server = flow.server_conn.address[0]
        if(not self.server_mitm_hosts(server)):
            return

        print(flow.response)
        ct = flow.response.headers["content-type"].lower()
        if(ct is not None and ct.find("mpegurl") != -1):
            ctx.log.info("PASS: found video playlist")
            newcontent=""
            found=False
            for line in flow.response.content.splitlines():
                print(line)
                if(re.compile("UPLYNK-SEGMENT:.*?,ad").search(line.decode("utf-8"))):
                    found=True
                    ctx.log.info("PASS: removing ad")
                    continue
                if(re.compile("UPLYNK-SEGMENT:.*?,segment").search(line.decode("utf-8"))):
                    found=False
                if(not found):
                  newcontent+=line.decode("utf-8") + '\n'

            if(newcontent):
                flow.response.content=newcontent.encode("utf-8")
