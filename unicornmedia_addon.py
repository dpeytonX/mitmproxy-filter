from mitmproxy import ctx
from xhostmatcher import XHostMatcher
import re

# Alter UnicornMedia m3u8 playlist to remove ad segments
class UnicornMedia:
    def __init__(self):
        self.server_mitm_hosts = XHostMatcher(['unicornmedia'])

    def response(self, flow):
        if(flow.server_conn.address is None):
            return

        server = flow.server_conn.address[0]
        if(not self.server_mitm_hosts(server)):
            return

        ct = flow.response.headers["content-type"].lower()
        if(ct is not None and ct.lower().find("mpegurl") != -1):
            ctx.log.info("PASS: found video playlist")
            newcontent=""
            if(flow.response.content is not None):
                content = flow.response.content
            elif(flow.response.text is not None):
                content = flow.response.text
            else:
                content = flow.response.raw_content

            if(content is None):
                ctx.log.info("PASS: empty playlist response")
                return
        

            #We are looking for EXT-X-KEY:METHOD=NONE -> DISCONTINUITY
            found=False
            ctx.log.info("PASS: response\n %s" % content)
            for line in content.splitlines():
                #print("PASS: %s" % line)
                if(re.compile("EXT-X-KEY:METHOD").search(line.decode("utf-8"))):
                    if("METHOD=NONE" in line.decode("utf-8")):
                        found=True
                        ctx.log.info("PASS: removing ad")
                    else:
                        found=False

                if(not found):
                    ctx.log.info("PASS: %s" % line)
                    newcontent+=line.decode("utf-8") + '\n'

            if(newcontent):
                flow.response.content=newcontent.encode("utf-8")
