from rest import RestDelegate
from flask import request

class FilterRest(RestDelegate):
    def __init__(self, filterAddon=None):
        self.filterer = filterAddon

    def index(self):
        return """
        <html>
          <head><title>Filtering</title></head>
          <body>
            <form method="POST" action="/post">
              <p>Enter the host or IP to block</p>
              <input name="host" type="test" />
            </form>
          </body>
        </html>"""

    def post(self):
        host = request.form['host']
        if(host is None):
            return "No host received"
        with open("filters.txt", "a") as f:
            hostRegex = host.replace('.','\\.')
            f.write('%s\n' % hostRegex)
            if(self.filterer is not None):
                # For now, clear allowed list so that previously whitelisted hosts will get rechecked
                self.filterer.allowed = {}
                # Update blocked site list
                self.filterer.sites.extend([hostRegex])
                #self.filterer.addIpChains(hostRegex)
        return "<p>Wrote %s to file.</p>\n%s" % (host, self.index())


