import re

class XHostMatcher:

    def __init__(self, regex=None):
        if(regex is None):
            self.regexes = [re.compile('\w*')]
        else:
            self.regexes = [re.compile(r) for r in regex]

    def __call__(self, address):
        if not address:
            return False
        if isinstance(address, str):
            host = "%s" % address
        elif isinstance(address, (tuple,list)):
            host = "%s" % address[0]
        else:
            host = str(address)

        if any(rex.search(host) for rex in self.regexes):
            return True
        else:
            return False

    def __bool__(self):
        return True

