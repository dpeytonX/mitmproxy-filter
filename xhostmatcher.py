import re

class XHostMatcher:

    def __init__(self, regex=None):
        if(regex is None):
          self.regexes = [re.compile('\w*')]
        self.regexes = [re.compile(r) for r in regex]

    def __call__(self, address):
        if not address:
            return False
        host = address
        if any(rex.search(host) for rex in self.regexes):
            return True
        else:
            return False

    def __bool__(self):
        return True

