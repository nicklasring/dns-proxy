from json import load
from glob import glob

BLACKLISTS = "./blacklist.d/*.list"
VIRTUAL_HOSTS = "./virtualhost.d/*.vhost"

class DNSFirewall():
    def GetBlackLists(self) -> list:
        blacklist = []
        files = glob(BLACKLISTS)
        for file in files:
            with open(file) as tmp_file:
                blacklist = blacklist + tmp_file.read().split("\n")
            tmp_file.close()
        return blacklist

    def IsAllowed(self, domain) -> bool:
        if domain in self.GetBlackLists():
            return False
        return True