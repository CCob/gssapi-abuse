
from ldap3 import Connection

class ComputerSearch:

    _ldapConnection : Connection = None
    
    def __init__(self, url, user, password):
        
        self._ldapConnection = Connection(url, user=user,password=password, authentication='NTLM')
        if self._ldapConnection.bind() == False:
            raise Exception("LDAP login failed")


    def find_linux_hosts(self):

        hosts = []
        
        if self._ldapConnection.search(search_filter = "(&(objectClass=computer)(!(operatingSystem=*Windows*)))", attributes=['dNSHostName'], search_base='DC=ad,DC=ginge,DC=com') == True:
                    
            for result in self._ldapConnection.response:
                if(result['type'] == 'searchResEntry' and len(result['attributes']['dNSHostName']) > 0):
                    hosts.append(result['attributes']['dNSHostName'])

        return hosts