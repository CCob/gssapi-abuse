
from ldap3 import Connection
from ldap3 import Server
from ldap3 import ALL

class ComputerSearch:

    _ldapConnection : Connection = None
    _base : str
    
    def __init__(self, url, user, password):
        
        server = Server(url, get_info=ALL)

        self._ldapConnection = Connection(server, user=user,password=password, authentication='NTLM')
        if self._ldapConnection.bind() == False:
            raise Exception("LDAP login failed")
            
        self._base = server.info.naming_contexts[2]
        
     
    def find_linux_hosts(self):

        hosts = []
        
        if self._ldapConnection.search(search_filter = "(&(objectClass=computer)(!(operatingSystem=*Windows*)))", attributes=['dNSHostName'], search_base=self._base) == True:
                    
            for result in self._ldapConnection.response:
                if(result['type'] == 'searchResEntry' and len(result['attributes']['dNSHostName']) > 0):
                    hosts.append(result['attributes']['dNSHostName'])

        return hosts
