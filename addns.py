import gssapi

import dns
import dns.update
import dns.name
import dns.tsig
import dns.tsigkeyring
import dns.rdtypes
import dns.rdtypes.ANY
import dns.rdtypes.ANY.TKEY
import dns.message
import dns.query
import dns.resolver

import logging
import uuid
import time
import utils

from typing import List


class SecureDnsUpdates:

    _keyring : dns.tsig.GSSTSigAdapter = None
    _keyname : dns.name.Name = None
    _server_addr : str = None
    _soa_server : str = None
    _current_update : dns.update.UpdateMessage = None
    _zone : str = None

    log = logging.getLogger('securedns')
    
    def __init__(self, zone : str, server: str = None):

        self._zone = zone; 

        #Figure out the nameserver for the zone we want to update
        nameserver = utils.get_soa(self._zone, server)
        self._soa_server = nameserver[0]
        self._server_addr = nameserver[1]
    
        # Now authenticate and negoitate a GSS-TSIG context
        # for signing DNS updates
        self._gss_tsig_init_ctx(self._soa_server, self._server_addr)

        self.log.info("[+] Successfully authenticated to DNS server %s" % (self._soa_server))

        self._current_update = dns.update.UpdateMessage(zone, keyring=self._keyring, 
                                                        keyname=self._keyname, keyalgorithm='gss-tsig.')


    def add(self, name : str, type : str, ttl : str, data : str):
        self.log.debug("[=] %s for zone %s has been added for pending addition" % (name, self._zone))
        self._current_update.add(name, ttl, type, data) 

    def delete(self, name : str):
        self.log.debug("[=] %s for zone %s has been added for pending removal" % (name, self._zone))
        self._current_update.delete(name)

    def replace(self, name : str, type : str, ttl : str, data : str):
        self.log.debug("[=] %s for zone %s has been added for pending replacement" % (name, self._zone))
        self._current_update.replace(name, ttl, type, data)  

    def apply(self, timeout=5) ->  dns.message.Message:
        result = dns.query.tcp(self._current_update, self._server_addr, timeout) 

        if result.rcode() == 0:
            self.log.info("[+] Applied %d updates successfully" % len(self._current_update.update))
        else:
            self.log.error("[!] Failed to apply %d updates with rcode %d" % (len(self._current_update.update), result.rcode()))

        self._current_update = dns.update.UpdateMessage(self._zone, keyring=self._keyring, 
                                                        keyname=self._keyname, keyalgorithm='gss-tsig.')  
        
        return result
                    
    def _build_tkey_query(self, token):
        # make TKEY record
        inception_time = int(time.time())
        tkey = dns.rdtypes.ANY.TKEY.TKEY(
            dns.rdataclass.ANY,
            dns.rdatatype.TKEY,
            dns.name.from_text('gss-tsig.'),
            inception_time,
            inception_time,
            3,
            dns.rcode.NOERROR,
            token,
            b''
        )

        # make TKEY query
        tkey_query = dns.message.make_query(
            self._keyname,
            dns.rdatatype.RdataType.TKEY,
            dns.rdataclass.RdataClass.ANY
        )

        # create RRSET and add TKEY record
        rrset = tkey_query.find_rrset(
            tkey_query.additional,
            self._keyname,
            dns.rdataclass.RdataClass.ANY,
            dns.rdatatype.RdataType.TKEY,
            create=True
        )
        rrset.add(tkey)
        tkey_query.keyring = self._keyring
        return tkey_query        


    def _gss_tsig_init_ctx(self, name_server_fqdn, name_server_ip):
        """
        initialize GSS-TSIG security context

        :param name_server_fqdn: server fqdn
        :param name_server_ip: ip address of dns server

        :return: TSIG key and TSIG key name
        """
        # generate random name
        random = uuid.uuid4()
        self._keyname = dns.name.from_text(f"{random}")
        spn = gssapi.Name(f'DNS/{name_server_fqdn}', gssapi.NameType.krb5_nt_principal_name)

        # create gssapi security context and TSIG keyring
        client_ctx = gssapi.SecurityContext(name=spn, usage='initiate')
        tsig_key = dns.tsig.Key(self._keyname, client_ctx, 'gss-tsig.')
        keyring = dns.tsigkeyring.from_text({})
        keyring[self._keyname] = tsig_key
        self._keyring = dns.tsig.GSSTSigAdapter(keyring)

        # perform GSS-API TKEY Exchange
        token = client_ctx.step()
        self.log.debug('keyname -> %s', self._keyname)
        self.log.debug('keyring -> %s', self._keyring)
        while not client_ctx.complete:
            tkey_query = self._build_tkey_query(token)
            response = dns.query.tcp(tkey_query, name_server_ip, timeout=10, port=53)
            if not client_ctx.complete:
                token = client_ctx.step(response.answer[0][0].key)
       
