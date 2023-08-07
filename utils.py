
import dns.resolver
import socket

def get_nameserver(zone : str, server : str = None):

        resolver = None
        answer = None

        if server is not None:        
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = [server]
                answer = resolver.resolve(zone, "NS")
        else:
                answer = dns.resolver.resolve(zone, "NS")

        ns_server = answer.rrset[0]
        server_addr = probe_server(ns_server, zone)        
        return (ns_server, server_addr) 


def get_soa(zone : str, server : str = None):

        resolver = None
        answer = None

        if server is not None:        
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = [server]
                answer = resolver.resolve(zone, "SOA")
        else:
                answer = dns.resolver.resolve(zone, "SOA")

        soa_server = answer.rrset[0].mname.to_text(True)  
        server_addr = probe_server(soa_server, zone)        
        return (soa_server, server_addr) 
        
def probe_server(server_name, zone):
    gai = socket.getaddrinfo(str(server_name),
                            "domain",
                            socket.AF_UNSPEC,
                            socket.SOCK_DGRAM)
    for af, sf, pt, cname, sa in gai:
        query = dns.message.make_query(zone, "SOA")
        res = dns.query.tcp(query, sa[0], timeout=10)
        return sa[0]             