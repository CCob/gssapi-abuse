# gssapi-abuse

gssapi-abuse was released as part of my DEF CON 31 talk, A Broken Marriage: Abusing Mixed Vendor Kerberos stacks.

The tool has two features.  The first is the ability to enumerate non Windows hosts that are joined to Active Directory that offer GSSAPI authentication over SSH.

The second feature is the ability to perform dynamic DNS updates for GSSAPI abusable hosts that do not have the correct forward and/or reverse lookup DNS entries.  GSSAPI based authentication is strict when it comes to matching service principals, therefore DNS entries should match the service principal name both by hostname and IP address.

## Prerequisites 

gssapi-abuse requires a working krb5 stack along with a correctly configured krb5.conf.  

### Windows

On Windows hosts, the MIT Kerberos software should be installed in addition to the python modules listed in `requirements.txt`, this can be obtained at the [MIT Kerberos Distribution Page](https://web.mit.edu/kerberos/dist/index.html).  Windows krb5.conf can be found at `C:\ProgramData\MIT\Kerberos5\krb5.conf`

### Linux

The `libkrb5-dev` package needs to be installed prior to installing python requirements

### All

Once the requirements are satisfied, you can install the python dependencies via pip/pip3 tool

```
pip install -r requirements.txt
```

## Enumeration Mode

The enumeration mode will connect to Active Directory and perform an LDAP search for all computers that do not have the word `Windows` within the Operating System attribute.  

Once the list of non Windows machines has been obtained, gssapi-abuse will then attempt to connect to each host over SSH and determine if GSSAPI based authentication is permitted.

### Example

```
python .\gssapi-abuse.py -d ad.ginge.com enum -u john.doe -p SuperSecret!
[=] Found 2 non Windows machines registered within AD
[!] Host ubuntu.ad.ginge.com does not have GSSAPI enabled over SSH, ignoring
[+] Host centos.ad.ginge.com has GSSAPI enabled over SSH
```

## DNS Mode

DNS mode utilises Kerberos and dnspython to perform an authenticated DNS update over port 53 using the DNS-TSIG protocol.  Currently `dns` mode relies on a working krb5 configuration with a valid TGT or DNS service ticket targetting a specific domain controller, e.g. `DNS/dc1.victim.local`. 

### Examples

Adding a DNS `A` record for host `ahost.ad.ginge.com`
```
python .\gssapi-abuse.py -d ad.ginge.com dns -t ahost -a add --type A --data 192.168.128.50
[+] Successfully authenticated to DNS server win-af8ki8e5414.ad.ginge.com
[=] Adding A record for target ahost using data 192.168.128.50
[+] Applied 1 updates successfully
```

Adding a reverse `PTR` record for host `ahost.ad.ginge.com`.  Notice that the `data` argument is terminated with a `.`, this is important or the record becomes a relative record to the zone, which we do not want.  We also need to specify the target zone to update, since `PTR` records are stored in different zones to `A` records. 
```
python .\gssapi-abuse.py -d ad.ginge.com dns --zone 128.168.192.in-addr.arpa -t 50 -a add --type PTR --data ahost.ad.ginge.com.
[+] Successfully authenticated to DNS server win-af8ki8e5414.ad.ginge.com
[=] Adding PTR record for target 50 using data ahost.ad.ginge.com.
[+] Applied 1 updates successfully
```

Forward and reverse DNS lookup results after execution

```
nslookup ahost.ad.ginge.com
Server:  WIN-AF8KI8E5414.ad.ginge.com
Address:  192.168.128.1

Name:    ahost.ad.ginge.com
Address:  192.168.128.50
```

```
nslookup 192.168.128.50
Server:  WIN-AF8KI8E5414.ad.ginge.com
Address:  192.168.128.1

Name:    ahost.ad.ginge.com
Address:  192.168.128.50
```

