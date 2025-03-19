from dnslib import DNSRecord, DNSHeader, DNSBuffer, DNSQuestion, RR, QTYPE, RCODE
from socket import socket, SOCK_DGRAM, AF_INET

ROOT_SERVERS = ["198.41.0.4", "170.247.170.2", "192.33.4.12", "199.7.91.13", "192.203.230.10",
 "192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129", 
 "199.7.83.42", "202.12.27.33"]

DNS_PORT = 53

error = False
cache = {}

def resolve_url_to_ip(url):
  domain = url.split(".")[-1].split("/")[0]
  ip = check_cache(url, domain)
  cache["ip:"+url] = ip
  print(f"IP address for {url} is {ip}")
  #print("Cache:", cache)

def check_cache(url, domain):
  url_parts = url.split(".")
  subdomain = url_parts[-2] + "." + domain
  
  if ("ip:"+url) in cache:
    #print(f"Cache hit")
    return cache["ip:"+url]
  elif ("ns:"+subdomain) in cache:
    #print(f"Cache hit for {subdomain}")    
    print(f"Querying {subdomain} name servers from cache for {url}")

    ip = query_ns(url, cache["ns:"+subdomain], domain)
    return ip
  elif ("tld:"+domain) in cache:
    #print(f"Cache hit for domain {domain}")
    print(f"Querying {domain} tlds from cache for {subdomain}")

    name_servers = query_tld(subdomain, cache["tld:"+domain])
    ip = query_ns(url, name_servers, domain)
    return ip
  else:
    #print("No results found in cache, querying root servers")
    tlds = query_root(url, domain)

    if not tlds:
      print("No results found")
      return

    name_servers = query_tld(subdomain, tlds)

    if not name_servers:
      print("No results found")
      return

    ip = query_ns(url, name_servers, domain)
    return ip

# Query the root servers for the TLDs resposible for the domain
  # and return the name servers for the TLDs
  # If the TLD is not found, return an empty list
def query_root(url, domain):
  tlds = []
  for root in ROOT_SERVERS:
    print(f"Querying root server {root} for {domain}")
    answers, name_servers = get_dns_record(sock, domain, root, "NS")

    for ns in name_servers:
      if ns not in tlds:
        tlds.append(ns)

    if tlds:
      #print(f"Found {len(tlds)} TLDs for {domain}")
      cache["tld:"+domain] = tlds
      return tlds

  return tlds

def query_tld(subdomain, tlds):
  name_servers = []

  query = subdomain if subdomain else url

  for tld in tlds:
    print(f"Querying TLD {tld} for {subdomain}")
    answers, name_servers = get_dns_record(sock, subdomain, tld, "NS")

    for ns in name_servers:
      if ns not in name_servers:
        name_servers.append(ns)
    
    if name_servers:
      #print(f"Found {len(name_servers)} name servers for {subdomain}")
      cache["ns:"+subdomain] = name_servers
      return name_servers
  
  return name_servers

def query_ns(url, name_servers, domain):
  for ns in name_servers:
    print(f"Querying name server {ns} for {url}")
    answers, name_servers = get_dns_record(sock, url, ns, "A")

    for a in answers:
      if a.rtype == QTYPE.A:
        #print(f"Found result from {ns} for {url}: {a.rdata}")
        ip = str(a.rdata)
        return ip
      elif a.rtype == QTYPE.CNAME:
        alias = str(a.rdata)[:-1]
        #print(f"Found alias for {url} from {ns}: {alias}")
        alias_domain = alias.split(".")[-1].split("/")[0]
        return check_cache(alias, alias_domain)
    
    if name_servers:
      return query_ns(url, name_servers, domain)

  return None


def get_dns_record(udp_socket, domain:str, parent_server: str, record_type):
  q = DNSRecord.question(domain, qtype = record_type)
  q.header.rd = 0   # Recursion Desired?  NO
  #print("DNS query", repr(q))
  udp_socket.sendto(q.pack(), (parent_server, DNS_PORT))
  pkt, _ = udp_socket.recvfrom(8192)
  buff = DNSBuffer(pkt)

  answers = []
  name_servers = []
  # additional = {}
  
  header = DNSHeader.parse(buff)
  #print("DNS header", repr(header))
  if q.header.id != header.id:
    print("Unmatched transaction")
    return
  if header.rcode != RCODE.NOERROR:
    print("Query failed")
    error = True
    return [], [], []

  # Parse the question section #2
  for k in range(header.q):
    q = DNSQuestion.parse(buff)
    #print(f"Question-{k} {repr(q)}")

  # Parse the answer section #3
  for k in range(header.a):
    a = RR.parse(buff)
    #print(f"Answer-{k} {repr(a)}")
    answers.append(a)
    if a.rtype == QTYPE.A:
      answers.append(a.rdata)

  # Parse the authority section #4
  for k in range(header.auth):
    auth = RR.parse(buff)
    #print(f"Authority-{k} {repr(auth)}")
    if (auth.rtype == QTYPE.NS):
      name_servers.append(str(auth.rdata))

  # Parse the additional section #5
  for k in range(header.ar):
    adr = RR.parse(buff)
    #print(f"Additional-{k} {repr(adr)} Name: {adr.rname}")
    # if (adr.rtype == QTYPE.A):
    #   additional[str(adr.rname)] = str(adr.rdata)

  return answers, name_servers

while (True):
  # Create a UDP socket with 2-second timeout
  sock = socket(AF_INET, SOCK_DGRAM)
  sock.settimeout(2)

  # Get the domain name from the user
  name = input("Enter a domain name or enter '.exit' to exit: ")

  if (name == ".exit"):
    break
  
  # Query the root server for the NS record of the domain
  resolve_url_to_ip(name)

sock.close()
