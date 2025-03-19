from dnslib import DNSRecord, DNSHeader, DNSBuffer, DNSQuestion, RR, QTYPE, RCODE
from socket import socket, SOCK_DGRAM, AF_INET

ROOT_SERVERS = ["198.41.0.4", "170.247.170.2", "192.33.4.12", "199.7.91.13", "192.203.230.10",
 "192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129", 
 "199.7.83.42", "202.12.27.33"]

DNS_PORT = 53

cache = {}

def resolve_url_to_ip(url):
  domain = url.split(".")[-1].split("/")[0]
  ip = check_cache(url, domain)
  cache["ip:"+url] = ip
  print(f"IP address for {url} is {ip}\n")

def check_cache(url, domain):
  url_parts = url.split(".")
  subdomain = url_parts[-2] + "." + domain
  
  if ("ip:"+url) in cache:
    return cache["ip:"+url]
  elif ("ns:"+subdomain) in cache:   
    print(f"Querying {subdomain} name servers from cache for {url}")

    ip = query_ns(url, cache["ns:"+subdomain], domain)
    return ip
  elif ("tld:"+domain) in cache:
    print(f"Querying {domain} tlds from cache for {subdomain}")

    name_servers = query_tld(subdomain, cache["tld:"+domain])
    ip = query_ns(url, name_servers, domain)
    return ip
  else:
    tlds = query_root(url, domain)

    if not tlds:
      print(f"No TLD servers found for domain {domain}")
      return

    name_servers = query_tld(subdomain, tlds)

    if not name_servers:
      print(f"No name servers found for {subdomain}")
      return

    ip = query_ns(url, name_servers, domain)
    if not ip:
      print(f"No IP address found for {url}")
    return ip

def query_root(url, domain):
  tlds = []
  for root in ROOT_SERVERS:
    print(f"Querying root server {root} for {domain}")
    answers, name_servers, additional = get_dns_record(sock, domain, root, "NS")
    
    for tld in name_servers:
      if tld not in tlds and tld in additional:
        tlds.append(additional[tld])

    if tlds:
      cache["tld:"+domain] = tlds
      return tlds

  return tlds

def query_tld(subdomain, tlds):
  name_servers = []

  query = subdomain if subdomain else url

  for tld in tlds:
    print(f"Querying TLD {tld} for {subdomain}")
    answers, name_servers, additional = get_dns_record(sock, subdomain, tld, "NS")
    
    if name_servers:
      cache["ns:"+subdomain] = name_servers
      return name_servers
  
  return name_servers

def query_ns(url, name_servers, domain):
  for ns in name_servers:
    print(f"Querying name server {ns} for {url}")
    answers, name_servers, additional = get_dns_record(sock, url, ns, "A")

    for a in answers:
      if a.rtype == QTYPE.A:
        ip = str(a.rdata)
        return ip
      elif a.rtype == QTYPE.CNAME:
        alias = str(a.rdata)[:-1]
        print(f"Found alias: {alias}")
        alias_domain = alias.split(".")[-1].split("/")[0]
        return check_cache(alias, alias_domain)
    
    if name_servers:
      return query_ns(url, name_servers, domain)

  return None


def get_dns_record(udp_socket, domain:str, parent_server: str, record_type):
  q = DNSRecord.question(domain, qtype = record_type)
  q.header.rd = 0   # Recursion Desired?  NO
  udp_socket.sendto(q.pack(), (parent_server, DNS_PORT))
  pkt, _ = udp_socket.recvfrom(8192)
  buff = DNSBuffer(pkt)

  answers = []
  name_servers = []
  additional = {}
  
  try:
    header = DNSHeader.parse(buff)
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

    # Parse the answer section #3
    for k in range(header.a):
      a = RR.parse(buff)
      answers.append(a)
      if a.rtype == QTYPE.A:
        answers.append(a.rdata)

    # Parse the authority section #4
    for k in range(header.auth):
      auth = RR.parse(buff)
      if (auth.rtype == QTYPE.NS):
        name_servers.append(str(auth.rdata))

    # Parse the additional section #5
    for k in range(header.ar):
      adr = RR.parse(buff)
      if (adr.rtype == QTYPE.A):
        additional[str(adr.rname)] = str(adr.rdata)

    return answers, name_servers, additional
  except:
    print(f"Timeout or error querying {parent_server}, try next server.")
    return [], [], []

def print_cache():
  if cache:
    print("Cache:")
    for i in range(len(cache)):
      key = list(cache.keys())[i]
      print(f"{i+1}: {key}: {cache[key]}")
  else:
    print("Cache is empty.")

def remove_cache_entry(i):
  if i <= len(cache):
    key = list(cache.keys())[i-1]
    cache.pop(key)
    print(f"Removed {key} from cache")
  else:
    print("Invalid index")

def clear_cache():
  cache = {}
  print("Cache cleared")

while (True):
  # Create a UDP socket with 2-second timeout
  sock = socket(AF_INET, SOCK_DGRAM)
  sock.settimeout(2)

  # Get the domain name from the user
  name = input("Enter a domain name or command: ")

  if name[0] == ".":
    match name.split():
      case [".exit"]:
        break
      case [".list"]:
        print_cache()
        continue
      case ".clear":
        clear_cache()
        continue
      case [".remove", i]:
        try:
          i = int(i)
        except:
          print("Invalid index")
        remove_cache_entry(i)
        continue
      case _:
        print("Invalid Command")
        continue
  
  resolve_url_to_ip(name)

sock.close()
