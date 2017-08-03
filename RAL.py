import whois
from pathlib import Path
import subprocess
import os.system
import webbrowser
import sys
import socket
import urllib2
from BeautifulSoup import BeautifulSoup

def tool_menu():
	print("	______  ___   _                 _                ")
	print("	| ___ \/ _ \ | |               | |               ")
	print("	| |_/ / /_\ \| |     ___   ___ | | ___   _ _ __  ")
	print("	|    /|  _  || |    / _ \ / _ \| |/ / | | | '_ \ ")
	print("	| |\ \| | | || |___| (_) | (_) |   <| |_| | |_) |")
	print("	\_| \_\_| |_/\_____/\___/ \___/|_|\_\\__,_| .__/ ")
	print("											  | |    - Reconnaissance Automated Lookup")
	print("											  |_|    - Whtn \'whtn.begins@gmail.com\'")
def cf(domain):
	"""Check if project file is created for the lookup"""
	path = "/projects/%s.txt" % (domain)
	path_to_file = Path(path)
	if !path_to_file.is_file():
		file = open(path,”w”)
			file.write("domain :\t%s" % (domain))
			file.write("ip     :\t%s" % (str(socket.gethostbyname(domain))))
		file.close()
	else:
		pass
	return path
def whois(domain):
	""" Perform whois on the domain"""
	dmn = whois.query(domain)
	a = datetime.datetime.now()
	print("[-] Domain name    :\t%s" %(dmn.name))
	print("[-] Creation date  :\t%s" %(str(dmn.creation_date))
	print("[-] Expiration date:\t%s" %(str(dmn.expiration_date)))
	print("[-] Last Updated   :\t%s" %(str(dmn.last_updated)))
	print("[-] Registrar      :\t%s" %(dmn.registrar))
	webbrowser.open_new("http://viewdns.info/whois/?domain=%s" % (domain))
	b = datetime.datetime.now()
	print("--> Fetched in: %s" % (str(b-a)))
	file = open(cf(domain), "a")
	file.write("------------------------------------[WHOIS]------------------------------------")
	file.write(domain.__dict__)
	file.close()
def ns_lookup(domain):
	"""Ns lookup"""
	x = datetime.datetime.now()
	process = subprocess.Popen(["nslookup", "www.google.com"], stdout=subprocess.PIPE)
	output = process.communicate()[0].split('\n')
	ip_arr = []
	for data in output:
		if 'Address' in data:
			ip_arr.append(data.replace('Address: ',''))
	ip_arr.pop(0)
	file = open(cf(domain), "a")
	file.write("----------------------------------[NSlookup]-----------------------------------")
	numb = 0
	file.write("[-]\tRegular nslookup :")
	for ip in ip_arr :
		numb = numb + 1
		print("-%d-\t%s" % (numb, str(ip)))
		file.write("-%d-\t%s" % (numb, str(ip)))
	print("[-] Trying nslookup -type=mx %s" % (domain))
	os.system("nslookup -type=mx %s" % (domain))
	file.write("[-]\tnslookup -type=mx %soutput" % (domain))
	file.write(os.system("nslookup -type=mx %s" % (domain)))
	y = datetime.datetime.now()
	print("--> Fetched in: %s" % (str(y-x)))
	file.close()
def traceroute(domain):
	""" traceroute from securityblog.gr/1047/simple-python-traceroute/"""
	e = datetime.datetime.now()
	file = open(cf(domain), "a")
	print("[-]\t Traceroute for %s" % (domain))
	print("--> Note that by default that the default port is 80 and max hops is set to 30 by default")
	file.write("---------------------------------[Traceroute]----------------------------------"
    destination = socket.gethostbyname(hostname)
    icmp = socket.getprotobyname('icmp')
    udp = socket.getprotobyname('udp')
    ttl = 1
    while True:
        recvsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        sendsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
        sendsock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        recvsock.bind(("", 80))
        sendsock.sendto("", (hostname, 80))
        currentaddr = None
        currenthostname = None
        try:
            _, currentaddr = recvsock.recvfrom(512)
            currentaddr = currentaddr[0]
 
            try:
                currenthostname = socket.gethostbyaddr(currentaddr)[0]
            except socket.error:
                currenthostname = currentaddr
        except socket.error:
            pass
        finally:
            sendsock.close()
            recvsock.close()
 
        if currentaddr is not None:
            currenthost = "%s (%s)" % (currenthostname, currentaddr)
        else:
            currenthost = "*"
        print("%dt%s" % (ttl, currenthost))
		file.write(os.system("%dt%s" % (ttl, currenthost))
        ttl += 1
        if currentaddr == destination or ttl > 30:
            break
	file.close()
	f = datetime.datetime.now()
	print("--> Fetched in: %s" % (str(f-e)))
def rev_domain_lookup(domain):
	""" Find other domains in the same server """
	m = datetime.datetime.now()
	file = open(cf(domain), "a")
	file.write("--------------------------------[DomainRev]----------------------------------"
	print("[-]\t Reverse domain lookup from ip: %s" % (str(socket.gethostbyname(domain))))
	print("--> Fetching first 1000 domains from viewdns.info" :)
	page_view_dns = urllib2.urlopen("http://viewdns.info/reverseip/?host=%s&t=1" % (domain))
	soup = BeautifulSoup(page_view_dns)
	table = soup.find("table")
	links = []
	for row in table.findAll('tr'):
		cells = row.findall("td")
		links.append(cells)
	del links[0, 1]
	for link in links:
		if links.index(link)%2 == 0:
			print("[--]\tDomain : ",link,"\t", end="")
			file.write("[--]\tDomain : ",link,"\t", end="")
		else:
			print("Last RD :", link)
			file.write("Last RD :", link)
	file.close()
	n = datetime.datetime.now()
	print("--> Fetched in: %s" % (str(n-m)))
def _initialize_arguments(self):
	parser = argparse.ArgumentParser('Pentester Automation Tool : Reconnaissance Automated Lookup')
	parser.add_argument("-d","--domain",type=str,help="The Domain Name to lookup")
	parser.add_argument("-w","--whois",help="whois of domain",action="store_true")
	parser.add_argument("-nl","--ns_lookup",help="NSlookup",action="store_true")
	parser.add_argument("-tr","--traceroute",help="Traceroute",action="store_true")
	parser.add_argument("-rl","--rev_domain_lookup",help="Check/Test the DNS security",action="store_true")
	args= parser.parse_args()
	if args.domain == None:
			self._usage()
	return args