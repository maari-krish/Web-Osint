import requests
import json
from bs4 import BeautifulSoup
from pprint import pprint

print("""
___       __      ______                        _______         _____         _____ 
__ |     / /_____ ___  /_                       __  __ \___________(_)_______ __  /_
__ | /| / / _  _ \__  __ \       ________       _  / / /__  ___/__  / __  __ \_  __/
__ |/ |/ /  /  __/_  /_/ /       _/_____/       / /_/ / _(__  ) _  /  _  / / // /_  
____/|__/   \___/ /_.___/                       \____/  /____/  /_/   /_/ /_/ \__/  
                                                                                    
""")
print("                                  𝕮𝖔𝖉𝖊𝖉 𝕭𝖞 𝕸𝖆𝖆𝖗𝖎-𝕶𝖗𝖎𝖘𝖍                    ")
option ="""
[1]Whois
[2]Domain Ip history
[3]Abuse Contact Lookup
[4]Reverse IP Lookup
[5]Reverse MX Lookup
[6]Reverse NS Lookup
[7]Reverse DNS Lookup
[8]DNS Record Lookup Type A
[9]DNS Record Lookup Type MX
[10]HTTP Headers
[11]Subnet Calc
[12]Find Shared Dns
[13]Zonetransfer
[14]Host search
[15]Port Scanner
[16]Ping
[17]Traceroute
[18]Google Pagerank Checker
[19]Exit
"""
print(option)

key = "d53636291b1e0d2e5bc322db8557d86cebe05182"
def scan():
    try:
        choice = input("Which option number : ")

        if choice == '1':
            print('')
            print("[+] Whois Lookup...")
            host = input("[+] Enter the Domain : ")
            print("Whois Lookup results for",host)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            url = "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=at_GGVeTALzhDZhk046qkISgdKcX2pJ4&domainName="+host
            response = requests.get(url)
            value = BeautifulSoup(response.content, features="lxml")
            data = value.find().text
            print("whois : ",data)

        elif choice == '2':
            print('')
            print("[+] Domain Ip History...")
            Domain = input("[+] Enter The Target Domain : ")
            print("IP history results for",Domain)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/iphistory/?domain="+Domain+"&apikey="+key+"&output=json"
            data = requests.get(api).json()
            print("Domain : " + data['query']['domain'])
            pprint(data['response'])
            
        elif choice == '3':
            print('')
            print("[+] Abuse Contact Lookup.....")
            lookup = input("[+] Enter the Target Domain : ")
            print("Abuse Contact Lookup results for",lookup)
            print("---------------------------------------------------------------------------------------")
            print('')
            api = "https://api.viewdns.info/abuselookup/?domain="+lookup+"&apikey="+key+"&output=json"
            data = requests.get(api).json()
            print("Domain : " + data['query']['domain'])
            print("AbuseContact : " + data['response']['abusecontact'])

        elif choice == '4':
            print('')
            print("[+] Reverse IP Lookup...")
            Ip = input("[+] Enter The Target IP : ")
            print("Reverse IP results for",Ip)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/reverseip/?host="+Ip+"&apikey="+key+"&output=json"
            data = requests.get(api).json()
            print("Domain : " + data['query']['host'])
            pprint(data['response'])

        elif choice == '5':
            print('')
            print("[+] Reverse MX Lookup...")
            Mailserver = input("[+] Enter The Target Mailserver(e.g. mail.google.com) : ")
            print("Reverse MX Lookup results for",Mailserver)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/reversemx/?mx="+Mailserver+"&apikey="+key+"&output=json"
            data = requests.get(api).json()
            pprint(data)

        elif choice == '6':
            print('')
            print("[+] Reverse NS Lookup...")
            Nameserver = input("[+] Enter The Target Nameserver(e.g. ns1.example.com) : ")
            print("Reverse NS Lookup results for",Nameserver)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/reversens/?ns="+Nameserver+"&apikey="+key+"&output=json"
            data = requests.get(api).json()
            pprint(data)

        elif choice == '7':
            print('')
            print("[+] Reverse DNS Lookup...")
            rdns = input("[+] Enter The Target IP : ")
            print("Reverse DNS Lookup results for",rdns)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/reversedns/?ip="+rdns+"&apikey="+key+"&output=json"
            data = requests.get(api).json()
            pprint(data)

        elif choice == '8':
            print('')
            print("[+] DNS Record Lookup Type A...")
            Atype = input("[+] Enter The Target Domain : ")
            print("DNS Record Lookup Type A results for",Atype)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/dnsrecord/?domain="+Atype+"&recordtype=A&apikey="+key+"&output=json"
            data = requests.get(api).json()
            print("Domain : " + data['query']['domain'])
            print("Record Type : " +data['query']['recordtype'])
            pprint(data['response'])

        elif choice == '9':
            print('')
            print("[+] DNS Record Lookup Type MX...")
            Mxtype = input("[+] Enter The Target Domain : ")
            print("DNS Record Lookup Type MX results for",Mxtype)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/dnsrecord/?domain="+Mxtype+"&recordtype=MX&apikey="+key+"&output=json"
            resp = requests.get(api)
            details = resp.json()
            print('')
            print("Domain : " + details['query']['domain'])
            print("Type : " + details['query']['recordtype'])
            print('')
            pprint(details["response"]["records"])
            print('')

        elif choice == '10':
            print('')
            print("[+] Get HTTP Headers...")
            http = input("[+] Enter The Target Domain : ")
            print("Get HTTP Headers results for",http)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.hackertarget.com/httpheaders/?q="+http
            response = requests.get(api)
            print(response.text)

        elif choice == '11':
            print('')
            print("[+] Subnetcalc...")
            subnet = input("[+] Enter The Target Domain : ")
            print("Subnet Calc results for",subnet)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.hackertarget.com/subnetcalc/?q="+subnet
            resp = requests.get(api)
            print(resp.text)

        elif choice == '12':
            print('')
            print("[+] FindsharedDns...")
            dns = input("[+] Enter The Target Domain : ")
            print("Shared DNS results for",dns)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.hackertarget.com/findshareddns/?q="+dns
            resp = requests.get(api)
            print(resp.text)

        elif choice == '13':
            print('')
            print("[+] Zonetransfer...")
            zonetransfer = input("[+] Enter The Target Domain : ")
            print("Zone Transfer results for",zonetransfer)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.hackertarget.com/zonetransfer/?q="+zonetransfer
            resp = requests.get(api)
            print(resp.text)

        elif choice == '14':
            print('')
            print("[+] Hostsearch...")
            host = input("[+] Enter The Target Domain : ")
            print("Host Search results for",host)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.hackertarget.com/hostsearch/?q="+host
            resp = requests.get(api)
            print(resp.text)

        elif choice == '15':
            print('')
            print("[+] Port Scanner...")
            port = input("[+] Enter The Target Domain : ")
            print("Port Scanner results for",port)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/portscan/?host="+port+"&apikey="+key+"&output=json"
            data = requests.get(api).json()
            pprint(data)

        elif choice == '16':
            print('')
            print("[+] Ping...")
            Ping = input("[+] Enter The Target Domain/Ip : ")
            print("Ping results for",Ping)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/ping/?host="+Ping+"&apikey="+key+"&output=json"
            data = requests.get(api).json()
            print("Domain : " + data['query']['host'])
            pprint(data['response'])

        elif choice == '17':
            print('')
            print("[+] Traceroute...")
            Traceroute = input("[+] Enter The Target Domain : ")
            print("Traceroute results for",Traceroute)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/traceroute/?domain="+Traceroute+"&apikey="+key+"&output=json"
            data = requests.get(api).json()
            print("Domain : " + data['query']['domain'])
            pprint(data['response'])

        elif choice == '18':
            print('')
            print("[+] Google Pagerank Checker...")
            pagerank = input("[+] Enter The Target Domain : ")
            print("Google Pagerank Checker results for",pagerank)
            print("-------------------------------------------------------------------------------------")
            print("\n")
            api = "https://api.viewdns.info/pagerank/?domain="+pagerank+"&apikey="+key+"&output=json"
            data = requests.get(api).json()
            print("Domain : " + data['query']['domain'])
            print("Pagerank : " + data['response']['pagerank'])

        elif choice == '20':
            exit()

    except KeyboardInterrupt:
        print("\nAborted!")
        quit()
    except:
        print("Invalid Option !\n")
        return scan()
scan()