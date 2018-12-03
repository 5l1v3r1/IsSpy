#!/usr/bin/python
#
###################################################
#[S] SCRIPT : IssPy                               #
#[V]Version : 1.0                                 #
#[J]    JOB : Get GeoIP INFO OF Foreign_IPs       #
#[C]CodedBy : Oseid Aldary                        #
###################################################
#
#
#Modules
try:
  import socket,re,urllib2,json,sys
  from os import system as sy , popen, geteuid as uid; from time import sleep
  sy("")
except ImportError as e:
	e = e[0][16:]
	print("[!] Please Install[ {} ] Module !!".format(e))
	exit(1)

####=COLORS=########
wi = '\033[1;37m' ##>>White
rd = '\033[1;31m' ##>Red
gr = '\033[1;32m' ##>Green
yl = '\033[1;33m' ##>Yallow
bl = '\033[1;34m' ##>Blue
pu = '\033[1;35m' ##>Purple
cy = '\033[1;36m' ##>Cyan
####################

class checkmecon:
	def cnet(self):
            try:
                ip = socket.gethostbyname("www.google.com")
                con = socket.create_connection((ip, 80), 2)
                return True
            except socket.error:
                pass
            return False

	def Windows(self):
            if  sys.platform not in ["win32", "win64"]:
                    print(rd+"\n["+yl+"!"+rd+"] Error:"+yl+" Your Not Using ["+rd+"Windows OS"+yl+"]"+rd+" !!!"+wi)
                    exit(1)
            if self.cnet() !=True:
                print(rd+"\n["+yl+"!"+rd+"] Error:"+yl+" Please Check Your Internet Connection "+rd+"!!!")
                exit(1)

	    print(yl+"Proto    "+gr+"LocalAddr "+yl+"&"+gr+" PORT"+rd+"       Foreign Address"+cy+"        Status          "+bl+"PID")
	    print(yl+"==========================================================================="+wi)
	    data = popen('netstat -no | findstr "ESTABLISHED"').read()
	    print(data)
	    print(yl+"\n===========================================================================")
	    data = data.split(" ")
	    foreign_IPs = []
	    for i in data:
                if re.findall( r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", i):
                    foreign_IPs.append(i.split(":")[0])
	    print(gr+"["+wi+"*"+gr+"]"+wi+" LookUP All "+gr+"Foreign Addresses...")
	    sleep(1.2)
	    checked = []
	    loop = 1
	    for i in range(1,len(foreign_IPs),2):
                ip = foreign_IPs[i]
                if ip in checked: continue
                if len(foreign_IPs) <=8:
                    try:
                        url = "http://ip-api.com/json/"
                        response = urllib2.urlopen(url + str(ip))
                        name = response.read()
                        labs = json.loads(name.decode("utf-8"))
                        print(" ")
                        region = labs['regionName']
                        print(rd+"INFO"+gr+":["+wi+str(ip)+gr+"]===:["+yl+str(loop)+gr+"]")
                        sleep(0.10)
                        print(gr + "\t\t IP: " +wi+ labs['query'])
                        sleep(0.10)
                        print(gr+ "\t\t Status: " +wi+ labs['status'])
                        sleep(0.10)
                        print(gr+ "\t\t Region: "+wi+"{}".format(region))
                        sleep(0.10)
                        print(gr + "\t\t Country: " +wi+ labs['country'])
                        sleep(0.10)
                        print(gr + "\t\t City: " +wi+ labs['city'])
                        sleep(0.10)
                        print(gr + "\t\t ISP: "+wi + labs['isp'])
                        sleep(0.10)
                        print(gr + "\t\t Lat,Lon: "+wi + str(labs['lat']) + "," + str(labs['lon']))
                        sleep(0.10)
                        print(gr + "\t\t ZIPCODE: "+wi + labs['zip'])
                        sleep(0.10)
                        print(gr + "\t\t TimeZone: " +wi+ labs['timezone'])
                        sleep(0.10)
                        print(gr + "\t\t AS: " +wi+ labs['as'])
                        sleep(0.10)
                        print(pu+"===============================\n"+wi)
                        checked.append(ip)
                        loop+=1
                    except KeyboardInterrupt:
                        print(" ")
                        exit(1)
                    except:
		        print(rd+"\t\t ["+yl+"!"+rd+"]"+yl+" Something Went Wrong"+rd+" !!!")
                        pass
		else:
                   try:
                        url = "http://ip-api.com/json/"
                        response = urllib2.urlopen(url + str(ip) )
                        name = response.read()
                        labs = json.loads(name.decode("utf-8"))
                        print(" ")
                        region = labs['regionName']
                        print(rd+"INFO"+gr+":["+wi+str(ip)+gr+"]===:["+yl+str(loop)+gr+"]")
                        print(gr + "\t\t IP: " +wi+ labs['query'])
                        print(gr+ "\t\t Status: " +wi+ labs['status'])
                        print(gr+ "\t\t Region: "+wi+"{}".format(region))
                        print(gr + "\t\t Country: " +wi+ labs['country'])
                        print(gr + "\t\t City: " +wi+ labs['city'])
                        print(gr + "\t\t ISP: "+wi + labs['isp'])
                        print(gr + "\t\t Lat,Lon: "+wi + str(labs['lat']) + "," + str(labs['lon']))
                        print(gr + "\t\t ZIPCODE: "+wi + labs['zip'])
                        print(gr + "\t\t TimeZone: " +wi+ labs['timezone'])
                        print(gr + "\t\t AS: " +wi+ labs['as'])
                        print(pu+"===============================\n"+wi)
                        checked.append(ip)
                        loop+=1
                   except KeyboardInterrupt:
                           print(" ")
                           exit(1)
                   except:
			print(rd+"\t\t ["+yl+"!"+rd+"]"+yl+" Something Went Wrong"+rd+" !!!")
                        pass

        def Linux(self):
                if  sys.platform not in ["linux", "linux2"]:
                        print(rd+"\n["+yl+"!"+rd+"] Error:"+yl+" Your Not Using ["+rd+"Linux OS"+yl+"]"+rd+" !!!"+wi)
                        exit(1)
		if uid() !=0:
		 	print(rd+"\n["+yl+"!"+rd+"]"+yl+" Error: Please Run This Script As "+gr+"ROOT"+rd+" !!!")
			exit(1)
		if self.cnet() !=True:
			print(rd+"\n["+yl+"!"+rd+"] Error:"+yl+" Please Check Your Internet Connection "+rd+"!!!")
			exit(1)
                print(yl+"Proto "+wi+"Recv-Q Send-Q "+gr+"Local Address           "+rd+"Foreign Address         "+cy+"Status"+bl+"      PID/Program-Name")
		print(yl+"================================================================================================="+wi)
                data = popen("cd Core/ && bash netstat.sh").read()
		print(data)
		print(yl+"\n================================================================================================="+wi)
		fop = open("Core/ips.txt", "r").readlines()
		if len(fop) <1:
                     print(rd+"["+yl+"!"+rd+"]"+yl+" No Connections Was Found "+rd+"!!!")
                     exit(1)
                print(gr+"["+wi+"*"+gr+"]"+wi+" LookUP All "+gr+"Foreign Addresses...")
                sleep(1.2)
                checked = []
                loop = 1
		for ip in fop:
		   if not ip.strip(): continue
		   ip = ip.strip()
		   if ip in checked: continue
		   if len(fop) <=4:
			try:
				url = "http://ip-api.com/json/"
				response = urllib2.urlopen(url + str(ip) )
				name = response.read()
				labs = json.loads(name.decode("utf-8"))
				print(" ")
				region = labs['regionName']
				print(rd+"INFO"+gr+":["+wi+str(ip)+gr+"]===:["+yl+str(loop)+gr+"]")
				sleep(0.10)
				print(gr + "\t\t IP: " +wi+ labs['query'])
				sleep(0.10)
				print(gr+ "\t\t Status: " +wi+ labs['status'])
                                sleep(0.10)
				print(gr+ "\t\t Region: "+wi+"{}".format(region))
				sleep(0.10)
				print(gr + "\t\t Country: " +wi+ labs['country'])
				sleep(0.10)
				print(gr + "\t\t City: " +wi+ labs['city'])
				sleep(0.10)
				print(gr + "\t\t ISP: "+wi + labs['isp'])
				sleep(0.10)
				print(gr + "\t\t Lat,Lon: "+wi + str(labs['lat']) + "," + str(labs['lon']))
				sleep(0.10)
				print(gr + "\t\t ZIPCODE: "+wi + labs['zip'])
				sleep(0.10)
				print(gr + "\t\t TimeZone: " +wi+ labs['timezone'])
				sleep(0.10)
				print(gr + "\t\t AS: " +wi+ labs['as'])
				sleep(0.10)
				print(pu+"===============================\n"+wi)
				checked.append(ip)
				loop+=1
			except KeyboardInterrupt:
				print(" ")
				exit(1)
			except:
			    print(rd+"\t\t ["+yl+"!"+rd+"]"+yl+" Something Went Wrong"+rd+" !!!")
			    pass

		   else:
			try:
				url = "http://ip-api.com/json/"
				response = urllib2.urlopen(url + str(ip) )
				name = response.read()
				labs = json.loads(name.decode("utf-8"))
				print(" ")
				region = labs['regionName']
				print(rd+"INFO"+gr+":["+wi+str(ip)+gr+"]===:["+yl+str(loop)+gr+"]")
				print(gr + "\t\t IP: " +wi+ labs['query'])
				print(gr+ "\t\t Status: " +wi+ labs['status'])
				print(gr+ "\t\t Region: "+wi+"{}".format(region))
				print(gr + "\t\t Country: " +wi+ labs['country'])
				print(gr + "\t\t City: " +wi+ labs['city'])
				print(gr + "\t\t ISP: "+wi + labs['isp'])
				print(gr + "\t\t Lat,Lon: "+wi + str(labs['lat']) + "," + str(labs['lon']))
				print(gr + "\t\t ZIPCODE: "+wi + labs['zip'])
				print(gr + "\t\t TimeZone: " +wi+ labs['timezone'])
				print(gr + "\t\t AS: " +wi+ labs['as'])
				print(pu+"===============================\n"+wi)
				checked.append(ip)
				loop+=1
			except KeyboardInterrupt:
				print(" ")
				exit(1)
			except:
			    print(rd+"\t\t ["+yl+"!"+rd+"]"+yl+" Something Went Wrong"+rd+" !!!")
			    pass

checkmecon = checkmecon()

def Main():
    if len(sys.argv) !=2:
        print("""

               ####  ######   ######  ########  ##    ## 
                ##  ##    ## ##    ## ##     ##  ##  ##  
                ##  ##       ##       ##     ##   ####   
                ##   ######   ######  ########     ##    
                ##        ##       ## ##           ##    
                ##  ##    ## ##    ## ##           ##    
               ####  ######   ######  ##           ##    
====================================================================
|               [-*-[-*-[-*-> [Is-Spy] <-*-]-*-]-*-]               |
|==================================================================|
|[J] Get Your System[ESTABLISHED] Foreign_IP_Addresses GeoIP INFO  |
|==================================================================|
|[V] Script Version: 1.0                                           |
|==================================================================|
|[A] Coded By: Oseid Aldary                                        | 
|==================================================================| 
|[?] Select Your System From Menu:                                 |
===================================================================+
     1) Windows
     2) Linux

     3) Exit -->""")

        ch = raw_input("\n[IsSpy->Choice]=> ")
        while ch=="" or ch is None or ch not in ["1","2","3"]:
                ch = raw_input("[IsSpy->Choice]=> ")
        if ch =="1":
                print("")
                checkmecon.Windows()
        elif ch=="2":
                print("")
                checkmecon.Linux()
        else:
                print(rd+"\n["+yl+"!"+rd+"]"+yl+" Exiting..."+rd+"!")
                sleep(1)
                print(cy+"~"+gr+"GoodBye :)"+wi)
                exit(1)
    else:
       ch = sys.argv[1]
       if ch in ["-h","--help","-hh","--HELP","/?","?","help"]:
		print("""\n
####  ######   ######  ########  ##    ## 
 ##  ##    ## ##    ## ##     ##  ##  ##  
 ##  ##       ##       ##     ##   ####   
 ##   ######   ######  ########     ##    
 ##        ##       ## ##           ##    
 ##  ##    ## ##    ## ##           ##    
####  ######   ######  ##           ##    
=========================================
Usage: python isspy.py [1] OR [2]
=========================================
   [1] For Select Windows Os
   [2] For Select Linux Os
========================================
Examples:
       python isspy.py 1
       python isspy.py 2
""")
		exit(1)
       else:
	 if ch in ["1","win","WIN","windows","WINDOWS"]:
		checkmecon.Windows()
	 elif ch in ["2","linux","LINUX","Linux"]:
		checkmecon.Linux()
	 else:
	   print(rd+"\n["+yl+"!"+rd+"]"+yl+" IsSpy: Error: No Such Option: "+ch)
	   exit(1)

if __name__=="__main__":
        try:
           Main()
        except Exception as e:
           pass

##############################################################
##################### 		     #########################
#####################   END OF TOOL  #########################
#####################                #########################
##############################################################
#This Tool by Oseid Aldary
#Have a nice day :)
#GoodBye
