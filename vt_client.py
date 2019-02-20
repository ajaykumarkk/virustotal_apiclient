#
# Name...............Virus Total API CLient
# Author.............Ajay Kumar K K
#               
#
import requests
import time
import csv
import sys

class GetOutOfLoop( Exception ):
    pass
	
def getdata(hash,apikey):
	params = {'apikey': apikey, 'resource':hash}
	headers = {"Accept-Encoding": "gzip, deflate","User-Agent" : "gzip,  My Python requests library example client or username"}
	response_dict={}
	try:
		r = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
		if r.status_code == 403:
			return "Forbidden. You don't have enough privileges to make the request"
		elif  r.status_code == 204:
			return "Request rate limit exceeded"
		elif r.status_code == 400:
			return "Bad Request"
		elif r.status_code == 200:
			response_dict = r.json()
			return response_dict
	except Exception as e:
		return "API Request Error"
	return response_dict
	
def checkVT(lines,apikeys,id):
	id=str(id)
	if len(apikeys) <= 14 :
		waitime = (60 - len(apikeys) * 4)
	else:
		waitime = 3
	csv_handle=open('output'+id+'.csv','w')
	flag=0
	el_flag=True
	#print("This is a Virustotal Checker The output will be loaded into output.csv")
	#print("Total no.of api keys added "+str(len(apikeys))+" And the calculated wait time is "+str(waitime))
	print("Total no.of hashes loaded is :"+str(len(lines)))
	hashes = iter(lines)
	unprocessed=[]
	notinvt=[]
	count=0
	try:
		while el_flag: 
			for api_key in apikeys:
				for i in range(0,4):
					response_dict={}
					hash=""
					count=count+1
					try:#getting hashes from iterator
						hash = next(hashes)
					except:
						print("End of list")
						el_flag=False
						raise GetOutOfLoop
					response_dict=getdata(hash,api_key)
					sample_info={}
					if isinstance(response_dict, str):
						#print("request error for hash :"+hash)
						#print("-->"+response_dict+" for Hash "+hash)
						if response_dict == "Request rate limit exceeded":
							#print("Changing api key..")
							unprocessed.append(hash)
							break
					elif isinstance(response_dict,dict) and response_dict.get("response_code") == 0:
						#print("Not in VT for hash :"+str(hash))
						notinvt.append(hash)
						csv_handle.write(hash+",0,0")
						csv_handle.write('\n')
					elif isinstance(response_dict,dict) and response_dict.get("response_code") == -2:
						print("In queue for scanning")
					elif isinstance(response_dict,dict) and response_dict.get("response_code") == 1:
						# Hashes
						sample_info["md5"] = response_dict.get("md5")
						# AV matches
						sample_info["positives"] = response_dict.get("positives")
						sample_info["total"] = response_dict.get("total")
						csv_handle.write(sample_info["md5"]+","+str(sample_info["positives"])+","+str(sample_info["total"]))
						print(sample_info["md5"]+","+str(sample_info["positives"])+","+str(sample_info["total"]),end = '\n')
						csv_handle.write('\n')
					else:
						print("Unknown Error for hash "+hash)
						unprocessed.append(hash)
				#print("Api Key has ran 4 times.. Changing APi Key..\n")
				time.sleep(1)
			print("WaitTime is "+str(waitime)+" Seconds")
			for i in range(1,waitime):
				print(i,end="\r")
				time.sleep(1)
	except GetOutOfLoop:
		csv_handle.close()
	print("unprocessed hashes "+str(unprocessed ))
	print("Hashes in Not in VT"+str(notinvt))
	with open('unprocessed'+id+'.txt', 'w') as f:
		for item in unprocessed:
			f.write("%s\n" % item)

