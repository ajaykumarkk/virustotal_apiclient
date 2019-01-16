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
	
	
with open('hashes.txt', 'r+') as f:
	lines = [line.rstrip('\n') for line in open('hashes.txt')]

apikeys=['08074dd7e431fa9f6bc342947e4707099c4adcfb4b72090286ed24fc9437f95f','924d105b1634c233f2f72d890fd1340b98cefafe6ef6939f2c88e9cf4eecdf47','c476f9625b273f5e4b4f3c3c4e8adbc33899cf2bcdc695b0ba8cb30cdd01b7f1']
if len(apikeys) <= 6 :
	waitime = (60 - len(apikeys) * 4)
else:
	waitime = 0
csv_handle=open('output.csv','w')

flag=0
el_flag=True
print("This is a Virustotal Checker The output will be loaded into output.csv")
print("Total no.of api keys added "+str(len(apikeys))+" And the calculated wait time is "+str(waitime))
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
					print("-->"+response_dict+" for Hash "+hash)
					if response_dict == "Request rate limit exceeded":
						print("Changing api key..")
						unprocessed.append(hash)
						break
				elif isinstance(response_dict,dict) and response_dict.get("response_code") == 0:
					#print("Not in VT for hash :"+str(hash))
					notinvt.append(hash)
				elif isinstance(response_dict,dict) and response_dict.get("response_code") == -2:
					print("In queue for scanning")
				elif isinstance(response_dict,dict) and response_dict.get("response_code") == 1:
					# Hashes
					sample_info["md5"] = response_dict.get("md5")
					# AV matches
					sample_info["positives"] = response_dict.get("positives")
					sample_info["total"] = response_dict.get("total")
					#csv_handle.write(sample_info["md5"]+","+str(sample_info["positives"])+","+str(sample_info["total"]))
					print(sample_info["md5"]+","+str(sample_info["positives"])+","+str(sample_info["total"]))
					#csv_handle.write('\n')
				else:
					print("Unknown Error for hash "+hash)
					unprocessed.append(hash)
			print("API KEY : "+str(api_key)+" has ran 4 times.. Changing APi Key..")
		print("WaitTime is "+str(waitime)+" Seconds")
		for i in range(1,waitime):
			print(i,end="\r")
			time.sleep(1)
except GetOutOfLoop:
	pass
print("unprocessed hashes "+unprocessed )		
print("Hashes in Not in VT"+notinvt)
