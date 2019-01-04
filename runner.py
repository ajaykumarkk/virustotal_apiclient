import requests
import time
import csv
import sys


def getdata(hash,apikey):
	params = {'apikey': apikey, 'resource':hash}
	headers = {"Accept-Encoding": "gzip, deflate","User-Agent" : "gzip,  My Python requests library example client or username"}
	success = False
	sample_info={}
	response_dict={}
	try:
		response_dict = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params).json()			
	except Exception as e:
		return "API Request Error"
	return response_dict


with open('hashes.txt', 'r+') as f:
	lines = [line.rstrip('\n') for line in open('hashes.txt')]

apikeys=['','']#Place the Api keys here
if len(apikeys) <= 6 :
	waitime = (60 - len(apikeys) * 10)
else:
	waitime = 0
csv_handle=open('output.csv','w')
flag=0
print("This is a Virustotal Checker The output will be loaded into output.csv")
print("Total no.of api keys added "+str(len(apikeys))+" And the calculated wait time is "+str(waitime))
print("Total no.of hashes loaded is :"+str(len(lines)))
hashes = iter(lines)
while True:
	for api_key in apikeys:
		for i in range(0,4):
			response_dict={}
			hash=""
			try:
				hash = next(hashes)
			except:
				print("End of list")
				sys.exit()
			try:
				response_dict=getdata(hash,api_key)
				flag=0
			except:
				csv_handle.write('API Response Error(Possible limit Reached)')
				csv_handle.write('\n')
				flag=1
				pass
			sample_info={}
			try:
				if isinstance(response_dict, str):
					print("request error for hash :"+hash)
					print("-->"+response_dict)
				elif response_dict.get("response_code") != None and response_dict.get("response_code") > 0 and flag==0:
					# Hashes
					sample_info["md5"] = response_dict.get("md5")
					# AV matches
					sample_info["positives"] = response_dict.get("positives")
					sample_info["total"] = response_dict.get("total")
					csv_handle.write(sample_info["md5"]+","+str(sample_info["positives"])+","+str(sample_info["total"]))
					print(sample_info["md5"]+","+str(sample_info["positives"])+","+str(sample_info["total"]))
					csv_handle.write('\n')
				elif flag==0:
					csv_handle.write("Not Found in VT")
			except:
				print("Not in VT")
				csv_handle.write("Not Found in VT")
		print("API KEY : "+str(api_key)+" has ran 4 times")
	print("WaitTime is "+str(waitime))
	for i in range(1,waitime+7):
		print(i,end="\r")
		time.sleep(1)
	
