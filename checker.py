import requests
import time
with open('hashes.txt', 'r+') as f:
	lines = [line.rstrip('\n') for line in open('hashes.txt')]
i=0
for hash in lines:
	i=i+1
	if(i==5):
		i=0
		print("----Limit Reached----")
		time.sleep(50)
	
	params = {'apikey': '', 'resource':hash}
	headers = {"Accept-Encoding": "gzip, deflate","User-Agent" : "gzip,  My Python requests library example client or username"}
	success = False
	sample_info={}
	response_dict={}
	try:
		response_dict = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params).json()
			
	except Exception as e:
			print("Error ---- ")
			pass
	if response_dict.get("response_code") != None and response_dict.get("response_code") > 0:
        # Hashes
		sample_info["md5"] = response_dict.get("md5")
        # AV matches
		sample_info["positives"] = response_dict.get("positives")
		sample_info["total"] = response_dict.get("total")
		print(sample_info["md5"]+" Positives: "+str(sample_info["positives"])+"Total "+str(sample_info["total"]))
	else:
		print("Not Found in VT")
	
	
	
