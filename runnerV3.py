import sys
import os
import time
from multiprocessing import Process,Manager
import csv
from vt_client import *

def chunkIt(seq, num):
	avg = len(seq) / float(num)
	out = []
	last = 0.0
	while last < len(seq):
		if seq[int(last):int(last + avg)] != []:
			out.append(seq[int(last):int(last + avg)])
		last += avg
	return out

def mergeadnremove(fnm):
	fout=open(fnm+".csv","a")
	for i in range(0,len(api_keys_list)):
		f = open(fnm+str(i)+".csv")
		for line in f:
			 fout.write(line)
		f.close()
		os.remove(fnm+str(i)+".csv")
	fout.close()
	
if __name__ == '__main__':
	hash_list=[]
	api_keys_list=[]
	with open('hashes.txt', 'r+') as f:
		lines = [line.rstrip('\n') for line in open('hashes.txt')]
	with open('apikeys.txt', 'r') as f:
		apikeys = [line.rstrip('\n') for line in open('apikeys.txt')]
	if len(apikeys) > 5:
		api_keys_list=chunkIt(apikeys,5)
		hash_list=chunkIt(lines,5)
	else:
		api_keys_list=chunkIt(apikeys,len(apikeys))
		hash_list=chunkIt(lines,len(apikeys))
	processlist=[]
	for i in range(0,len(api_keys_list)):
		p1=Process(target=checkVT, args=(hash_list[i],api_keys_list[i],str(i),))
		p1.start()
		processlist.append(p1)
	for p in processlist:
		p.join()
	mergeadnremove("output")
	mergeadnremove("unprocessed")
		
	