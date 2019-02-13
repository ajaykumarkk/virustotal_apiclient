# virustotal_apiclient
This is a python implementation for getting virus total scores for Hashes only.
Support for multiple api keys to bypass the per minute limit

## Pre-Req:

  1. Requests
  
          pip install requests
 
## Instructions:

  1. Place the hashes in the hashes.txt file 
  
  2. Place the Virustotal apikeys in a text file called apikeys.txt one in each line
  
  3. Run using command 
  
          python runnerV2.py
          
  4.The output will be shown in the csv file(uncomment in the code) and also in the stdout
  
  ## For multiprocess 
    
     Run using command 
          
            python runnerV3.py
          
