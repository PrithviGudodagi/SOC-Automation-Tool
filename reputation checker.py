import requests
import json

print("\n")
print("--------------------------------------------------------")
print("#################  Reputition checker ##################")
print("--------------------------------------------------------")

ip = input("Enter the IP address : ")

try: 
    url = "https://www.virustotal.com/api/v3/ip_addresses/%s" % ip
    headers = {
"accept": "application/json",
"x-apikey": "<-- add api key here -->"
}
except:
     print("Invalid Input")

response = requests.get(url, headers=headers)

results = response.json()
res_str = json.dumps(results)
resp = json.loads(res_str)

reference = "https://www.virustotal.com/gui/ip-address/"+ip

print ("Reputition check for IP : " + ip)
print("\n")

print("Owner: ", str(resp['data']['attributes']['as_owner']))
print("Reputition: ", str(resp['data']['attributes']['reputation']))
print("Total harmless scans ", str(resp['data']['attributes']['last_analysis_stats']['harmless']))
print("Total malicious scans ", str(resp['data']['attributes']['last_analysis_stats']['malicious']))
print("Total suspicious scans ", str(resp['data']['attributes']['last_analysis_stats']['suspicious']))
print("Total undetected scans ", str(resp['data']['attributes']['last_analysis_stats']['undetected']))
print("Virustotal report reference :", reference)

