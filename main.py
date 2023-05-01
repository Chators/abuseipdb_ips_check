import requests
import json
import ipaddress
import uuid
import os
from datetime import datetime

if not os.path.exists('./reports'):
    os.makedirs('./reports')
    
apiKey = 'REPLACE'
fileIp = open('ip_list.txt', 'r')
ips = fileIp.readlines()
fileIp.close()

url = 'https://api.abuseipdb.com/api/v2/check'
ipsInformation = []
total_ips = len(ips)
print(f'[!] Number of ips : {total_ips}')
for i, ip in enumerate(ips):
    count = i + 1
    ip = ip.rstrip()
    print(f'[!] {count}/{total_ips} Retrieve information : {ip}')
    try:
        if not ipaddress.ip_address(ip).is_private:
            querystring = {
                'ipAddress': ip,
                'maxAgeInDays': '90'
            }
            headers = {
                'Accept': 'application/json',
                'Key': apiKey
            }
            response = requests.request(method='GET', url=url, headers=headers, params=querystring)
            decodedResponse = json.loads(response.text)['data']
            ipsInformation.append({
                'ip': decodedResponse['ipAddress'],
                'maliciousScore': decodedResponse['abuseConfidenceScore'],
                'totalReports': decodedResponse['totalReports'],
                'isp': decodedResponse['isp'],
                'domain': decodedResponse['domain'],
                'hostnames': '\n'.join(decodedResponse['hostnames']),
                'countryCode': decodedResponse['countryCode']
            })
    except:
        print(f'[X] Failed to retrieve information : {ip}')

ipsInformation = sorted(ipsInformation, key=lambda x: x['maliciousScore'], reverse=True)
fileOutputPath = './reports/'+datetime.now().strftime("%Y-%m-%d-%H-%M-%S!")+str(uuid.uuid4())+'.csv'
fileOutput = open(fileOutputPath, 'w')
fileOutput.write('IP,Malicious Score,Total Reports,ISP,Domain,Hostnames,Country Code\n')
for ipInformation in ipsInformation:
    fileOutput.write(f'{ipInformation["ip"]},{ipInformation["maliciousScore"]},{ipInformation["totalReports"]},{ipInformation["isp"]},{ipInformation["domain"]},"{ipInformation["hostnames"]}",{ipInformation["countryCode"]}\n')
fileOutput.close()
print(f'[!] Your report is available at {fileOutputPath}')
