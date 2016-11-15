#!/usr/bin/python

import requests
import base64
import urllib
import md5

with open('data/activation-info.xml', 'rb') as myfile:
	data=myfile.read()

checksum = md5.new(data).hexdigest().upper()

headers = {'User Agent': 'iTunes/12.5.1 (Windows; Microsoft Windows 7 x64 Business Edition Service Pack 1 (Build 7601); x64) AppleWebKit/7602.1050.4.4',
        'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
	'Content-Type': 'multipart/form-data; boundary='+checksum}

header = "--" + checksum + "\r\nContent-Disposition: form-data; name=\"InStoreActivation\""
header += "\r\n\r\nfalse\n--" + checksum + "\r\nContent-Disposition: form-data; name=\"activation-info\"\r\n\r\n"

data = header + data + "\r\n--" + checksum + "--\r\n"
print(data)

r = requests.post("https://albert.apple.com/deviceservices/deviceActivation", data=data, headers=headers)
print("Received response:")
print(r.text)
