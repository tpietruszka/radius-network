#!/usr/bin/python
# coding: utf-8

import pyrad
from pyrad.client import Client
from pyrad.dictionary import Dictionary
 
 
server = "localhost"
authport = 1812
secret = "elkaSecret"
dictionary = Dictionary("dictionary")
client = Client(server, authport=authport, secret=secret, dict=dictionary)
 
user = "pietro"
password = "asd"
 
request = client.CreateAuthPacket(code=pyrad.packet.AccessRequest, User_Name=user, User_Password=password)
 
 
reply = client.SendPacket(request)
if reply.code == pyrad.packet.AccessAccept:
    print "Success"
else:
    print "fail" 
print reply