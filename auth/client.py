# coding: utf-8

from auth import *
import random
import select
import socket
import struct
from auth import packet
from auth.packet import Packet

class Client:
    def __init__(self, host, port, secret, retry_count, timeout):
        self.host = host
        self.port = port
        
        self.secret = str(secret)
        self.retry_count = retry_count
        self.timeout = float(timeout)/1000
        
        self._socket = None
        
    def __del__(self):
        self._socket_close()
        
        
    def _socket_open(self):
        if self._socket == None:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#             self._socket.connect((self.host, self.port))

    def _socket_close(self):
        if self._socket:
            self._socket.close()
            self._socket = None
            
    def generate_authenticator(self):
        '''A 16 byte random string'''
        v = range(0, 17)
        v[0] = '16B'
        for i in range(1, 17):
            v[i] = random.randint(1, 255)
        return apply(struct.pack, v)
    
    
    
    def authorize(self, user_name, password):
        response = None
        self._socket_open()
         
        id = random.randint(0, 255)

        authenticator = self.generate_authenticator()

        encpass = packet.encrypt(self.secret, authenticator, password)
        
        attributes = dict({ATTRIBUTE_KEYS['User-Name']: user_name,
                           ATTRIBUTE_KEYS['User-Password']: encpass})

        request = Packet(code = CodeAccessRequest, id = id, authenticator = authenticator, attributes = attributes).to_bytestring()
        
        for i in range(0, self.retry_count):
            
            self._socket.sendto(request, (self.host, self.port))
            t = select.select([self._socket, ], [], [], self.timeout)
            if t[0]:
                response = self._socket.recv(4096)
            else: 
                # timeout detected
                print "attempt ", i+1, " - timed out"
                continue

            if ord(response[1]) == id:
                break
            else:
                # incorrect id - a response to something else?
                print "Response with an incorrect ID received - ignored"
                continue
    
        self._socket_close()
        
        if response == None:
            raise TimeoutError("Timed out after " + str(self.retry_count) + " attempts")
        
        result = Packet.from_bytestring(response)
        
        if result.code == CodeAccessAccept:
            authorized = True    
        else:
            authorized = False
        
        try:
            reply_message = result.attributes[ATTRIBUTE_KEYS['Reply-Message']]
        except KeyError:
            reply_message = ""
        return (authorized, reply_message)
        
