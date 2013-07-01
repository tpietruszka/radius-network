# coding: utf-8
import select
from auth import TimeoutError, CodeAccessAccept, ATTRIBUTE_KEYS
from auth.packet import Packet
import socket

def request_authorization(request, my_socket, server_address, server_port, retry_count, timeout):
        """Tries "retry_count" times to request authorization to a remote server,
        SOCKET SHOULD BE ALREADY OPEN 
        returns (bool authorized, string reply_message)
        throws TimeoutError if did not succeed"""
        
        response = None
        
        request_packet = request.to_bytestring()
        
        for i in range(0, retry_count):
            my_socket.sendto(request_packet, (server_address,  server_port))
            t = select.select([my_socket, ], [], [], timeout) # wait for response
            if t[0]: #response received
                response = my_socket.recv(4096)
            else: 
                # timeout detected
#                 print "attempt ", i+1, " - timed out"
                continue

            if ord(response[1]) == request.id:
                break
            else:
                # incorrect id - a response to something else?
                print "Response with an incorrect ID received - ignored"
                continue
        
        if response == None:
            raise TimeoutError("Timed out after " + str(retry_count) + " attempts")
        
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
    
def get_client_socket():
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)