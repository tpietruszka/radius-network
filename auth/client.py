# coding: utf-8

import pyrad.packet
from auth import CodeAccessRequest, TimeoutError, ATTRIBUTE_KEYS
import socket
import time
import select

class client:
    def __init__(self, host, port, secret, retry_count, timeout):
        self.host = host
        self.port = port
        
        self.secret =  str(secret)
        self.retry_count = retry_count
        self.timeout = float(timeout)/1000
        
        self._socket = None
        
    
    def _SocketOpen(self):
        if not self._socket:
            self._socket = socket.socket(socket.AF_INET,
                                       socket.SOCK_DGRAM)
            self._socket.setsockopt(socket.SOL_SOCKET,
                                    socket.SO_REUSEADDR, 1)

    def _CloseSocket(self):
        if self._socket:
            self._socket.close()
            self._socket = None
            
            
    def authorize(self, user_name, password):
        request = pyrad.packet.AuthPacket(CodeAccessRequest, id=None, secret=self.secret, authenticator=None, dict=ATTRIBUTE_KEYS)
        request.AddAttribute(ATTRIBUTE_KEYS['User-Name'], user_name)
        request.AddAttribute(ATTRIBUTE_KEYS['User-Password'], password)
        
        self._SendPacket(request)
        
    def _SendPacket(self, pkt):
        """Send a packet to a RADIUS server.

        :param pkt:  the packet to send
        :type pkt:   pyrad.packet.Packet
        :param port: UDP port to send packet to
        :type port:  integer
        :return:     the reply packet received
        :rtype:      pyrad.packet.Packet
        :raise Timeout: RADIUS server does not reply
        """
        self._SocketOpen()

        for i in range(self.retry_count):
            self._socket.sendto(pkt.RequestPacket(), (self.host, self.port))

#             now = time.time()
#             waitto = now + self.timeout
# 
#             while now < waitto:
            ready = select.select([self._socket], [], [], self.timeout)
            
            if ready[0]:
                rawreply = self._socket.recv(4096)
                break
            else:
                 continue
#                 else:
#                     now = time.time()
#                     continue

        try:
            reply = pkt.CreateReply(packet=rawreply)
            if pkt.VerifyReply(reply, rawreply) or True:
                return reply
            else:
                raise pyrad.packet.PacketError ("Verification failed")
        except pyrad.packet.PacketError:
            print "packetError"

#                 now = time.time()

        raise TimeoutError("No response from the server after " + str(self.retry_count) + " tries") 
    
