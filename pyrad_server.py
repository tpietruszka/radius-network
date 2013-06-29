#!/usr/bin/python2.7
# encoding: utf-8

import pyrad
from pyrad import packet, dictionary, server

class FakeServer(server.Server):
    def _HandleAuthPacket(self, pkt):
        server.Server._HandleAuthPacket(self, pkt)

        print "Received an authentication request"
        print "Attributes: "
        for attr in pkt.keys():
            print "%s: %s" % (attr, pkt[attr])
        

        reply=self.CreateReplyPacket(pkt)
        reply.code=packet.AccessAccept
        reply["User-Name"] ="ASDDDDDDDd"
        print reply
        
        self.SendReplyPacket(pkt.fd, reply)

    def _HandleAcctPacket(self, pkt):
        server.Server._HandleAcctPacket(self, pkt)

        print "Received an accounting request"
        print "Attributes: "
#         for attr in pkt.keys():
#             print "%s: %s" % (attr, pkt[attr])
        print pkt

        reply=self.CreateReplyPacket(pkt)
        
        self.SendReplyPacket(pkt.fd, reply)


srv=FakeServer(dict=dictionary.Dictionary("dictionary"))
srv.hosts["127.0.0.1"]=pyrad.server.RemoteHost("127.0.0.1", "elkaSecret", "localhost")
srv.BindToAddress("")
srv.Run()