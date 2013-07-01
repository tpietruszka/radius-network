# coding: utf-8
import struct
try:
    from hashlib import md5
except ImportError:
    from md5 import new as md5


# length of a radius's packet header, in bytes
RADIUS_HEADER_LENGTH = 20

class Packet:
    def __init__(self, code, id, authenticator, attributes):
        self.code = code
        self.id = id
        self.authenticator = authenticator
        # a dict of Attribute-Value pairs: {code: value}
        self.attributes = attributes 
        
    def to_bytestring(self):
        data = ''
        for code in self.attributes:
            value = self.attributes[code]
            data += struct.pack('!B B %ds' % len(value), code, len(value)+2, value)
            # 2 bytes in each pair are for len and code
        
        #authenticator length - 16 bytes
        header = struct.pack('!B B H 16s', 
                             self.code, #message-type code
                             self.id, #message identifier
                             len(data)+ RADIUS_HEADER_LENGTH, #total length
                             self.authenticator)
        return header + data
        
        
    @classmethod
    def from_bytestring(cls, raw_packet):
        """ Parses a bytestring to recreate a packet.
        All attribute values are assumed to be strings
        """
        header = raw_packet[:RADIUS_HEADER_LENGTH]
        code, id, packet_len, authenticator = struct.unpack('!B B H 16s', header)
        attributes = dict()
        
        
        remaining_data = raw_packet[RADIUS_HEADER_LENGTH:]
        remaining_length = packet_len - RADIUS_HEADER_LENGTH # this should be used to stop, 
        # as packet can have padding 0's
        
        while remaining_length > 0: # parsing 1 attribute-value pair at a time
            if ord(remaining_data[0]) == 0:
                break # 0 is not a code - means padding 0s 
            
            record_length = ord(remaining_data[1])
            record = remaining_data[:record_length]
            if record_length > 2:
                key, l, value = struct.unpack('!B B %ds' % (len(record)-2), record)
            else:
                key, l = struct.unpack('!B B', record)
                value = ""
            attributes[key] = value
            remaining_data = remaining_data[record_length:] #delete parsed record 
            remaining_length -= record_length
            
        return Packet(code, id, authenticator, attributes)
            
    def __str__(self):
        result = \
        "\ncode: " + str(self.code) + \
        "\nid: " + str(self.id) + \
        "\ndata: " + str(self.attributes) + "\n"
        return result

def encrypt(secret, authenticator, password):
    """ Encrypt the password a "Shared secret" and given authenticator"""
    # pad the password with zeros to multiple of 16 octets 
    password += chr(0) * (16 - (len(password) % 16))
    if len(password) > 128:
        raise Exception('Password exceeds max. of 128 bytes')
    result = ''
    last = authenticator
    while password:
        # md5sum the shared secret with the authenticator,
        # after the first iteration, the authenticator is the previous
        # result of our encryption.
        hashed = md5(secret + last).digest()
        for i in range(16):
            result += chr(ord(hashed[i]) ^ ord(password[i]))
        # The next iteration will act upon the next 16 octets of the password
        # and the result of our xor operation above. We will set last to
        # the last 16 octets of our result (the xor we just completed). And
        # remove the first 16 octets from the password.
        last, password = result[-16:], password[16:]
    return result

def decrypt(secret, authenticator, encrypted):
    """ Decrypt the password using a "Shared secret" and given authenticator"""
    result = ''
    last = authenticator
    while encrypted:
        hashed = md5(secret + last).digest()
        for i in range(16):
            result += chr(ord(hashed[i]) ^ ord(encrypted[i]))
        last = encrypted[:16]
        encrypted = encrypted[16:]
        
        # remove padding 0's 
    while result.endswith(chr(0)):
        result = result[:-1]
    return result   

     
