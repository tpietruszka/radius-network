# coding: utf-8

from auth import *
import random
import select
import socket
import struct
try:
    from hashlib import md5
except ImportError:
    from md5 import new as md5


class client:
    def __init__(self, host, port, secret, retry_count, timeout):
        self.host = host
        self.port = port
        
        self.secret = str(secret)
        self.retry_count = retry_count
        self.timeout = float(timeout) / 1000
        
        self._socket = None
        
    def __del__(self):
        self._socket_close()
        
        
    def _socket_open(self):
        if self._socket == None:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.connect((self.host, self.port))

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
    
    
    
    def encrypt(self, authenticator, text):
        '''Encrypt a password with the secret'''
        # First, pad the password to multiple of 16 octets.
        text += chr(0) * (16 - (len(text) % 16))
        if len(text) > 128:
            raise Exception('Password exceeds maximun of 128 bytes')
        result = ''
        last = authenticator
        while text:
            # md5sum the shared secret with the authenticator,
            # after the first iteration, the authenticator is the previous
            # result of our encryption.
            hashed = md5(self.secret + last).digest()
            for i in range(16):
                result += chr(ord(hashed[i]) ^ ord(text[i]))
            # The next iteration will act upon the next 16 octets of the password
            # and the result of our xor operation above. We will set last to
            # the last 16 octets of our result (the xor we just completed). And
            # remove the first 16 octets from the password.
            last, text = result[-16:], text[16:]
        return result
            
    def authorize(self, user_name, password):
        try:
            self._socket_open()
            id = random.randint(0, 255)

            authenticator = self.generate_authenticator()

            encpass = self.encrypt(authenticator, password)

            msg = struct.pack('!B B H 16s B B %ds B B %ds' \
                    % (len(user_name), len(encpass)), \
                1, id,
                len(user_name) + len(encpass) + 24,  # Length of entire message
                authenticator,
                1, len(user_name) + 2, user_name,
                2, len(encpass) + 2, encpass)

            for i in range(0, self.retry_count):
                self._socket.send(msg)

                t = select.select([self._socket, ], [], [], self.timeout)
                if len(t[0]) > 0:
                    response = self._socket.recv(4096)
                else: 
                    # timeout detected
                    continue

                if ord(response[1]) == id:
                    break
                else:
                    # incorrect id - a response to something else?
                    print "Response with an incorrect ID received - ignored"
                    continue

                
            self._socket_close()
            if ord(response[0]) == CodeAccessAccept:
                return 1    
            else:
                return 0
            # TODO: wprowadzić walidację pakietów - gdy współpracujące serwery będą to obsługiwać
            # # Verify the packet is not a cheap forgery or corrupt
                # checkauth = response[4:20]
                # m = md5(response[0:4] + authenticator + response[20:] 
                    # + self._secret).digest()
                # if m <> checkauth:
                    # continue
        except socket.error, x:  # SocketError
            try: self._socket_close()
            except: pass
            raise RuntimeError("socket error" + str(x))

        raise TimeoutError
        
