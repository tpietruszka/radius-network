# coding: utf-8
try:
    from hashlib import md5
except ImportError:
    from md5 import new as md5


def encrypt(secret, authenticator, password):
    """ Encrypt the password using Client's "Shared secret" and given authenticator"""
    # pad the password with zeros to multiple of 16 octets 
    password += chr(0) * (16 - (len(password) % 16))
    if len(password) > 128:
        raise Exception('Password exceeds maximun of 128 bytes')
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
    """ Decrypt the password using Client's "Shared secret" and given authenticator"""
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
