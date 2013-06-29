# coding: utf-8


# used RADIUS packet codes
CodeAccessRequest = 1
CodeAccessAccept = 2
CodeAccessReject = 3

# Attribute - value pair keys

ATTRIBUTE_KEYS = {
    "User-Name": 1, 
    "User-Password": 2, 
    "Reply-Message": 18
}

# custom errors and exceptions

class TimeoutError(Exception): pass