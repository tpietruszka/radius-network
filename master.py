#!/usr/bin/env python
# encoding: utf-8

from auth.server import Server


port = 1816
shared_secret = "elkaSecret"

s = Server(port, shared_secret)
s.run()