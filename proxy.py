#!/usr/bin/env python
# encoding: utf-8

import utils
from auth.server import ProxyServer

config_file = "config/proxy.json"

config_vars = ["hostName", "sharedSecret", "authPort", "socketTimeout", \
               "slaveHostName1", "slavePort1", \
               "slaveHostName2", "slavePort2", \
               "retryCount"]
c = utils.parseConfig(config_file, config_vars)


s = ProxyServer(c['hostName'], c['authPort'], c['sharedSecret'], c['socketTimeout'],\
                 c['slaveHostName1'], c['slavePort1'], \
                 c['slaveHostName2'], c['slavePort2'], \
                 c['retryCount'])
s.run()