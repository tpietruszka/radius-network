#!/usr/bin/env python
# encoding: utf-8

from auth.server import MasterServer
import utils

config_file = "config/master.json"
config_vars = ["hostName", "sharedSecret", "authPort", "socketTimeout", "databasePath"]
c = utils.parseConfig(config_file, config_vars)


s = MasterServer(c['hostName'], c['authPort'], "c['sharedSecret']", c['socketTimeout'], c['databasePath'])
s.run()