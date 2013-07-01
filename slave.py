#!/usr/bin/env python
# encoding: utf-8

from argparse import ArgumentParser
import utils
from auth.server import SlaveServer



parser = ArgumentParser()
parser.add_argument('number', help="Number of slave config to run. Can be 1 or 2", type=int)
args = parser.parse_args()    


if args.number == 1:
    config_file = "config/slave1.json"
elif args.number == 2:
    config_file = "config/slave2.json"
else: raise RuntimeError("Wrong parameter given - no config available")

config_vars = ["hostName", "sharedSecret", "authPort", "socketTimeout", "databasePath", "masterHostName", "masterPort", "retryCount"]
c = utils.parseConfig(config_file, config_vars)


s = SlaveServer(c['hostName'], c['authPort'], c['sharedSecret'], c['socketTimeout'], c['databasePath'], c['masterHostName'], c['masterPort'], c['retryCount'])
s.run()