# encoding: utf-8
import sys
import json


def parseConfig(file, variables):
    """ Loads a given JSON file
    Returns a dict of given variables
    """ 
    try:
        with open(file) as fp:
            config = json.load(fp)
        results = dict()
        for k in variables:
            results[k] = config[k]
    except IOError as e: 
        raise LookupError("Error reading client's configuration file.\n" + e.message)
    except KeyError as e: 
        raise LookupError("Key missing in config file: " + e.message)
    return results