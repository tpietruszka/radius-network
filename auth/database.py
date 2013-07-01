# coding: utf-8
import csv

class NoAnswerException(Exception): #used when server should not respond
    pass
class UserUnknownException(Exception):
    pass
class WrongPasswordException(Exception):
    pass
class AccessRestrictedException(Exception):
    pass

class Database:
    """ Reads from csv file, verifies users credentials afterwards
    file format:
    login,password,[accept|reject]
    first line is a header
    """
    
    def __init__(self, file_name):
        self.file_name = file_name
        self.table = dict()
        with open(file_name, 'rb') as fp:
            rows = csv.reader(fp, delimiter=',')
            rows.next() # skipping header
            for row in rows: 
                self.table[row[0]] = (row[1], row[2])
                
                 
    def check(self, user_name, password):
        """returns 1 on accept, 0 on reject
        throws UserUnknownException when no record is present
        throws WrongPasswordException when wrong password was given
        """
        try: 
            user = self.table[user_name]
        except KeyError:
            raise UserUnknownException("User " + user_name + " not found")
        if user[0] != password:
            raise WrongPasswordException("Wrong password for user " + user_name)
        
        if user[1] == "accept":
            return True
        else: 
            raise AccessRestrictedException("Access restricted for user " + user_name)
        
            