# coding: utf-8
from Queue import Queue, Empty
from auth import ATTRIBUTE_KEYS, CodeAccessAccept, CodeAccessReject, \
    TimeoutError
from auth.common import get_client_socket, request_authorization
from auth.database import Database, UserUnknownException, WrongPasswordException, \
    AccessRestrictedException, NoAnswerException
from auth.packet import Packet, decrypt
import abc
import errno
import signal
import socket
import threading

class Server:
    """ Abstract class of a radius server, 
    base classess should implement rules of checking validity of user's password
    """
    __metaclass__ = abc.ABCMeta
        
    def __init__(self, host_name, listening_port, shared_secret, timeout):
        self.host_name = host_name
        self.listening_port = listening_port
        self.shared_secret = str(shared_secret)
        self._server_socket = None
        self.request_queue = Queue()
        self.running = False
        self.timeout = float(timeout)/1000 # how often to check if worker threads should terminate [s]
        self.thread_count = 2 # number of worker threads
    
    def __del__(self):
        self._socket_close()
            
    def _socket_open(self):
        """ Opens a socket, starts listening for incoming requests 
        queues them up to "self.max_request_queue" 
        """
        if self._server_socket == None:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._server_socket.bind((self.host_name, self.listening_port))
        
    def _socket_close(self):
        if self._server_socket:
            self._server_socket.close()
            self._server_socket = None
        
    
    def run(self):
        self._socket_open()
        
        self.running = True
        print type(self).__name__,"listening, port " + str(self.listening_port)
        
        signal.signal(signal.SIGINT, self.stop)
#         signal.siginterrupt(signal.SIGINT, False)

        #initializing worker threads
        for i in range(0, self.thread_count):
            t = threading.Thread(target=self.handle_request)
            t.start()
            
        #beginning to receive requests
        while self.running: # can be changed with SIGINT
            try:
                # TODO: ustalic maksymalny rozmiar pakietu
                (received_packet, address) = self._server_socket.recvfrom(4096)
                self.request_queue.put((received_packet, address))
            except socket.error as (code, msg):
                if code == errno.EINTR:
                    print "socket closed via SIGINT"
                else: raise
        
        self._socket_close()
        print "all threads finished"

    
    def stop(self, signal=None, frame=None):
        """ additional arguments are not used, but mandatory for a signal handler """
        print "shutting down..."
        self.running = False
        
        
        
    def handle_request(self):
        """Main loop of each worker thread - get a message from queue, handle it, mark as done"""
        while self.running:
            try:
                (packet, address) = self.request_queue.get(True, self.timeout)
                self.respond(packet, address)
                
                self.request_queue.task_done()
            except Empty:
                pass
        return
    
    def respond(self, raw_packet, client_address):
        """ Performs parrsing of a request, calls  "verify()" function to determine right answer,
        sends an anser afterwards (or not, if NoAnswerException was catched)
        """  
        
        print "\n\n\n\n", type(self).__name__, " - authorization requested"
        request = Packet.from_bytestring(raw_packet)
        try:
            user_name = request.attributes[ATTRIBUTE_KEYS['User-Name']]
            print "user name: ", user_name
            encrypted_password = request.attributes[ATTRIBUTE_KEYS['User-Password']]
        except KeyError as e:
            print "Invalid packet - no credentials ", e
            return
        password = decrypt(self.shared_secret, request.authenticator, encrypted_password)
        try:
            authorized, reply_message = self.verify(user_name, password, request, raw_packet)
        except NoAnswerException:
            print "no answer - request dropped"
            return 
        
        
        if authorized:
            reply_code = CodeAccessAccept
        else:
            reply_code = CodeAccessReject
        
        attributes = dict()
        if reply_message:
            attributes[ATTRIBUTE_KEYS['Reply-Message']] = reply_message    
                
        response_packet = Packet(reply_code, request.id, request.authenticator, attributes)
        response = response_packet.to_bytestring()
        self._server_socket.sendto(response, client_address)
        print "Response sent - access " + ("allowed" if authorized else "denied")
        if len(reply_message) > 0: print "message: ", reply_message
        
    @abc.abstractmethod  
    def verify(self, user_name, password, packet_object, raw_packet):
        """Each base class should implement custom users verification rules
        returns (bool authorized, string reply_message)
        throws NoAnswerException if no answert should be sent
        """
        
    def packet_show(self, packet):
        """debugging purpose only, shows basic packet info"""
        print "code:", ord(packet[0])
        print "id: ", ord(packet[1])
        print "length: ", packet[3:4],
        
        


class MasterServer(Server):
    """Simplest server - verification based on it's own database """
    
    def __init__(self, host_name, listening_port, shared_secret, timeout, database):
        super(MasterServer, self).__init__(host_name, listening_port, shared_secret, timeout)
        self.database = Database(database)
        
    def verify(self, user_name, password, packet_object, raw_packet):
        authorized = False
        reply_message = ""
        try: 
            authorized = self.database.check(user_name, password)
        except (UserUnknownException, WrongPasswordException, AccessRestrictedException) as e:
            authorized = False
            reply_message = e.message
            
        return authorized, reply_message
        
    
class SlaveServer(Server):
    """ If there is no answer in its database, a request to a master server is sent """
    
    def __init__(self, host_name, listening_port, shared_secret, timeout, database, \
                 master_host_name, master_port, retry_count):
        
        super(SlaveServer, self).__init__(host_name, listening_port, shared_secret, timeout)
        self.database = Database(database)
        self.master_host_name = master_host_name
        self.master_port = master_port
        self.retry_count = retry_count
        
        
    def verify(self, user_name, password, request_object, raw_request):
        authorized = False
        reply_message = ""
        try:
            authorized = self.database.check(user_name, password)
        except (WrongPasswordException, AccessRestrictedException) as e:
            authorized = False
            reply_message = e.message
        except UserUnknownException: # request to the master server:
            print "User unknown, checking with the MasterServer"
            
            try:
                out_socket = get_client_socket()
                (authorized, reply_message) = request_authorization(request_object, out_socket,\
                                                                     self.master_host_name, \
                                                                     self.master_port, \
                                                                     self.retry_count, \
                                                                     self.timeout)
                out_socket.close()
            except TimeoutError: # if master server did not answer - do not answer either
                raise NoAnswerException
        return authorized, reply_message

class ProxyServer(Server):
    """ Request authorization from 2 other servers, chooses worse of 2 decisions 
    if only 1 decision is received - it is the final one
    """
    
    def __init__(self, host_name, listening_port, shared_secret, timeout, slave_host_name_1, \
                 slave_port_1, slave_host_name_2, slave_port_2, retry_count):
        
        super(ProxyServer, self).__init__(host_name, listening_port, shared_secret, timeout)
        self.slave_host_name_1 = slave_host_name_1
        self.slave_port_1 = slave_port_1
        self.slave_host_name_2 = slave_host_name_2
        self.slave_port_2 = slave_port_2
        self.retry_count = retry_count
        
        
    def verify(self, user_name, password, request_object, raw_request):
        slaves = [[self.slave_host_name_1, self.slave_port_1], \
                  [self.slave_host_name_2, self.slave_port_2]]        
        responses = []
        messages = []
        out_socket = get_client_socket()
        
        for s in slaves: # try to ask 2 servers, results appended to lists
            try:
                (authorized, reply_message) = request_authorization(request_object, out_socket, s[0], s[1], \
                                                                    self.retry_count, self.timeout)
                responses.append(authorized)
                messages.append(reply_message)
            except TimeoutError:
                pass
        if len(responses) == 0:
            response = False
            reply_message = "No responses received by ProxyServer"
        else:
            print "Received", len(responses), "responses"
            response = min(responses)
            if messages[0] or messages[1]:
                reply_message = "Messages received by ProxyServer: " + ", ".join(messages)
            else:
                reply_message = ""
        out_socket.close()
        return response, reply_message







