# coding: utf-8
import socket
import threading
import signal
from jinja2._stringdefs import No
import errno

class Server:
    def __init__(self, listening_port, shared_secret):
        self.listening_port = listening_port
        self.shared_secret = shared_secret
        self.max_request_queue = 5
        self._server_socket = None
        self._thread_list = [] 
        self.running = False
    
    def __del__(self):
        self._socket_close()
            
    def _socket_open(self):
        """ Opens a socket, starts listening for incoming requests 
        queues them up to "self.max_request_queue" 
        """
        if self._server_socket == None:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._server_socket.bind(("127.0.0.1", self.listening_port))
#             self._server_socket.listen(self.max_request_queue) 
        
    def _socket_close(self):
        if self._server_socket:
            self._server_socket.close()
            self._server_socket = None
        
    
    def run(self):
        self._socket_open()
        
        self.running = True
        print "Server listening, port " + str(self.listening_port)
        
        signal.signal(signal.SIGINT, self.stop)
#         signal.siginterrupt(signal.SIGINT, False)
        
        while self.running: # can be changed with SIGINT
            try:
                # TODO: ustalic maksymalny rozmiar pakietu
                (received_packet, address) = self._server_socket.recvfrom(4096)
                print "received sth"
                t = threading.Thread(target=self.handle_request, args=((received_packet, address)))
                self._thread_list.append(t)
                t.run()
                print self._thread_list
            except socket.error as (code, msg):
                if code == errno.EINTR:
                    print "socket closed via SIGINT"
                else: raise
                    
            
        for t in self._thread_list:
            if t.is_alive():
                t.join()
        
        self._socket_close()
        print "all threads finished"

    
    def stop(self, signal=None, frame=None):
        """ additional arguments are not used, but mandatory for a signal handler """
        print "shutting down..."
        self.running = False
        
        
        
    def handle_request(self, packet, address):
        print "handlin"
        print packet
        return 0
        