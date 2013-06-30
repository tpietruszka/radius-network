# coding: utf-8
import socket
import threading
import signal
from jinja2._stringdefs import No
import errno
from Queue import Queue, Empty

class Server:
    def __init__(self, listening_port, shared_secret):
        self.listening_port = listening_port
        self.shared_secret = shared_secret
        self._server_socket = None
        self.request_queue = Queue()
        self.running = False
        self.listening_timeout = 2 # how often to check if worker threads should terminate [s]
        self.thread_count = 2 # number of worker threads
    
    def __del__(self):
        self._socket_close()
            
    def _socket_open(self):
        """ Opens a socket, starts listening for incoming requests 
        queues them up to "self.max_request_queue" 
        """
        if self._server_socket == None:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._server_socket.bind(('', self.listening_port))
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

        #initializing worker threads
        for i in range(0, self.thread_count):
            t = threading.Thread(target=self.handle_request)
            t.start()
            
        #beginning to receive requests
        while self.running: # can be changed with SIGINT
            try:
                # TODO: ustalic maksymalny rozmiar pakietu
                (received_packet, address) = self._server_socket.recvfrom(4096)
                print "received sth"
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
        while self.running:
            try:
                (packet, address) = self.request_queue.get(True, self.listening_timeout)
                self.packet_show(packet)
                self.request_queue.task_done()
            except Empty:
                pass
        return
            
    def packet_show(self, packet):
        print "code:", ord(packet[0])
        print "id: ", ord(packet[1])
        print "length: ", packet[3:4],
#         print "authenticator", packet[]
        
        
        
        
        
        
        
        
        
        
        
        