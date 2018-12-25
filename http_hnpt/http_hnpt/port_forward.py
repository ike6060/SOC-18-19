#!/usr/bin/python           # This is server.py file

import socket               # Import socket module

sourceIP = (([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")] or [[(s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) + ["no IP found"])[0]
 # Get local machine name
sourcePort = 80
destinationIP = (([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")] or [[(s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) + ["no IP found"])[0]
#destinationIP = "192.168.252.7"
destinationPort = 12344
print destinationIP



#NO NEED FOR CHECKS IF END-CLIENT IS CONNECTED, IF ERROR OCCURS, CYCLE RESETS
s_source = socket.socket()         # Create a socket object
s_source.bind((sourceIP, sourcePort))        # Bind to the port

s_source.listen(5)                 # Now wait for client connection.
while True:
    c_source, addr = s_source.accept()     # Establish connection with client.
    print 'Connection received from address :', addr
    try:
        request = c_source.recv(1024)

    except socket.error:
        print "An error occured while retreiving data from client..."
        print "Resetting..."
        continue
    print request
    
    s_destination = socket.socket()
    try:
        s_destination.connect((destinationIP,destinationPort))
        s_destination.send(request)
        response = s_destination.recv(1024)
        #response = open("http_server/http_header.txt", "r").read()
    except socket.error:
        print "An error occured whithin communication with destination server..."
        print "Resetting..."
        continue


    print "length of data sent/original : ",c_source.send(response), len(response)
    c_source.close()               # Close the connection
