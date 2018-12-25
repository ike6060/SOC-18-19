import select, socket, sys, Queue
primPort = 12344
secPort = 12345
server1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server1.setblocking(0)
server2.setblocking(0)
hostname = socket.gethostname()    
IPAddr = (([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")] or [[(s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) + ["no IP found"])[0]

server1.bind((IPAddr, primPort))
server2.bind((IPAddr, secPort))
server1.listen(5)
server2.listen(5)
inputs = [server1, server2]
outputs = []
message_queues = {}
connection1 = 0
connection1 = 0
servertype = "Server: Apache/2.4.2 (Ubuntu)"
print "listening"

#COMMUNICATION PROTOCOL RESPONSES
COMM_ACK = "ack"
COMM_END = "end"



while inputs:
    readable, writable, exceptional = select.select(
        inputs, outputs, inputs)
    for s in readable:
        print s.getsockname()
        if (s is server1) and (s.getsockname()[1] == primPort):
            connection1, client_address1 = s.accept()
            connection1.setblocking(0)
            inputs.append(connection1)
            message_queues[connection1] = Queue.Queue()

        if (s is server2) and (s.getsockname()[1] == secPort):
            connection2, client_address2 = s.accept()
            connection2.setblocking(0)
            inputs.append(connection2)
            message_queues[connection2] = Queue.Queue()

        else:            
            if (s is not server1 and s is not server2):
                try:
                    data = s.recv(1024)
                except socket.error:
                    continue
                
                print data

                if (data) and (s.getsockname()[1] == primPort):                    
                    if (data == COMM_END):
                        s.close()
                        if s not in inputs:
                            inputs.append(s)
                        if s in outputs:
                            outputs.remove(s)
                    else:
                        html_fileName = "html_response.txt"
                        html_payload_file = open(html_fileName, "r")


                        http_header_fileName = "http_header.txt"
                        http_header_file = open(http_header_fileName, "r")
                        payload = html_payload_file.read()

                        logging_fileName = "log.csv"
                        logging_file = open(logging_fileName, "a")
                        header =  http_header_file.read()
                        log = ""
		                
                        #header =  http_header_file.read().split('\n')
                        #header[2] = servertype
                        #header = "\n".join(header)
                        http_header_file.close()
                        html_payload_file.close()
                        message_queues[s].put(header + payload)
			#message_queues[s].put(payload)
			#message_queues[s].put("HELLO WORLD")
                        if s not in outputs:
                            outputs.append(s)

                elif (data) and (s.getsockname()[1] == secPort):
                    if (data == COMM_END):
                        s.close()
                        if s not in inputs:
                            inputs.append(s)
                        if s in outputs:
                            outputs.remove(s)
                    else:
                        servertype = data
                        message_queues[s].put(COMM_ACK)
                        if s not in outputs:
                            outputs.append(s)
                else:
                    if s in outputs:
                        outputs.remove(s)
                    inputs.remove(s)
                    s.close()
                    del message_queues[s]

    for s in writable:
        try:
            next_msg = message_queues[s].get_nowait()
        except Queue.Empty:
            outputs.remove(s)
        else:
            s.send(next_msg)

    for s in exceptional:
        inputs.remove(s)
        if s in outputs:
            outputs.remove(s)
        s.close()
        del message_queues[s]
