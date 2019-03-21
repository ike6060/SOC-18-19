import select, socket, sys, queue, hashlib, string, curses.ascii, syslog
from datetime import datetime, date






def replaceInString(original, marker, replacement):
    try:
        result = original[:original.index(marker)] + replacement + original[original.index(marker)+1:]
    except ValueError:
        return -1
    return result

def HTTP_Date_generator():
    date_fin = ""
    date_utc =datetime.utcnow()
    min = str(date_utc.minute)
    sec = str(date_utc.second)
    
    to_day = datetime.today()
    weekdays = ["Mon", "Tue", "Wen", "Thu", "Fri", "Sat", "Sun"]
    months = ["Jan","Feb","Mar","Apr","May","June","July","Aug","Sept","Oct","Nov","Dec"]
    date_fin += weekdays[to_day.weekday()] + ", "
    date_fin+= str(date_utc.day) + " "+ months[date_utc.month-1] +" "+ str(date_utc.year) + " "
    if len(str(date_utc.minute)) == 1:
        min = "0"+str(date_utc.minute)
    if len(str(date_utc.second)) == 1:
        sec = "0"+str(date_utc.second)
    
    date_fin += str(date_utc.hour) + ":" + min + ":" + sec + " GMT"
    return date_fin


def check(rec_password, correct_password_hash):
    rec_password_hash = hashlib.sha256(rec_password).hexdigest()
    if rec_password_hash == correct_password_hash:
        return True
    else:
        return False


def HTTPreq_to_keyval(get_request):
    get_request_split = get_request.split("\n")
    get_request_split = list(filter(None, get_request_split))
    top = get_request_split[0].split(" ")
    parsedreq = ""
    parsedreq += "Method=\""+top[0]+"\","

    requested_site = "".join(top[1:-1])
    parsedreq += "Site-Requested=\""+ requested_site + "\","
    parsedreq += "Http-Version=\""+ top[-1] + "\","

    for i in range(1,len(get_request_split)-1):
        if get_request_split[i] == "":
            continue
        if get_request_split[i].split("=")[0] == "licenseID":
            parsedreq += "licenseID" + get_request_split[i][len("licenseID"):]
            continue
        get_request_split[i] = get_request_split[i].split(": ")
        temp_str = ": ".join(get_request_split[i][1:])
        #print str(get_request_split[i][0])

        #checking if the value can be integer 
        try:
            int(temp_str)
            parsedreq += str(get_request_split[i][0]) +"="+ temp_str + "," 
        except ValueError:
            parsedreq += str(get_request_split[i][0]) +"=\""+ temp_str + "\","


    if parsedreq[-1] == ',':
        parsedreq = parsedreq[:-1]


    parsedreq = parsedreq + "\n"
    return parsedreq.replace('\r', '' ), requested_site.replace('\r', '')



def getResponseFileName(url_requested,resp_conf_file_object):
    for conf_line in resp_conf_file_object:
        #check line is commented
        if conf_line[0] == "#":
            continue


        conditions, response_page_path = conf_line.split("==")
        for condition in conditions.split("||"):
            if condition[0] == "%" and url_requested.find(condition[1:-1]) != -1:
                return response_page_path.replace("\n", "")
            elif condition[0] == "\"" and url_requested == condition[1:-1]:
                return response_page_path.replace("\n", "")
        if conditions == "default":
            return response_page_path.replace("\n", "")
                
       
def checkForSpecialChars(url):
    special_chars = ["|", "+", "-", "&&", "||", "!", "(", ")", "{", "}", "[", "]", "^",
                "~", "*", ":"]

    for i in url[1:]:
        if i in special_chars:
            return True
    return False













httpServer_port = 80
maintenanceServer_port = 12345
httpServer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
maintenanceServer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
httpServer_socket.setblocking(0)
maintenanceServer_socket.setblocking(0)
hostname = socket.gethostname()    
IPAddr = (([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")] or [[(s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) + ["no IP found"])[0]

httpServer_socket.bind((IPAddr, httpServer_port))
maintenanceServer_socket.bind((IPAddr, maintenanceServer_port))
httpServer_socket.listen(5)
maintenanceServer_socket.listen(5)
inputs = [httpServer_socket, maintenanceServer_socket]
outputs = []
message_queues = {}



webserverVersion = "Apache/2.4.6 (CentOS)"
httpVersion= "HTTP/1.1"
connectionAction = "close"
contentType = "text/html; charset=iso-8859-1"
statusCode = "200 OK"

print("listening")

#COMMUNICATION PROTOCOL RESPONSES
COMM_ACK = "comm_ack"
COMM_END = "comm_end"
TURN_OFF = "turn_off"




while inputs:
    readable, writable, exceptional = select.select(
        inputs, outputs, inputs)
    for s in readable:
        if (s is httpServer_socket) and (s.getsockname()[1] == httpServer_port):
            httpServer_connection, httpServer_clientAddr = s.accept()
            httpServer_connection.setblocking(0)
            inputs.append(httpServer_connection)
            message_queues[httpServer_connection] = queue.Queue()

        if (s is maintenanceServer_socket) and (s.getsockname()[1] == maintenanceServer_port):
            maintenanceServer_connection, maintenanceServer_clientAddr = s.accept()
            maintenanceServer_connection.setblocking(0)
            inputs.append(maintenanceServer_connection)
            message_queues[maintenanceServer_connection] = queue.Queue()

        else:            
            if (s is not httpServer_socket and s is not maintenanceServer_socket):
                try:
                    data = s.recv(1024).decode('ascii')
                except (socket.error, UnicodeDecodeError) as e:
                    print(e)
                    continue
                
                print(data)
                #COMMUNICATION CHANNEL WITH PORT_FORWARDER AND LATER INTERNET
                if (data) and (s.getsockname()[1] == httpServer_port):                    
                    if (data == COMM_END):
                        s.close()
                        if s not in inputs:
                            inputs.append(s)
                        if s in outputs:
                            outputs.remove(s)
                    else:
                        #********writing log via syslog***************
                        log = ""
                        output, URL_requested = HTTPreq_to_keyval(data)
                        log = "Client-Address=" + str(httpServer_clientAddr) + "," +  output
                        syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL5)
                        syslog.syslog(syslog.LOG_INFO, log)
                        syslog.closelog()
                        

                        

                        resp_conf_file = open("response_conf.txt", "r")
                        response_filename = getResponseFileName(URL_requested, resp_conf_file)
                        resp_conf_file.close()

                        #*******building http header and payload******
                        header = ["", "", "", "", "", ""]

                        
                        print(URL_requested)
                        
                        if (len(URL_requested) == 0):
                            statusCode = "400 Bad Request"
                            response_filename = "./html_responses/400_badrequest.txt"
                        elif (URL_requested[0] != "/" or checkForSpecialChars(URL_requested)) and ("/" not in URL_requested):
                            statusCode = "400 Bad Request"
                            response_filename = "./html_responses/400_badrequest.txt"
                        elif(response_filename == "./html_responses/404.txt"):
                            statusCode = "404 Not Found"

                        else:
                            statusCode = "200 OK"
                        


                        payloadfile = open(response_filename, "r")
                        payload = payloadfile.read()
                        payloadfile.close()


                        header[0] = httpVersion + " " + statusCode
                        header[1] = "Date: " + HTTP_Date_generator()
                        header[2] = "Server: " + webserverVersion
                        header[3] = "Content-Length: "+ str(len(payload))
                        header[4] = "Connection: " + connectionAction
                        header[5] = "Content-Type: " + contentType

                        header = "\n".join(header)
                        payload = replaceInString(payload, "%", webserverVersion)
                        
                        message_queues[s].put(str(header +"\n\n"+ payload))
                        #message_queues[s].put(header)

                        if s not in outputs:
                            outputs.append(s)


                        if s not in outputs:
                            outputs.append(s)


                #COMMUNICATION CHANNEL WITH MASTER APPLICATION
                elif (data) and (s.getsockname()[1] == maintenanceServer_port):
                    if(data == COMM_END):
                        s.close()
                        if s not in inputs:
                            inputs.append(s)
                        if s in outputs:
                            outputs.remove(s)
                    else:
                        command = data.split("=")
                        if command[0] == "Http-ver":
                            httpVersion = command[1]

                        elif command[0] == "Status-code":
                            statusCode = command[1]

                        elif command[0] == "Server-Version":
                            webserverVersion = command[1]
                        
                        elif command[0] == "Connection":
                            connectionAction = command[1]

                        elif command[0] == "Content-Type":
                            contentType = command[1]


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
        except queue.Empty:
            outputs.remove(s)
        else:
            print(next_msg)
            s.send(next_msg.encode('ascii'))

    for s in exceptional:
        inputs.remove(s)
        if s in outputs:
            outputs.remove(s)
        s.close()
        del message_queues[s]
