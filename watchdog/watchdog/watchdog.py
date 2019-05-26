
import getpass, smtplib, argparse, socket
from email.mime.text import MIMEText as text
from os.path import exists
import sys


def proc_check(pid_file):
    procid = open(pid_file, "r").read()
    if procid == "":
        print("program is shutted down")
        return 1
    path = "/proc/"+procid
    print(path)
    if exists(path):
        print("program is running")
        return 0
    else:
        print("program has been unexpectedly shutted down")
        return -1

def hnpt_check(get_req_file):
    get_req = open(get_req_file, "r").read()
    HOST = "172.31.45.189"  # The server's hostname or IP address
    PORT = 80       # The port used by the server

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try :
            s.connect((HOST, PORT))
            s.sendall(get_req.encode("ascii"))
            data = s.recv(1024)
        except:
            return 1
        else:
            return 0
 





def main():
    parser = argparse.ArgumentParser(description='My example explanation')
    parser.add_argument('-p','--pidfile', help='provide a path to file with PID')
    parser.add_argument('-hn', '--honeypot',help = "if watching status of honeypot, provide path to get-req file", default="")
    parser.add_argument('-m', '--master', help="provide this parameter when checking master program", action="store_true")
    parsed = parser.parse_args()    
    
    
    if parsed.master == True:
        if proc_check(parsed.pidfile) == 0:
            return 0
        else:
            subject = "MASTER IS NOT RUNNING"
            message = "master is not running"
    elif parsed.master == False and parsed.honeypot != "":
        proc_running = proc_check(parsed.pidfile)
        hnpt_running = hnpt_check(parsed.honeypot)

        if proc_running == 0 and hnpt_running == 0:
            return 0
        elif proc_running != 0:
            subject = "HONEYPOT IS NOT RUNNING"
            message = "honeypot is not running"
        elif proc_running == 0 and hnpt_running != 0:
            subject = "HONEYPOT IS INACCESSIBLE"
            message = "the watchdog was not able to connect to the internet interface of the honeypot"
    else:
        subject = "WATCHDOG ERROR"
        message = "wrong arguments provided to watchdog"
        print(subject)
        print(message)




    print(sys.argv[2])
    gmail_pass = "akafuka123"
    gmail_account = "emailsender789"
    FROM = "emailsender789@gmail.com"
    TO = "ivokotora@gmail.com"

    try:  
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(FROM, "akafuka123")
        m = text(message)
            
        m['Subject'] = subject
        m['From'] = FROM
        m['To'] = TO

        server.sendmail(FROM, TO, m.as_string())
        server.close()

        print('Email sent!')
    except Exception as e:  
        print('Something went wrong...\n', e)



if __name__ == "__main__":
    main()
    