
import getpass, smtplib, argparse
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
from os.path import exists
import sys


def proc_check():
    pid_file = sys.argv[1]
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

def main():
    if proc_check() == 0:
        return 0

    
    gmail_pass = "akafuka123"
    gmail_account = "emailsender789"
    sent_from = gmail_account  
    to = ['ivokotora@gmail.com']  
    subject = 'HNPT not running...'  
    body = ''

    email_text = """\  
    From: %s  
    To: %s  
    Subject: %s

    %s
    """ % (sent_from, ", ".join(to), subject, body)

    try:  
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login("emailsender789@gmail.com", "akafuka123")
        server.sendmail(sent_from, to, email_text)
        server.close()

        print('Email sent!')
    except Exception as e:  
        print('Something went wrong...\n', e)



if __name__ == "__main__":
    main()
    