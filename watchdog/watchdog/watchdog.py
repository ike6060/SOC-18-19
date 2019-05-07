
import getpass, smtplib, argparse
from email.mime.text import MIMEText as text
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
    FROM = "emailsender789@gmail.com"
    TO = "ivokotora@gmail.com"
    message = "ahoj"
    try:  
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(FROM, "akafuka123")
        m = text(message)

        m['Subject'] = 'HONEYPOT OR MASTER ARE NOT RUNNING'
        m['From'] = FROM
        m['To'] = TO

        server.sendmail(FROM, TO, m.as_string())
        server.close()

        print('Email sent!')
    except Exception as e:  
        print('Something went wrong...\n', e)



if __name__ == "__main__":
    main()
    