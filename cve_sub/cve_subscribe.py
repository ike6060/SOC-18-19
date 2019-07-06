import requests
import zipfile
from urllib.request import urlopen
import socket
from sys import argv
from os import remove, rename, getpid
from datetime import datetime, date
import xml.etree.ElementTree as ET
import logging
import time
'''
******************************
ERROR NUMBERS
1 - INSUFFICIENT NUMBER OF ARGUMENTS
2 - CAN NOT READ ONLINE META FILE
3 - CAN NOT DOWNLOAD META FILE
4 - CAN NOT DOWNLOAD CVE DATABASE
5 - CAN NOT CONNECT TO HNPT
6 - CAN NOT SEND COMMAND TO HNPT
7 - HNPT DID NOT SEND ACK SIGNAL





******************************
'''






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



def replaceInString(original, marker, replacement):
    return original[:original.index(marker)] + replacement + original[original.index(marker)+1:]

def cveVersionTranslator(version,fileLogger, product_name, dict_file = "cve_product_name_dictionary.txt"):
    try:
        dictionary = open(dict_file, "r")
    except IOError:
        fileLogger.warning(HTTP_Date_generator()+":"+"cve_productname to http_servername dictionary was not found")
        return -1


    dictionary_entries = dictionary.read().split("\n")
    for entry in dictionary_entries:
        splitted_entry = entry.split("=")
        if splitted_entry[0] == product_name:
            return replaceInString(splitted_entry[1], "%", version)

    return 0

def cveEntryToDict(cveEntry, spec_product_versions , product_name):
    compromised_versions = []
    cveEntryDict = {}
    cveEntryDict = cveEntry.attrib
    cveEntryDict["product_name"] = product_name
    
    for version in spec_product_versions:
        compromised_versions.append(str(version.attrib["num"]))
    cveEntryDict["versions"] = compromised_versions
    return cveEntryDict

    


def findInCve(nvd_cve_file_name, product_name, vendor, CVSS_score_down_eq, CVSS_score_up_eq):
    if CVSS_score_down_eq == -1:
        CVSS_score_down_eq = 10.0
    if CVSS_score_up_eq == -1:
        CVSS_score_up_eq = 0.0
    found_entries = []
    tree = ET.parse(nvd_cve_file_name)
    root = tree.getroot()
    target_name = product_name

    for child in root:
        for schild in child[-1]:
            if child[-1].tag[-9:] == "vuln_soft": #-9 preto, lebo v cve entry ma pred "vuln_soft" hodenu URL a string vuln_soft ma 9 znakov
                if (schild.attrib["name"] == target_name and schild.attrib["vendor"] == vendor) or (schild.attrib["name"] == target_name):
                    if((float(child.attrib["CVSS_score"]) >= CVSS_score_up_eq) and (float(child.attrib["CVSS_score"]) <= CVSS_score_down_eq)):
                        entry = cveEntryToDict(child, schild, product_name)
                        found_entries.append(entry)
    return found_entries



def parse_conf(file_handle):
    dict_paths = {}
    for path in file_handle.readlines():
        #print "==================",path
        path_split = path.split("=")
        dict_paths[path_split[0]] = path_split[1]
    return dict_paths






def prepareFiles(config_path, nvdCveLogger, fileLogger):
    online_error = False
    nvd_cve_file = OS = default_apache_version = hnpt_update_timeout = cve_up_to_date = ''


    conf = open(config_path, "r")
    conf_dict = parse_conf(conf)
    nvd_cve_file = conf_dict["nvd_cve_file"][:-1]
    path_META = conf_dict['path_META'][:-1]
    url_META = conf_dict['url_META'][:-1]
    path_recent_zip = conf_dict['path_recent_zip'][:-1]
    url_recent = conf_dict['url_recent'][:-1]
    OS = conf_dict['operating_system'][:-1]
    default_apache_version = conf_dict['default_apache_version'][:-1]
    hnpt_update_timeout = conf_dict['hnpt_update_timeout'][:-1]
    online_error = False #returned True when error occured while retrieving files from nvd.nist.gov failed
    conf.close()
    missing_meta = False
    cve_up_to_date = False
    #******CHECK SHA256 CHECKSUM IF THERE IS NEW RECENT CVE RELEASE*******
    nvdCveLogger.info(HTTP_Date_generator()+":"+"Checking for new version of CVE")
    try:
        file_META = open(path_META, "r")
        prev_META_sha256 = file_META.readlines()[-1].split(":")[1]
    except IOError:
        fileLogger.warning(HTTP_Date_generator()+":"+"local cve-META file not found")
        missing_meta = True
        prev_META_sha256 = ""

    try:
        new_META = (urlopen(url_META).read()).decode("ascii")
    except:
       nvdCveLogger.error(HTTP_Date_generator()+":"+"could not read online meta file")
       online_error = True
       return online_error,nvd_cve_file, OS, default_apache_version, hnpt_update_timeout, cve_up_to_date
       
    
    new_META_sha256 = (new_META.split("\n")[-2]).split(":")[1]
    
    new_META_sha256 = new_META_sha256[:-1]
    prev_META_sha256 = prev_META_sha256[:-1]

    if prev_META_sha256 == new_META_sha256 and missing_meta == False:
        nvdCveLogger.info(HTTP_Date_generator()+":"+"no new CVE has been found")
        cve_up_to_date=True
    else:
        nvdCveLogger.info(HTTP_Date_generator()+":"+"new CVE has been found")
        nvdCveLogger.info(HTTP_Date_generator()+":"+"downloading new META file...")
        fileLogger.info(HTTP_Date_generator()+":"+"updating local META file")
        #******DOWNLOAD NEW META FILE*****
        try:
            req = requests.get(url_META, allow_redirects=True)
        except:
            nvdCveLogger.error(HTTP_Date_generator()+":"+"could not download new meta file")
            online_error = True
            return online_error,nvd_cve_file, OS, default_apache_version, hnpt_update_timeout, cve_up_to_date

        open(path_META, 'wb').write(req.content)
        
        nvdCveLogger.info(HTTP_Date_generator()+":"+"downloading CVE file...")
        nvdCveLogger.info(HTTP_Date_generator()+":"+"<finished>")
        fileLogger.info(HTTP_Date_generator()+":"+"extracting CVE file...")
        
        try:
            r = requests.get(url_recent, allow_redirects=True)
        except:
            nvdCveLogger.error(HTTP_Date_generator()+":Failed to download new cve database")
            online_error = True
            return online_error,nvd_cve_file, OS, default_apache_version, hnpt_update_timeout, cve_up_to_date

        open(path_recent_zip, 'wb').write(r.content)    
        print(path_recent_zip)
        try:
            zip_ref = zipfile.ZipFile(path_recent_zip, 'r')
            temp_cve_name = str(zip_ref.namelist()[0])
            zip_ref.extractall(''   )
            zip_ref.close()
            remove(path_recent_zip)
        except:
            fileLogger.info(HTTP_Date_generator()+":"+"Failed to extract or remove cve database")
            online_error = True
            return online_error,nvd_cve_file, OS, default_apache_version, hnpt_update_timeout, cve_up_to_date
        try:
            remove(nvd_cve_file)
        except:
            pass
        rename(temp_cve_name, nvd_cve_file)
        fileLogger.info(HTTP_Date_generator()+":"+"<extraction finished>")
    nvdCveLogger.info(HTTP_Date_generator()+":"+"<CVE database updating finished>")
    conf.close()
    
    return online_error,nvd_cve_file, OS, default_apache_version, hnpt_update_timeout, cve_up_to_date

'''
argv usage
python27 cve_subscribe.py conf_file_path product_name vendor_name CVSS_score_up_eq CVSS_score_down_eq
'''
if __name__ == "__main__":
    print(getpid())

    pid_file = open("process.id", "w")
    pid_file.write(str(getpid()))
    pid_file.close()

    
    logging.basicConfig()
    rootLogger = logging.getLogger()
    hnptConnectionLogger = logging.getLogger("Connection-Honeypot")
    fileLogger = logging.getLogger("File-Operations")
    cveConnectionLogger = logging.getLogger("Connection-NVD-CVE")

    hnptConnectionLogger.setLevel(10)
    fileLogger.setLevel(10)
    cveConnectionLogger.setLevel(10)
    rootLogger.setLevel(10)
    #COMMUNICATION PROTOCOL RESPONSES
    COMM_ACK = "comm_ack"
    COMM_END = "comm_end"
    TURN_OFF = "turn_off"

    if len(argv) == 4:
        paths_filePath= argv[1]
        product_name = argv[2]
        vendor_name = argv[3]
        CVSS_up = -1
        CVSS_down = -1
    elif len(argv) == 5:
        paths_filePath= argv[1]
        product_name = argv[2]
        vendor_name = argv[3]
        CVSS_up = float(argv[4])
        CVSS_down = -1
    elif len(argv) == 6:
        paths_filePath= argv[1]
        product_name = argv[2]
        vendor_name = argv[3]
        CVSS_up = float(argv[4])
        CVSS_down = float(argv[5])
    else:
        rootLogger.error("Insufficient number of arguments provided...")
        rootLogger.warning("proper usage : python3.6 cve_subscribe.py paths_file product_name vendor_name CVSS_score_up_eq CVSS_score_down_eq")
        


    hnpt_update_timeout = 5
    while True:
        time.sleep(int(hnpt_update_timeout))
       
        error, nvd_cve_file_name, operating_system, default_apache_version, hnpt_update_timeout, cve_up_to_date = prepareFiles(paths_filePath, cveConnectionLogger, fileLogger)
        
        if error == True:
            continue

        rootLogger.info(HTTP_Date_generator()+":"+"----------------------------------------------------")
        versions = []
        if cve_up_to_date:
            rootLogger.info(HTTP_Date_generator()+":"+"cve database is up to date, therefore not sending new version to hnpt")
            continue

        for i in (findInCve(nvd_cve_file_name, product_name, vendor_name, CVSS_score_up_eq = CVSS_up, CVSS_score_down_eq = CVSS_down)):
            versions.append(i["versions"][0])
        if versions == []:
            toSend = default_apache_version
            rootLogger.warning(HTTP_Date_generator()+":"+"no new vulnerable version in cve found...")
            rootLogger.warning(HTTP_Date_generator()+":"+"sending default vuln-version to honeypot")
        else:
     
            toSend = cveVersionTranslator(versions[0],fileLogger, product_name)
            while toSend == -1:
                dict_path = input("Product-name dictionary file not found... Please enter path to this file\n->")
                toSend = cveVersionTranslator(version=versions[0], fileLogger=fileLogger,product_name=product_name, dict_file=dict_path)  
            rootLogger.info(HTTP_Date_generator()+":"+"new version of hnpt server " + toSend)
            default_apache_version = toSend


        toSend = replaceInString(toSend, "&", operating_system)
        hnptConnectionLogger.info(HTTP_Date_generator()+":"+"connecting to Honeypot...")


        host = "127.0.0.1"
        s = socket.socket()
        port = 12345                # Reserve a port for your service.
        try:
            s.connect((host, port))
        except socket.error:
            hnptConnectionLogger.error(HTTP_Date_generator()+":"+"could not connect to honeypot")
      

        hnptConnectionLogger.info(HTTP_Date_generator()+":"+"connected to honeypot")
        hnptConnectionLogger.info (HTTP_Date_generator()+":"+"sending new version of server")

        try:
            s.send(("Server-Version=" + toSend).encode("ascii"))
        except socket.error:
            hnptConnectionLogger.error(HTTP_Date_generator()+":"+"Unable to send server-version!")
            
        hnptConnectionLogger.info (HTTP_Date_generator()+":"+"data sent, waiting for acknowledgement from hnpt")
        resp = s.recv(1024).decode("ascii")
        if resp == COMM_ACK:
            rootLogger.info(HTTP_Date_generator()+":"+"successfully sent new server-version, honeypot sent ack")
        else:
            rootLogger.warning(HTTP_Date_generator()+":"+"successfully sent new server-version, honeypot did not send ack")
        
        s.close()
    pid_file = open("pid", "w")
    pid_file.write("")
    pid_file.close()
