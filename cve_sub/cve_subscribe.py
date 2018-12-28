import requests
import zipfile
from urllib.request import urlopen
import socket
from sys import argv, exit
from os import remove, rename
import xml.etree.ElementTree as ET


'''
******************************
TODO list
-prehodit do commandline rezimu
-zmenit printy na debiliny jak alert a drbnut nastavenie do argv



******************************
'''









def replaceInString(original, marker, replacement):
    return original[:original.index(marker)] + replacement + original[original.index(marker)+1:]

def cveVersionTranslator(version, product_name, dict_file = "cve_product_name_dictionary.txt"):
    try:
        dictionary = open(dict_file, "r")
    except FileNotFoundError:
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



def parse_paths(file_handle):
    dict_paths = {}
    for path in file_handle.readlines():
        #print "==================",path
        path_split = path.split("=")
        dict_paths[path_split[0]] = path_split[1]
    return dict_paths






def prepareFiles(config_path):
    paths = open(config_path, "r")
    paths_dict = parse_paths(paths)
    nvd_cve_file = paths_dict["nvd_cve_file"][:-1]
    path_META = paths_dict['path_META'][:-1]
    url_META = paths_dict['url_META'][:-1]
    path_recent_zip = paths_dict['path_recent_zip'][:-1]
    url_recent = paths_dict['url_recent'][:-1]
    OS = paths_dict['operating_system'][:-1]
    paths.close()
    missing_meta = False
    #******CHECK SHA256 CHECKSUM IF THERE IS NEW RECENT CVE RELEASE*******
    print ("Checking for new version of CVE")
    try:
        file_META = open(path_META, "r")
        prev_META_sha256 = file_META.readlines()[-1].split(":")[1]
    except IOError:
        missing_meta = True
        prev_META_sha256 = ""


    new_META = (urlopen(url_META).read()).decode("ascii")
    
    new_META_sha256 = (new_META.split("\n")[-2]).split(":")[1]
    
    new_META_sha256 = new_META_sha256[:-1]
    prev_META_sha256 = prev_META_sha256[:-1]
    print(new_META_sha256 + "\n" + prev_META_sha256)

    if prev_META_sha256 == new_META_sha256 and missing_meta == False:
        print ("No new CVE has been found")
    else:
        print ("New CVE has been found\n Downloading...")
        print ("downloading META file...")
        #******DOWNLOAD NEW META FILE*****
        req = requests.get(url_META, allow_redirects=True)
        open(path_META, 'wb').write(req.content)
        print ("\t-> <finished>")
        print ("downloading CVE file...")
        print ("\t-> <finished>")
        print ("\t-> extracting CVE file...")
        
        r = requests.get(url_recent, allow_redirects=True)
        open(path_recent_zip, 'wb').write(r.content)    
        print(path_recent_zip)
        zip_ref = zipfile.ZipFile(path_recent_zip, 'r')
        temp_cve_name = str(zip_ref.namelist()[0])
        zip_ref.extractall(''   )
        zip_ref.close()
        remove(path_recent_zip)
        try:
            remove(nvd_cve_file)
        except:
            pass
        rename(temp_cve_name, nvd_cve_file)
        print("\t\t-> <finished>")

    print("all files ready...")
    paths.close()
    
    return nvd_cve_file, OS

'''
argv usage
python27 cve_subscribe.py paths_file product_name vendor_name CVSS_score_up_eq CVSS_score_down_eq
'''
if __name__ == "__main__":
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
        print ("Insufficient number of arguments provided...")
        print ("proper usage : python27 cve_subscribe.py paths_file product_name vendor_name CVSS_score_up_eq CVSS_score_down_eq")
        exit(1)

    
    paths_data = prepareFiles(paths_filePath)
    nvd_cve_file_name = paths_data[0]
    operating_system = paths_data[1]
    versions = []
    for i in (findInCve(nvd_cve_file_name, product_name, vendor_name, CVSS_score_up_eq = CVSS_up, CVSS_score_down_eq = CVSS_down)):
        versions.append(i["versions"][0])
    

    toSend = cveVersionTranslator(versions[0], product_name)
    while toSend == -1:
        dict_path = input("Product-name dictionary file not found... Please enter path to this file\n->")
        toSend = cveVersionTranslator(versions[0], product_name, dict_path)
    
        
    toSend = replaceInString(toSend, "&", operating_system)
    print ("This version of webserver will be used in honeypot from now on...", toSend)
    print ("Connecting to Honeypot...")


    host = (([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")] or [[(s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) + ["no IP found"])[0]
    s = socket.socket()
    port = 12345                # Reserve a port for your service.
    try:
        s.connect((host, port))
    except socket.error:
        print("An error occured during establishment of connection to honeypot.")
        exit(1)

    print ("Connection with master established... Sending new server-version.")

    try:
        s.send(("Server=" + toSend).encode("ascii"))
    except socket.error:
        print( "Unable to send server-version!")
        exit(1)

    resp = s.recv(1024).decode("ascii")
    if resp == COMM_ACK:
        print( "Action successful, honeypot received new server-version!")

    else:
        print ("Something went wrong on the other side...")
        
    s.close() 