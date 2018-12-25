'''import xml.etree.ElementTree as ET
tree = ET.parse('nvdcve-recent.xml')
root = tree.getroot()
target_name = "firefox"
for child in root:
    for schild in child[-1]:
        #print "(", schild.tag, schild.attrib,")"
        #print
        #print child[-1].tag[-9:] == "vuln_soft", child[-1].tag
        #print
        if child[-1].tag[-9:] == "vuln_soft":
            if schild.attrib["name"] == target_name:
                for i in child.attrib:
                    print i, ":", child.attrib[i]
                print "Versions of", target_name, "which are compromised..."
                for version in schild:
                    print version.attrib["num"]
                print "\n-------\n"'''
import requests
import zipfile

 
path_META = 'last_checked_meta.xml'
url_META = 'https://nvd.nist.gov/feeds/xml/cve/1.2/nvdcve-recent.xml.zip'
r = requests.get(url_META, allow_redirects=True)
open(path_META, 'wb').write(r.content)


path_recent = 'nvd_cve_recent.zip'
url_recent = 'https://nvd.nist.gov/feeds/xml/cve/1.2/nvdcve-recent.xml.zip'
r = requests.get(url_recent, allow_redirects=True)
open(path_recent, 'wb').write(r.content)



zip_ref = zipfile.ZipFile(path_recent, 'r')
zip_ref.extractall(''   )
zip_ref.close()