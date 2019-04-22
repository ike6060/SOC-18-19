import folium
import urllib.request
import urllib.parse
import yaml
import time
def prepareFiles(confpath):
    ignore_chars = "\n# "
    try:
        conf = open(confpath, "r")
    except:
        print("Unable to open conf file, please provide a correct path, or create one")

    

    for line_whitespace in conf:
        
        line = line_whitespace.strip()
        print(line)
        print("----",line,"-----")
        if line == "":
            continue
        elif line[0] in ignore_chars:
            continue
        else:
            command = line.split("=")
            
            if command[0] == "logfilepath":
                logfilepath = command[1]

    return logfilepath

def get_key(i,u,string):
    #print(string)
    while string[i] != "=":
        if i == len(string)-1:
            #print("hello")
            return None, None, None
        i+=1
    key = string[u+1:i].strip("\",")
    i+=1
 


    intval = ""
    try :
        while int(string[i]) >= 0:
            intval+=string[i]
            i+=1
    except ValueError:
        i+=1
    
    u = i

    if len(intval) > 0:
        i-=1
        u = i
        return {key:int(intval)}, i, u
       
    if key == "lient-Address":
        key = "Client-Address"
        endchar = ")"
    else:
        endchar = "\""
    try:
        while string[i+1] != endchar:
            if i == len(string)-1:
                #print("hello")
                return None, None, None
            i+=1
    except:
        return None, None, None
    i+=1
    value = string[u:i]
    
    u = i
    
    
    return {key:value}, i, u
    

def logsplit(string):
    result = {}
    end_of_log = False
    new_entry, i, u = get_key(0,0,string)
    result.update(new_entry)
    #print(result)
    while not end_of_log:
        new_entry, i, u = get_key(i,u,string)
        if new_entry == None and i == None and u == None:
            return result
        result.update(new_entry)
        #print(result)
        
    result.update(new_entry)

    
    



logfilepath = prepareFiles("master.conf")
logfile = open(logfilepath, "r")
attacker_ip_dict = {}
for line in logfile:
    #print(logsplit(line))
    line_splt = line.split(": ")

    time = line_splt[0].split(" ")[2]

    line = "".join(line_splt[1:])
    
    logdict = logsplit(line)

    attacker_ip = logdict["Client-Address"].split(", ")[0].strip("'")
    try:
        attacker_ip_dict[attacker_ip]+=1
    except KeyError:
        attacker_ip_dict[attacker_ip] = 1

    
url = "https://iplocation.com/"
print(len(attacker_ip_dict))
mapa = folium.Map()
for act_ip in attacker_ip_dict:
    params = {"ip":act_ip}
    query_string = urllib.parse.urlencode( params )
    data = query_string.encode( "ascii" )
    try:
        with urllib.request.urlopen( url, data ) as response:
            try:
                response_text = response.read().decode("utf-8")
            except:
                print("error occured, ip addr was", act_ip)
                continue
            #print( response_text )
    except:
           print("error occured while connecting to remote server")
           continue
    lat = ""
    lng = ""

    i = response_text.find("\"lat\"") + 3 + 2 + 1 #3 for rest of letter in "lat\"", 2 for ":\""
    #print(response_text[i])
    while response_text[i+1]!= "\"":
        lat += response_text[i]
        i+=1
    
    #print(lat)

    i = response_text.find("\"lng\"") + 3 + 2 + 1 #3 for rest of letter in "lat\"", 2 for ":\""
    #print(response_text[i])
    while response_text[i+1]!= "\"":
        lng += response_text[i]
        i+=1
    try:
        lng = float(lng)
        lat = float(lat)
    except:
        print("error proccessing lat and lng" , act_ip)
        continue

    if attacker_ip_dict[act_ip]<2:
        mapa.add_child(folium.Marker(icon=folium.Icon(color='green'), popup=str(attacker_ip_dict[act_ip])+' connections from this address', location=[lat, lng]))
    elif attacker_ip_dict[act_ip]>=2 and attacker_ip_dict[act_ip]<7:
        mapa.add_child(folium.Marker(icon=folium.Icon(color='blue'), popup=str(attacker_ip_dict[act_ip])+' connections from this address', location=[lat, lng]))
    else:
        mapa.add_child(folium.Marker(icon=folium.Icon(color='red'), popup=str(attacker_ip_dict[act_ip])+' connections from this address', location=[lat, lng]))

mapa.save("mapa4.html")


