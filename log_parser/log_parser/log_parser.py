

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
    while string[i] != "=":
        if i == len(string)-1:
            print("hello")
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
       
    

    while string[i] != "\"":
        if i == len(string)-1:
            print("hello")
            return None, None, None
        i+=1
    i+=1
    value = string[u:i].strip("\",")
    
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
for line in logfile:
    print(logsplit(line))
    input()

