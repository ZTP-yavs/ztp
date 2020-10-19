import socket 
import sys  
from pymongo import MongoClient
from bson import ObjectId

sys.path.insert(0, "./")

def receive(sock):
    chunks = []
    bytes_recd = 0
    chunk = sock.recv(512)
    if chunk == b'':
        raise RuntimeError("socket connection broken")
    chunks.append(chunk)
    bytes_recd = bytes_recd + len(chunk)
    return b''.join(chunks)

def login(username, password, ip):
    try: 
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    except socket.error as err: 
        print ("socket creation failed with error %s" %(err)) 
    
    # default port for ftp 
    port = 21
    
    s.connect((ip, port)) 

    receive(s)

    username_byte = b'USER '+ str.encode(username) + b'\r\n'

    s.send(username_byte)

    receive(s)

    password_byte = b'PASS ' + str.encode(password) + b'\r\n'

    s.send(password_byte)    

    response = receive(s)

    if b"Login successful" in response or b"Already logged in" in response:
        return True
    return False

def ftp_login(username, password, ip_address, MongoDB_port, target_id):
    #target id is ObjectId
    target_id = ObjectId(target_id.decode("utf-8"))
    #since parameters are byte we have to convert them to string
    username = username.decode("utf-8")
    password = password.decode("utf-8")
    ip_address = ip_address.decode("utf-8")
    MongoDB_port = int(MongoDB_port.decode("utf-8"))

    if(login(username, password, ip_address)):
        #We should add it to the database!
        client = MongoClient('localhost', MongoDB_port)
        db = client['ztp-dev']
        
        post = {
             "static_report": "",
            "dynamic_report": "Anonymous login is enabled.",
            "target": ObjectId(target_id)
        }
        db["dynamicreport"].insert_one(post).inserted_id
        
        print("anonymous login enabled!")
    else:
        print("not enabled!")


