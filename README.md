
### ZTP

ZTP is a vulnerability scanner tool which is still in active development.

### Developers

- Abdullah Eryuzlu
    - [Github] (https://github.com/aeryz)
    - [Linkedin] (https://www.linkedin.com/in/abdullah-eryuzlu-675611182)

- Kaan Caglan
    - [Github] (https://github.com/caglankaan)
    - [Linkedin] (https://www.linkedin.com/in/caglankaan)

## Installation
You can compile code with following
```bash
c++ --std=c++17 modules/*.cpp src/*.cpp src/vendor/easylogging++/easylogging++.cpp -lstdc++fs -lssh -lhiredis -lredis++ -lpthread -Wall -I/usr/include/python3.8 -lpython3.8 $(pkg-config --cflags --libs libmongocxx) -w -o ztp
```

## New Feature
Now you can add your own modules with python nd you can integrate them with ZTP! You just have to add them to the under external_modules folder. With following command you can add any .py file.
```bash
sudo ./ztp  '{"external-function-path":"/home/kaancaglan/development/ftp_login.py"}'
```
After you add your function ftp_login.py will be executed by ZTP Engine. You just have to pick unique name for your file and same name for your function. For example our ftp_login.py looks like:

```python
import socket 
import sys  
from pymongo import MongoClient
from bson import ObjectId

sys.path.insert(0, "./")

def receive(sock):
    ....
def login(username, password, ip):
    ....
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
```
Main function and our file has same name. You should add your report do database in python file. Full version of the given example file is located in modules/external_modules.

## Usage
You just have to call binary with given json format as argument.
```bash
sudo ./ztp '{"ssh-username":"kaancaglan",  "ssh-password":"my_password", "ssh-port":"22", "targets":["my_ip_address"], "nmap":"nmap -sS -T4", "brute-force-type":"light", "excluding_functions":[""]}'
```
