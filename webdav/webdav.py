#!/usr/bin/env python3

# beta webdav handler
# dev: parrotassassin15


# imports
from time import sleep as delay 
from os import system as s


global host
host = "http://127.0.0.1:8098"

def main():
    s("sudo service wsgidav start")
    print("Please wait...")
    for x in reversed(range(1,4)):
        print(x)
        delay(2)
    print("web dav server started. visit " + host)

main()
