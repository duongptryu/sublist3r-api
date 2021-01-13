#!/usr/bin/env python

from fastapi import FastAPI, status, Response, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
import time

from typing import Optional
from fastapi.middleware.cors import CORSMiddleware

import re
import threading
import socket
# import pandas as pd
import sublist3r

import config as cfg



app=FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=cfg.setup_CORS['origin'],
    allow_credentials=cfg.setup_CORS['allow_credentials'],
    allow_methods=cfg.setup_CORS['allow_methods'],
    allow_headers=cfg.setup_CORS['allow_headers'],
)
app.mount("/public", StaticFiles(directory="build"), name="public")


templates = Jinja2Templates(directory="build")


@app.get("/", response_class=HTMLResponse)
async def serve_spa(request: Request, ):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/{domain}", status_code=status.HTTP_200_OK)
async def check(res: Response, domain: str, ports: Optional[str]=None, bruteforce: Optional[bool]=False, engines: Optional[str]=None ):
    print(ports)
    if checkDomain(domain) == False:
        res.status_code = status.HTTP_400_BAD_REQUEST
        return {"Error": "Please input valid domain"}

    if engines != None:
        if checkEngine(engines.split(',')) == False:
            res.status_code = status.HTTP_400_BAD_REQUEST
            return {"Error": "Bad Input"}

    try:
        subdomains = await scan(domain, ports, bruteforce, engines)
    except TypeError as identifier:
        res.status_code = status.HTTP_503_SERVICE_UNAVAILABLE  
        return {"Error": "Something error"}

    if ports:
        ports = ports.split(',')
        try:
            pscan = portscan(subdomains, ports)
            subListPort = await pscan.run()   
        except TimeoutError as identifier:
            res.status_code = status.HTTP_408_REQUEST_TIMEOUT
            return {"Error": "Request timeout"}

        if len(subListPort) > 0:
            # writeFileExcel(subListPort)
            return {"result": subListPort}
        else:
            return {"result": []}

    if len(subdomains) == 0:
        return {"result": []}
    else:
        new_subdomains = list(map(lambda subdomain: {"host": subdomain, 'port': None}, subdomains))
        # writeFileExcel(new_subdomains)
        return {"result": new_subdomains}



async def scan(domain, port, bruteforce, engines):
    subdomains = sublist3r.main(domain, 40, None, ports=None, silent=False, verbose= False, enable_bruteforce= bruteforce, engines=engines)
    return subdomains



def checkDomain(domain):
    domain_check = re.compile("^(http|https)?[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$")
    if not domain_check.match(domain):
        return False


def checkEngine(engines):
    print(engines)
    listEngine = ['baidu', 'yahoo', 'google', 'bing', 'ask', 'netcraft', 'dnsdumpster', 'virustotal', 'threatcrowd', 'ssl', 'passivedns']
    for n in engines:
            if n not in listEngine:
                return False



class portscan():
    def __init__(self, subdomains, ports):
        self.subdomains = subdomains
        self.ports = ports
        self.lock = None

    def port_scan(self, host, ports, sublistPort):
        self.lock.acquire()
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((host, int(port)))
                if result == 0:
                    print({"Host": host, "Port": port})
                    sublistPort.append({"host": host, "port": port})
                s.close()
            except Exception:
                pass
        self.lock.release()

    async def run(self):
        sublistPort = []
        threads = list()

        self.lock = threading.BoundedSemaphore(value=20)
        for subdomain in self.subdomains:
            t = threading.Thread(target=self.port_scan, args=(subdomain, self.ports, sublistPort))
            threads.append(t);
            t.start();
        
        for thread in threads:
            thread.join(2)
        
        # time.sleep(180)
        return sublistPort