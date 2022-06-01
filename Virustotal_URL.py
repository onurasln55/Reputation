import time

import requests
import json

def vt_url_scan(url,api):
    vt = "https://www.virustotal.com/api/v3/urls"
    payload = "url="+url
    headers = {
        "Accept": "application/json",
        "x-apikey": api,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    try:
        response = requests.request("POST", vt, data=payload, headers=headers)
        json_response = json.loads(response.text)
        id=json_response["data"]["id"]
        id=id.split("-")
        id=id[1]
        url = "https://www.virustotal.com/api/v3/urls/" + id

        headers = {
            "Accept": "application/json",
            "x-apikey": api
        }
        response = requests.get(url, headers=headers)
        json_response = json.loads(response.text)
        malicious = json_response["data"]["attributes"]["last_analysis_stats"]["malicious"]

        return malicious
    except:
        print("vt_url_upload_hata")
        return '','',''

def dosyadan_islem(api):
    from tkinter import Tk
    from tkinter.filedialog import askopenfilename

    pencere = Tk()
    pencere.attributes('-topmost', 1)
    pencere.withdraw()
    x = askopenfilename(filetypes=[('.txt', '.txt')], title='URL listesi girin')

    with open(x, 'r') as urls:
        data=urls.readlines()
        for i in data:
            u=i.strip()
            sonuc=vt_url_scan(i, api)
            print(u+","+str(sonuc))

dosyadan_islem("")#buraya api key ekleyin
