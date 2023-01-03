import requests
import json

def vt_hash_reputation(hash,api):
    url = "https://www.virustotal.com/api/v3/search?query="+hash
    headers = {
        "Accept": "application/json",
        "x-apikey": api
    }
    try:
        response = requests.request("GET", url, headers=headers)
        json_response = json.loads(response.text)
        r = json_response["data"]
        malicious = r[0]["attributes"]["last_analysis_stats"]["malicious"]
        scan_date = r[0]["attributes"]["last_analysis_date"]
        md5 = r[0]["attributes"]["md5"]
        scan_id = r[0]["id"]
        from datetime import datetime
        scan_date = datetime.utcfromtimestamp(scan_date).strftime('%H:%M:%S %d-%m-%Y')
        scan_link = "https://www.virustotal.com/gui/file/" + scan_id
        return malicious, scan_date, md5, scan_link
    except:
        print("Hata oluştu!")

def dosyadan_islem(api):
    from tkinter import Tk
    from tkinter.filedialog import askopenfilename
    pencere = Tk()
    pencere.attributes('-topmost', 1)
    pencere.withdraw()
    x = askopenfilename(filetypes=[('.txt', '.txt')], title='URL listesi seçin')
    try:
        with open(x, 'r', encoding='utf-8') as urls:
            data = urls.readlines()
            for i in data:
                u = i.strip()
                try:
                    sonuc = vt_hash_reputation(u, api)
                except:
                    pass
                print(u + ", " + str(sonuc))
                s = u + ", " + str(sonuc) + "\n"
                try:
                    with open(x + '_s.txt', 'a') as f:
                        f.write(s)
                        f.close()
                except:
                    print("Dosya oluşturma hatası")
    except:
        print("File read error")

dosyadan_islem("")#api input
