from requests import request,get
from json import loads
def vt_url_scan(url,api):
    vt = "https://www.virustotal.com/api/v3/urls"
    payload = "url="+url
    headers = {"Accept": "application/json","x-apikey": api,"Content-Type": "application/x-www-form-urlencoded"}
    try:
        response = request("POST", vt, data=payload, headers=headers)
        json_response = loads(response.text)
        id=json_response["data"]["id"]
        id=id.split("-")
        id=id[1]
        url = "https://www.virustotal.com/api/v3/urls/" + id
        headers = {"Accept": "application/json","x-apikey": api}
        response = get(url, headers=headers)
        json_response = loads(response.text)
        malicious = json_response["data"]["attributes"]["last_analysis_stats"]["malicious"]
        return malicious
    except:
        print("vt_url_upload_hata")
        return '','',''
def dosyadan_islem(api): #dosya konumu vermeden dosya arayüzü ile ekleme.
    from tkinter import Tk
    from tkinter.filedialog import askopenfilename
    pencere = Tk()
    pencere.attributes('-topmost', 1)
    pencere.withdraw()
    x = askopenfilename(filetypes=[('.txt', '.txt')], title='URL listesi seçin')
    try:
        with open(x, 'r') as urls:
            data=urls.readlines()
            for i in data:
                u=i.strip()
                sonuc=vt_url_scan(i, api)
                print(u+","+str(sonuc))
                s=u+","+str(sonuc)+"\n"
                try:
                    with open(x+'_s.csv', 'a') as f:
                        f.write(s)
                        f.close()
                except:
                    print("CSV oluşturma hatası")
    except:
        print("File read error")
api=input("Enter the Virustotal api key: ")#Bu bölgede api keyi dışarıdan giriyoruz.
dosyadan_islem(api)
input("Click Enter to close")
