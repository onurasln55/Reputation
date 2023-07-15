from requests import request,get
from json import loads
from pycountry import countries

def api_check():
    try:
        with open("api_list.txt",'r') as api:
            vt_api=api.readline()
            abuseip_api=api.readline()

            print("Virustotal:\t"+vt_api)
            print("AbuseIPDB: \t"+abuseip_api)
            print("Kayıtlı API keylerdir.")
            return vt_api,abuseip_api

    except:
        print("kayıtlı api yok. api girin")
        with open("api_list.txt",'w') as api:
            vt_api=input("Virustotal api key girin:")
            api.writelines(vt_api)
            api.write("\n")
            abuseip_api=input("AbuseIPDB api key girin:")
            api.writelines(abuseip_api)
            print("API Kaydedildi programı yeniden başlatın.")
            api.close()
            return vt_api,abuseip_api
def vt_ip_sorgu(ip,key_vt):
    url = "https://www.virustotal.com/api/v3/ip_addresses/"+ip
    headers = {
        "Accept": "application/json",
        "x-apikey": key_vt
    }
    try:
        response = request("GET", url, headers=headers)
        json_response = loads(response.text)
        return json_response["data"]["attributes"]["last_analysis_stats"]["malicious"]
    except:
        return "Hata. Girdi veya API key hatalı Kontrol edin"
def abuse_ip_sorgu(ip,key_abuse):
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress':ip ,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': key_abuse
    }
    try:
        response = request(method='GET', url=url, headers=headers, params=querystring)
        json_response = loads(response.text)
        return json_response["data"]["abuseConfidenceScore"],json_response["data"]["countryCode"],json_response["data"]["usageType"],json_response["data"]["isp"]

    except:
        return "Hata. Girdi veya API key hatalı kontrol edin"
def country(code):
    try:
        country = countries.get(alpha_2=code.upper())
        if country:
            return country.name
    except LookupError:
        pass
    return None

def country_code_to_name_restcountries(code):
    url = f"https://restcountries.com/v3/alpha/{code}"
    response = get(url)
    data = response.json()
    if response.status_code == 200:
        return data["name"]["common"]
    return None

def ip():
    api_keys=api_check()
    key_vt=str(api_keys[0]).strip()
    key_abuse=str(api_keys[1]).strip()
    print("Girdi türü seçin:\n1.txt dosyası ise \n2.Tek bir ip için ")
    tur_secimi=int(input())
    if tur_secimi==1:
        from tkinter import Tk
        from tkinter.filedialog import askopenfilename

        pencere=Tk()
        pencere.attributes('-topmost', 1)
        pencere.withdraw()
        girdi_dosyasi = askopenfilename(filetypes=[('.txt', '.txt')], title='IP listesi dosyasını seçin')

        if girdi_dosyasi!="":
            from tkinter import Tk
            from tkinter.filedialog import asksaveasfilename
            pencere = Tk()
            pencere.attributes('-topmost', 1)
            pencere.withdraw()
            cikti_dosyasi = asksaveasfilename(filetypes=[('.txt', '.txt')], title='Çıktı dosyasını kaydedin.')

            if cikti_dosyasi!="":
                cikti_dosyasi=cikti_dosyasi+".txt"
                with open(cikti_dosyasi, 'w+') as sonuc_dosyası:
                    sonuc_dosyası.write("IP Adresi,Kurum,Ülke,Kullanım Tipi,AbuseipDB skoru, Virustotal skoru,AbuseipDB Link,Virustotal Link,IPalyzer Link\n")
                    print("IP Adresi,Kurum,Ülke,Kullanım Tipi,AbuseipDB skoru, Virustotal skoru,AbuseipDB Link,Virustotal Link,IPalyzer Link")
                    with open(girdi_dosyasi) as f:
                        data = [row for row in f]
                        for d in data:
                            try:
                                #AbuseIpDB işlemleri
                                abuse_all = abuse_ip_sorgu(d,key_abuse)
                                abuse_skor = str(abuse_all[0])
                                abuse_country = str(abuse_all[1])
                                abuse_usageType = str(abuse_all[2])
                                abuse_isp = str(abuse_all[3])

                                #Virustotal işlemleri
                                response_vt=vt_ip_sorgu(d,key_vt)
                                response_vt=str(response_vt)
                                ip = d
                                ip = str(ip)

                                if abuse_all == "Hata. Girdi veya API key hatalı kontrol edin":
                                    sonuc_dosyası.writelines(ip.strip() + ", ip girdisi hatalı lütfen düzeltin.\n")
                                    print(ip.strip() + ", ip girdisi hatalı lütfen düzeltin.")

                                else:
                                    sonuc_dosyası.writelines(ip.strip() + "," + abuse_isp + "," + str(country(
                                        abuse_country)) + "," + abuse_usageType + "," + abuse_skor + "," + response_vt + " ,https://www.abuseipdb.com/check/" + ip.strip() + " ,https://www.virustotal.com/gui/ip-address/" + ip.strip() + ", https://www.ipalyzer.com/" + ip.strip() + "\n")
                                    print(ip.strip() + "," + abuse_isp + "," + str(country(
                                        abuse_country)) + "," + abuse_usageType + "," + "," + abuse_skor + "," + response_vt + " ,https://www.abuseipdb.com/check/" + ip.strip() + " ,https://www.virustotal.com/gui/ip-address/" + ip.strip() + ", https://www.ipalyzer.com/" + ip.strip())
                            except:
                                print("hata")
                sonuc_dosyası.close()
            else:
                print("Çıktı dosyası seçilmedi.")
        else:
            print("girdi dosyası seçilmedi")
    elif tur_secimi == 2:
        ip=input("Ip adresini girin:")
        vt_skor=str(vt_ip_sorgu(ip, key_vt))
        abuse_all=abuse_ip_sorgu(ip, key_abuse)
        abuse_skor=str(abuse_all[0])
        abuse_country=str(abuse_all[1])
        abuse_usageType=str(abuse_all[2])
        abuse_isp=str(abuse_all[3])
        print("Kurum:" + abuse_isp)
        print("Ülke:" + str(country(abuse_country)))
        print("Kullanım tipi:" + abuse_usageType)
        print("Virustotal:"+vt_skor)
        print("AbuseIpDB:"+abuse_skor)

        if vt_skor!="Hata. Girdi veya API key hatalı Kontrol edin" or abuse_skor!="Hata. Girdi veya API key hatalı kontrol edin":

            print("https://www.virustotal.com/gui/ip-address/"+ip)
            print("https://www.abuseipdb.com/check/"+ip)
            print("https://www.ipalyzer.com/"+ip)
    else:
        print("Yanlış girş yaptınız 1 veya 2 yi tuşlayın ve Enter tuşuna basın.")

ip()
input("İşlemler tamamlandı.\nÇıkmak için Enter a basın.")
