from __future__ import print_function
from Crypto.PublicKey import ECC
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
import os.path
import base64
import json
import requests
from Crypto.Protocol.KDF import HKDF
from SEAL import SEAL
import ctypes


class Utils:
    @staticmethod
    def println(text):
        print(text,end='\n\n')
    @staticmethod
    def point_to_public_key_bytes(point):
            return bytes([4]) + long_to_bytes(point.x) + long_to_bytes(point.y)
    @staticmethod
    def point_to_secret_key_bytes(point):
            return long_to_bytes(point)
    @staticmethod
    def createCTypeArrayfromKeyPair(keyPair):
        key_str = "{0x"
        for i in range(len(keyPair)):
            key_str += keyPair[i]
            if i % 2 != 0 and i != len(keyPair) - 1:
                key_str += ", 0x"
        key_str += '}'
        return key_str

class SealWrapper(SEAL):
    def __init__(self):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        super().__init__(current_dir + "/libseadyn.so")
    def getStaticPublicKey(self):
        static_pub_key = super().get_public_key(0)
        return static_pub_key
    def getDevEUI(self):
        devEUI = base64.b64encode(self.getStaticPublicKey()[:8]).decode('utf-8')
        return devEUI
    def _getHash(self,message):
        digest= super().get_hash(message,len(message))
        return digest
    def sign(self,message):
        signature= super().sign(0,self._getHash(message))
        return signature
    def getBase64Signature(self,message):
        b64_signature = base64.b64encode(self.sign(message)).decode('utf-8')
        return b64_signature
    def store(self,message):
        super().store_data(10,(ctypes.c_ubyte*16).from_buffer_copy(message),16)
    def read(self):
        return super().read_data(10,16)





class SharedSecret:
    def __init__(self):
        ephemeral_key = ECC.generate(curve='P-256')
        ephemeral_pub_key = ephemeral_key.pointQ
        self.ephemeral_sec_key = ephemeral_key.d
        self.ephemeral_pub_key_bytes = Utils.point_to_public_key_bytes(ephemeral_pub_key)
    def getEphemeralPublicKey(self):
        return self.ephemeral_pub_key_bytes
    def getBase64PublicKey(self):
        return base64.b64encode(self.getEphemeralPublicKey()).decode('utf-8')
    def calculateSharedSecret(self,ephemeralLedgerPublicKey):
        ephemeralLedgerKeyX = int.from_bytes(ephemeralLedgerPublicKey[1:33], byteorder='big')
        ephemeralLedgerKeyY = int.from_bytes(ephemeralLedgerPublicKey[33:], byteorder='big')
        ephemeralLedgerKey = ECC.construct(point_x=ephemeralLedgerKeyX, point_y=ephemeralLedgerKeyY, curve='secp256r1')
        secret = ephemeralLedgerKey.public_key().pointQ * self.ephemeral_sec_key

        # HKDF the coordinates of the shared secret point
        secret_hkdf = HKDF(secret.x.to_bytes() + secret.y.to_bytes(), 16, b'', SHA256)
        return secret_hkdf




class Verifier:
    def __init__(self,serverStaticPublicKey='BJStOzHeObJ7KKQv5xJFr4LJjGsRN/Qhtss1eC/hwxAv4nRXrsWS+Lxq/KHvXDLSqi02kAcMHMoB0BfviJjGGTU='):
        staticLedgerKeyBuffer = base64.b64decode(serverStaticPublicKey)
        staticLedgerKeyX = int.from_bytes(staticLedgerKeyBuffer[1:33], byteorder='big')
        staticLedgerKeyY = int.from_bytes(staticLedgerKeyBuffer[33:], byteorder='big')
        self.staticLedgerKey = ECC.construct(point_x=staticLedgerKeyX, point_y=staticLedgerKeyY, curve='secp256r1')

    def verify(self,response):

        try:
            serverEphemeralKey = base64.b64decode(response["data"]["ephemeralKey"])
            serverSignature = base64.b64decode(response["data"]["signature"])
            verifier = DSS.new(self.staticLedgerKey, 'fips-186-3')
            verifier.verify(SHA256.new(serverEphemeralKey),(serverSignature))
            print('Signature from ledger is valid')
            return True
        except KeyError:
            print('Invalid JSON Fields')
            return False
        except ValueError:
            print('Signature is not valid')
            return False

class NISTP_Pair:

    key = None

    @staticmethod
    def generate_key(curve='P-256'):
        NISTP_Pair.key = (ECC.generate(curve=curve))
        NISTP_Pair.save_key()
    @staticmethod
    def save_key(filename='myprivatekey.pem'):
        f = open(filename,'wt')
        f.write(NISTP_Pair.key.export_key(format='PEM'))
        f.close()
    @staticmethod
    def read_key():
        f = open('myprivatekey.pem','rt')
        NISTP_Pair.key = ECC.import_key(f.read())
        f.close()
        return NISTP_Pair.key


class Network:

    headers = {'content-type': 'application/json','x-api-key': '4O8R5sCy889lR2IsUSJrgaekDTLIBcR11nIcYuRC'}
    service = "https://yjlwd381s5.execute-api.eu-central-1.amazonaws.com/dev/devices"

    def createBody(self,DevEUI,ephemeralKey,signedEphemeralKey):
        self.body = {"id": DevEUI,'ephemeralKey': ephemeralKey,
            'signedEphemeralKey':signedEphemeralKey}
        return self.body
    def post(self,DevEUI,ephemeralKey,signedEphemeralKey):
        response = requests.post(self.service , headers=self.headers, json=self.createBody(DevEUI,ephemeralKey,signedEphemeralKey)).json()
        return response

class MockNetwork():
    def post(self,DevEUI,ephemeralKey,signedEphemeralKey):
        mockResponse ={

        "data": {

        "ephemeralKey": "BPz/r0PkhFqCjlpfm2gOkgp1T0f5GMcQNW7PM495hXnHLtzmPxuKPbG9txkqR/esXWtlb3zyfZvZIukFny771OI=",

        "signature": "xuaV3OUe3C0EWFQO2c/Da+j3eNXODmC4UymGAZDfsJV4ILD0JJb+yq7fhlpIyCL2xtA1A9zxaX4fPM9pWR7WHg=="

        },

        "transaction_id": "76ded3117376892d69de4dbab52d897397234514ac34c7f667da565c83270ab2"

        }
        return mockResponse


seal = SealWrapper()
secret = SharedSecret()
serverEphemeralVerifier = Verifier()
bmwEndpoint = Network()
mockBmwEndpoint = MockNetwork()

response = bmwEndpoint.post(seal.getDevEUI(),secret.getBase64PublicKey(),seal.getBase64Signature(secret.getBase64PublicKey()))
Utils.println(response)
response = mockBmwEndpoint.post(seal.getDevEUI(),secret.getBase64PublicKey(),seal.getBase64Signature(secret.getBase64PublicKey()))

if serverEphemeralVerifier.verify(response) is True:

    serverEphemeralKey = base64.b64decode(response['data']['ephemeralKey'])
    secret_hkdf = secret.calculateSharedSecret(serverEphemeralKey)


    print("Calculated secret of ECDH :" + " " + str((secret_hkdf).hex()))
    print("Storing the secret inside Secure Element ... ")
    seal.store(secret_hkdf[:16])




