import cv2
import configparser
import logging
import secure
import requests

logging.basicConfig(
    filename='logs.log',
    level=logging.DEBUG, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)

CAMERA_OBJECT = cv2.VideoCapture(0)
QRCODE_DETECTOR = cv2.QRCodeDetector()
CONFIG_PARSER = configparser.ConfigParser()
CONFIG_PARSER.read("config.ini")
SERVERURL = CONFIG_PARSER["server"]["url"]
SERVERAPI = CONFIG_PARSER["server"]["api"]
SERVERID = CONFIG_PARSER["server"]["id"]

headers = {
    "API-Code":SERVERAPI,
    "server-id":SERVERID
}

def scan_qr():
    while True:
        _,frame = CAMERA_OBJECT.read()
        data,_,_ = QRCODE_DETECTOR.detectAndDecode(frame)
        if data:
            logging.info("Scanned QR; initialize next step.")
            return data


def data_parser(data):
    split_len = int(CONFIG_PARSER["data"]["split"])
    keycheck = int(CONFIG_PARSER["data"]["keycheck"]) - 1
    _data = data.split(";")
    username,userid,picture,fullname = _data[:4]
    permission = _data[4]
    if len(_data) != split_len:
        keys = [CONFIG_PARSER["keys"][key] for key in CONFIG_PARSER["keys"].keys()] # default keys from config
    else:
        keys = _data[5:]
    
    if int(keys[keycheck],16) != int(permission,2):
        logging.error("Encryption keycheck doesn't match permission. Invalid QR code")
        return False
    else :
        try:
            encryption_key = secure.generate_encryption_key(keys)
            username = secure.decrypt(username,encryption_key)
            userid = secure.decrypt(userid,encryption_key)
            picture = secure.decrypt(picture,encryption_key)
            fullname = secure.decrypt(fullname,encryption_key)
            data = {
                "username":username,
                "userid":userid,
                "picture":picture,
                "fullname":fullname,
            }
            """if requests.post(SERVERURL,headers = headers, json = data).status_code == 200:
                return True"""
            logging.error("Couldn't verify information.")
            return False
        except Exception as e:
            logging.error(f"an error occured {e}")