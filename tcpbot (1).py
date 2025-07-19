import warnings
warnings.filterwarnings("ignore", category=UserWarning)
import threading
import jwt
import random
from threading import Thread
import json
import requests
import json
import time
import datetime
from protobuf_decoder.protobuf_decoder import Parser
from datetime import datetime
from google.protobuf.json_format import MessageToJson
import xdd_pb2
import trick_pb2
import data_pb2
import MajorLoginRes_pb2
import base64
from datetime import datetime
import logging
import re
import socket
from google.protobuf.timestamp_pb2 import Timestamp
import uwu_pb2
import os
import binascii
import sys
import psutil
import urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BOT_ID = 12173210

SESSION_FILE = 'session.json'

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def read_bytes_from_file(filename):
    with open(filename, 'r') as file:
        return file.read().strip()

def get_random_user_agent():
    versions = ['4.0.18P6', '4.0.19P7', '4.0.20P1', '4.1.0P3']
    models = ['G011A', 'G012B', 'SM-G973F', 'Pixel 3', 'Redmi Note 8']
    android_versions = ['8.1', '9', '10', '11', '12']
    languages = ['en', 'en-US', 'id', 'es', 'pt-BR']
    countries = ['USA', 'IND', 'IDN', 'BRA', 'MEX']

    version = random.choice(versions)
    model = random.choice(models)
    android = random.choice(android_versions)
    lang = random.choice(languages)
    country = random.choice(countries)

    return f"GarenaMSDK/{version}({model} ;Android {android};{lang};{country};)"



def encrypt_packet(plain_text, key, iv):
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def get_available_room(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = parse_results(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        print(f"error {e}")
        return None

def get_random_avatar():
    avatar_list = ['902049014']
    return random.choice(avatar_list)

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data["wire_type"] = result.wire_type
        if result.wire_type == "varint":
            field_data["data"] = result.data
        if result.wire_type == "string":
            field_data["data"] = result.data
        if result.wire_type == "bytes":
            field_data["data"] = result.data
        elif result.wire_type == "length_delimited":
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

def dec_to_hex(ask):
    ask_result = hex(ask)
    final_result = str(ask_result)[2:]
    if len(final_result) == 1:
        final_result = "0" + final_result
    return final_result

def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return binascii.hexlify(encrypted_message).decode('utf-8')

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 3, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def extract_jwt_from_hex(hex_str):
    byte_data = binascii.unhexlify(hex_str)
    message = uwu_pb2.Garena_420()
    message.ParseFromString(byte_data)
    json_output = MessageToJson(message)
    token_data = json.loads(json_output)
    return token_data

def format_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

def restart_program():
    print("Restarting program...")
    time.sleep(2)
    p = psutil.Process(os.getpid())
    for handler in p.open_files():
        try:
            os.close(handler.fd)
        except Exception:
            pass
    python = sys.executable
    os.execl(python, python, *sys.argv)

def get_player_status(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result) if json_result else {}
    if not isinstance(parsed_data.get("5"), dict) or "data" not in parsed_data["5"]:
        return "OFFLINE"
    json_data = parsed_data["5"]["data"]
    if not isinstance(json_data.get("1"), dict) or "data" not in json_data["1"]:
        return "OFFLINE"
    data = json_data["1"]["data"]
    if not isinstance(data, dict) or "3" not in data:
        return "OFFLINE"
    status_data = data["3"]
    if not isinstance(status_data, dict) or "data" not in status_data:
        return "OFFLINE"
    status = status_data["data"]
    if status == 1:
        return "SOLO"
    if status == 2:
        try:
            group_count = data["9"]["data"]
            countmax1 = data["10"]["data"]
            countmax = countmax1 + 1
            return f"INSQUAD ({group_count}/{countmax})"
        except Exception:
            return "INSQUAD"
    if status in [3, 5]:
        return "INGAME"
    if status == 4:
        return "IN ROOM"
    if status in [6, 7]:
        return "IN SOCIAL ISLAND MODE .."
    return "NOTFOUND"

def get_idroom_by_idplayer(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result) if json_result else {}
    if not isinstance(parsed_data, dict):
        parsed_data = {}
    json_data = parsed_data.get("5", {}).get("data", {})
    data = json_data.get("1", {}).get("data", {})
    idroom = data.get("15", {}).get("data", None)
    return idroom

def get_leader(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result) if json_result else {}
    if not isinstance(parsed_data, dict):
        parsed_data = {}
    json_data = parsed_data.get("5", {}).get("data", {})
    data = json_data.get("1", {}).get("data", {})
    leader = data.get("8", {}).get("data", None)
    return leader

def generate_random_color():
    color_list = [
        "[00FF00][b][c]",
        "[FFDD00][b][c]",
        "[3813F3][b][c]",
        "[FF0000][b][c]",
        "[0000FF][b][c]",
        "[FFA500][b][c]",
        "[DF07F8][b][c]",
        "[11EAFD][b][c]",
        "[DCE775][b][c]",
        "[A8E6CF][b][c]",
        "[7CB342][b][c]",
        "[FF0000][b][c]",
        "[FFB300][b][c]",
        "[90EE90][b][c]"
    ]
    return random.choice(color_list)

def fix_num(num):
    fixed = ""
    count = 0
    num_str = str(num)
    for char in num_str:
        if char.isdigit():
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0
    return fixed

def rrrrrrrrrrrrrr(number):
    if isinstance(number, str) and '***' in number:
        return number.replace('***', '106')
    return number

def Encrypt(number):
    number = int(number)
    encoded_bytes = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80
        encoded_bytes.append(byte)
        if not number:
            break
    return bytes(encoded_bytes).hex()

def create_protobuf_packet(fields):
    result_hex = ""
    for field_num in sorted(fields.keys()):
        value = fields[field_num]
        if isinstance(value, dict):
            nested_bytes = create_protobuf_packet(value)
            nested_hex = nested_bytes.hex()
            length_hex = Encrypt(len(nested_bytes))
            tag = (field_num << 3) | 2
            tag_hex = Encrypt(tag)
            result_hex += tag_hex + length_hex + nested_hex
        elif isinstance(value, str):
            encoded = value.encode('utf-8')
            length_hex = Encrypt(len(encoded))
            tag = (field_num << 3) | 2
            tag_hex = Encrypt(tag)
            result_hex += tag_hex + length_hex + encoded.hex()
        elif isinstance(value, bytes):
            length_hex = Encrypt(len(value))
            tag = (field_num << 3) | 2
            tag_hex = Encrypt(tag)
            result_hex += tag_hex + length_hex + value.hex()
        elif isinstance(value, bool):
            tag = (field_num << 3) | 0
            tag_hex = Encrypt(tag)
            val_hex = Encrypt(1 if value else 0)
            result_hex += tag_hex + val_hex
        elif value is None:
            tag = (field_num << 3) | 2
            tag_hex = Encrypt(tag)
            result_hex += tag_hex + "00"
        else:
            tag = (field_num << 3) | 0
            tag_hex = Encrypt(tag)
            val_hex = Encrypt(value)
            result_hex += tag_hex + val_hex
    return bytes.fromhex(result_hex)

class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        threading.Thread.__init__(self)
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.token = None
        self.tempdata = None
        self.tempdata1 = None
        self.statusinfo = False
        self.pleaseaccept = False
        self.sent_inv = False
        self.tempid = None
        self.leaveee = False
        self.start_par = False
        self.nameinv = None
        self.idinv = None
        self.senthi = False
        self.autospam_active = False
        self.autospam_active = {}
        
    def parse_my_message(self, serialized_data):
        try:
            MajorLogRes = trick_pb2.MajorLoginRes()
            MajorLogRes.ParseFromString(serialized_data)
            key = MajorLogRes.ak
            iv = MajorLogRes.aiv
            if isinstance(key, bytes):
                key = key.hex()
            if isinstance(iv, bytes):
                iv = iv.hex()
            self.key = key
            self.iv = iv
            print(f"Key: {self.key} | IV: {self.iv}")
            return self.key, self.iv
        except Exception as e:
            print(f"{e}")
            return None, None

    def nmnmmmmn(self, data):
        key, iv = self.key, self.iv
        try:
            key = key if isinstance(key, bytes) else bytes.fromhex(key)
            iv = iv if isinstance(iv, bytes) else bytes.fromhex(iv)
            data = bytes.fromhex(data)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            cipher_text = cipher.encrypt(pad(data, AES.block_size))
            return cipher_text.hex()
        except Exception as e:
            print(f"Error in nmnmmmmn: {e}")

    def GenResponsMsg(self, Msg, Enc_Id):
        fields = {
        1: 1,
        2: {
            1: 11406675779,
            2: Enc_Id,
            3: 2,
            4: str(Msg),
            5: int(datetime.now().timestamp()),
            9: {
                1: "ＤＥＶㅤＡＲＩＩᴮᴼᵀ",
                2: int(get_random_avatar()),
                3: 901049014,
                4: 330,
                5: 800000304, #pin replace with any item magic cube , stone, characters etc
                8: "GUILD|BOT",
                10: 1,
                11: 1,
                13: {1: 2,2:64}, 
                14: {
                1: 1158053040,
                2: 8,
        3: "\u0010\u0015\b\n\u000b\u0013\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"
        }
            },
            10: "en",
            13:
            {
            1: "https://graph.facebook.com/v9.0/104076471965380/picture?width=160&height=160",
            2: 1,
            3: 1
            },
            14: {
            1: {
                1: 1,
                2: 1,
                3: 1,
                4: 1,
                5: 1748201400,
                6: "BR"
            }
        }
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, self.key, self.iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "1203000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "120300000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "12030000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "1203000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def createpacketinfo(self, idddd):
        ida = Encrypt(idddd)
        packet = f"080112090A05{ida}1005"
        header_length = len(encrypt_packet(packet, self._key if isinstance(self._key, bytes) else self._key, self._iv if isinstance(self._iv, bytes) else self._iv)) // 2
        header_length_final = dec_to_hex(header_length)
        if len(header_length_final) == 2:
            final_packet = "0F15000000" + header_length_final + self.nmnmmmmn(packet)
        elif len(header_length_final) == 3:
            final_packet = "0F1500000" + header_length_final + self.nmnmmmmn(packet)
        elif len(header_length_final) == 4:
            final_packet = "0F150000" + header_length_final + self.nmnmmmmn(packet)
        elif len(header_length_final) == 5:
            final_packet = "0F15000" + header_length_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def spam_room(self, idroom, idplayer, invitation_name):
        fields = {
            1: 78,
            2: {
                1: int(idroom),
                2: invitation_name,
                4: 330,
                5: 6000,
                6: 201,
                10: int(get_random_avatar()),
                11: int(idplayer),
                12: 1
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_length = len(encrypt_packet(packet, self._key if isinstance(self._key, bytes) else self._key, self._iv if isinstance(self._iv, bytes) else self._iv)) // 2
        header_length_final = dec_to_hex(header_length)
        if len(header_length_final) == 2:
            final_packet = "0E15000000" + header_length_final + self.nmnmmmmn(packet)
        elif len(header_length_final) == 3:
            final_packet = "0E1500000" + header_length_final + self.nmnmmmmn(packet)
        elif len(header_length_final) == 4:
            final_packet = "0E150000" + header_length_final + self.nmnmmmmn(packet)
        elif len(header_length_final) == 5:
            final_packet = "0E15000" + header_length_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
        


    def skwad_maker(self):
        fields = {
            1: 1,
            2: {
                2: "\u0001",
                3: 1,
                4: 1,
                5: "en",
                9: 1,
                11: 1,
                13: 1,
                14: {
                    2: 5756,
                    6: 11,
                    8: "1.109.5",
                    9: 3,
                    10: 2
                }
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_length = len(encrypt_packet(packet, self._key if isinstance(self._key, bytes) else self._key, self._iv if isinstance(self._iv, bytes) else self._iv)) // 2
        header_length_final = dec_to_hex(header_length)
        if len(header_length_final) == 2:
            final_packet = "0515000000" + header_length_final + self.nmnmmmmn(packet)
        elif len(header_length_final) == 3:
            final_packet = "051500000" + header_length_final + self.nmnmmmmn(packet)
        elif len(header_length_final) == 4:
            final_packet = "05150000" + header_length_final + self.nmnmmmmn(packet)
        elif len(header_length_final) == 5:
            final_packet = "0515000" + header_length_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def changes(self, num):
        fields = {
            1: 17,
            2: {
                1: 131771246,
                2: 1,
                3: int(num),
                4: 62,
                5: "\u001a",
                8: 5,
                13: 329
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_length = len(encrypt_packet(packet, self._key if isinstance(self._key, bytes) else self._key, self._iv if isinstance(self._iv, bytes) else self._iv)) // 2
        header_length_final = dec_to_hex(header_length)
        if len(header_length_final) == 2:
            final_packet = "0515000000" + header_length_final + self.nmnmmmmn(packet)
        elif len(header_length_final) == 3:
            final_packet = "051500000" + header_length_final + self.nmnmmmmn(packet)
        elif len(header_length_final) == 4:
            final_packet = "05150000" + header_length_final + self.nmnmmmmn(packet)
        elif len(header_length_final) == 5:
            final_packet = "0515000" + header_length_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def leave_s(self):
        fields = {
            1: 7,
            2: {
                1: 131771246
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_length = len(encrypt_packet(packet, self._key if isinstance(self._key, bytes) else self._key, self._iv if isinstance(self._iv, bytes) else self._iv)) // 2
        header_length_final = dec_to_hex(header_length)
        if len(header_length_final) == 2:
            final_packet = "0515000000" + header_length_final + self.nmnmmmmn(packet)
        elif len(header_length_final) == 3:
            final_packet = "051500000" + header_length_final + self.nmnmmmmn(packet)
        elif len(header_length_final) == 4:
            final_packet = "05150000" + header_length_final + self.nmnmmmmn(packet)
        elif len(header_length_final) == 5:
            final_packet = "0515000" + header_length_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def invite_skwad(self, idplayer):
        fields = {
            1: 2,
            2: {
                1: int(idplayer),
                2: "BR",
                4: 1
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_length = len(encrypt_packet(packet, self._key if isinstance(self._key, bytes) else self._key, self._iv if isinstance(self._iv, bytes) else self._iv)) // 2
        header_length_final = dec_to_hex(header_length)
        if len(header_length_final) == 2:
            final_packet = "0515000000" + header_length_final + self.nmnmmmmn(packet)
        elif len(header_length_final) == 3:
            final_packet = "051500000" + header_length_final + self.nmnmmmmn(packet)
        elif len(header_length_final) == 4:
            final_packet = "05150000" + header_length_final + self.nmnmmmmn(packet)
        elif len(header_length_final) == 5:
            final_packet = "0515000" + header_length_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)


    def try_send(self, sock, data):
        try:
            sock.send(data)
        except OSError:
            pass

    def auto_spam(self, target_id, uid_sender, nome):
        global clients, socket_client
        convite_base = generate_random_color() + nome
        inicio = time.time()
        fim = inicio + 50
        clients.send(self.GenResponsMsg("[C][B][FF0000]SPAM INICIADO! (50s)", uid_sender))
        while time.time() < fim and target_id in self.autospam_active:
            try:
                socket_client.send(self.createpacketinfo(target_id))
                if self.tempdata and "IN ROOM" in self.tempdata:
                    sala = get_idroom_by_idplayer(self.data22) if hasattr(self, "data22") else None
                    if sala:
                        pkt = self.spam_room(sala, target_id, convite_base)
                        for _ in range(10):
                            threading.Thread(target=self.try_send, args=(socket_client, pkt)).start()
                time.sleep(random.uniform(0.2, 0.5))
            except Exception:
                time.sleep(random.uniform(0.2, 0.5))
        clients.send(self.GenResponsMsg("[C][B][FF0000]SPAM FINALIZADO!", uid_sender))
        if target_id in self.autospam_active:
            del self.autospam_active[target_id]
        with open("autospam_state.json", "w") as f:
            json.dump(self.autospam_active, f)
            
        

            
    def auto_spam_resume(self, target_id, restante, nome):
        global clients, socket_client
        convite_base = generate_random_color() + nome
        inicio = time.time()
        fim = inicio + restante
        clients.send(self.GenResponsMsg(f"[C][B][FF0000]SPAM INICIADO! ({int(restante)}s)", BOT_ID))
        while time.time() < fim and target_id in self.autospam_active:
            try:
                socket_client.send(self.createpacketinfo(target_id))
                if self.tempdata and "IN ROOM" in self.tempdata:
                    sala = get_idroom_by_idplayer(self.data22) if hasattr(self, "data22") else None
                    if sala:
                        pkt = self.spam_room(sala, target_id, convite_base)
                        for _ in range(10):
                            threading.Thread(target=self.try_send, args=(socket_client, pkt)).start()
                time.sleep(random.uniform(0.2, 0.5))
            except Exception:
                time.sleep(random.uniform(0.2, 0.5))
        clients.send(self.GenResponsMsg("[C][B][FF0000]SPAM FINALIZADO!", BOT_ID))
        if target_id in self.autospam_active:
            del self.autospam_active[target_id]
        with open("autospam_state.json", "w") as f:
            json.dump(self.autospam_active, f)
            

    def resume_autospam(self):
        if os.path.exists("autospam_state.json"):
            with open("autospam_state.json", "r") as f:
                self.autospam_active = json.load(f)
            for tgt, ts in list(self.autospam_active.items()):
                restante = 50 - (time.time() - ts)
                if restante > 0:
                    threading.Thread(
                        target=self.auto_spam_resume,
                        args=(tgt, restante, "AUTO SPAM"),
                        daemon=True
                    ).start()
                else:
                    del self.autospam_active[tgt]
            with open("autospam_state.json", "w") as f:
                json.dump(self.autospam_active, f)
                
                


    def sockf1(self, tok, host, port, packet, key, iv):
        global socket_client
        while True:
            try:
                socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket_client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                socket_client.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                socket_client.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                socket_client.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 6)
                socket_client.connect((host, int(port)))
                print(f" Servidor conectado! Porta: {port}, IP: {host} ")
                socket_client.send(bytes.fromhex(tok))
                while True:
                    try:
                        data2 = socket_client.recv(9999)
                        if not data2:
                            raise ConnectionResetError
                        h = data2.hex()
                        if h.startswith("0505"):
                            pkt = "08" + h.split("08", 1)[1]
                            pd = json.loads(get_available_room(pkt) or "{}")
                            v = pd.get("4", {}).get("data") if isinstance(pd, dict) else None
                            if v == 6:
                                self.leaveee = True
                            elif v == 50:
                                self.pleaseaccept = True
                        elif h.startswith("0f00"):
                            pkt = "08" + h.split("08", 1)[1]
                            pd = json.loads(get_available_room(pkt) or "{}")
                            if not isinstance(pd, dict):
                                continue
                            asdj = pd.get("2", {}).get("data")
                            try:
                                self.tempdata = get_player_status(pkt)
                                if self.tempdata == "OFFLINE" or self.tempdata == "NOTFOUND":
                                    self.tempdata = "IN ROOM (Failed to get status)"
                            except Exception as e:
                                print(f"Error getting player status: {e}")
                                self.tempdata = "IN ROOM (Failed to get status)"
                            
                            if asdj == 15:
                                player_dict = pd.get("5", {}).get("data", {}).get("1", {}).get("data", {}) if isinstance(pd.get("5", {}), dict) else {}
                                idplayer = player_dict.get("1", {}).get("data")
                                idplayer1 = fix_num(idplayer) if idplayer else ""
                                if "IN ROOM" in self.tempdata:
                                    try:
                                        rid = get_idroom_by_idplayer(pkt)
                                        rid1 = fix_num(rid) if rid else ""
                                        self.tempdata = f"id : {idplayer1}\nstatus : {self.tempdata}\nid room : {rid1}"
                                        self.data22 = pkt
                                    except:
                                        self.tempdata = f"id : {idplayer1}\nstatus : {self.tempdata}"
                                elif "INSQUAD" in self.tempdata:
                                    try:
                                        idleader = get_leader(pkt)
                                        idleader1 = fix_num(idleader) if idleader else ""
                                        self.tempdata = f"id : {idplayer1}\nstatus : {self.tempdata}\nleader id : {idleader1}"
                                    except:
                                        self.tempdata = f"id : {idplayer1}\nstatus : {self.tempdata}"
                                else:
                                    if not self.tempdata.startswith("id :"):
                                        self.tempdata = f"id : {idplayer1}\nstatus : {self.tempdata}"
                                self.statusinfo = True
                                print(self.tempdata)
                        elif h.startswith("0e00"):
                            pkt = "08" + h.split("08", 1)[1]
                            pd = json.loads(get_available_room(pkt) or "{}")
                            if not isinstance(pd, dict):
                                continue
                            asdj = pd.get("2", {}).get("data")
                            try:
                                self.tempdata1 = get_player_status(pkt)
                                if self.tempdata1 == "OFFLINE" or self.tempdata1 == "NOTFOUND":
                                    self.tempdata1 = "IN ROOM (Failed to get status)"
                            except Exception as e:
                                print(f"Error getting player status: {e}")
                                self.tempdata1 = "IN ROOM (Failed to get status)"
                                
                            if asdj == 14:
                                room = pd.get("5", {}).get("data", {}).get("1", {}).get("data", {})
                                if isinstance(room, dict):
                                    nameroom = room.get("2", {}).get("data", "")
                                    maxp = room.get("7", {}).get("data", "")
                                    nowp = room.get("6", {}).get("data", "")
                                    maxp1 = fix_num(maxp) if maxp else ""
                                    nowp1 = fix_num(nowp) if nowp else ""
                                    self.tempdata1 = f"{self.tempdata}\nRoom name : {nameroom}\nMax player  : {maxp1}\nLive player : {nowp1}"
                                    print(self.tempdata1)
                    except (ConnectionResetError, socket.error):
                        raise
                    except Exception as e:
                        print(f"[sockf1] erro interno: {e}")
                        continue
            except (ConnectionResetError, socket.error) as e:
                try:
                    socket_client.close()
                except:
                    pass
                print(f"[sockf1] reconectando em 1s... erro: {e}")
                time.sleep(1)
                continue
  
    def connect(self, tok, host, port, packet, key, iv):
        global BOT_ID
        self._tok = tok
        self._host = host
        self._port = int(port)
        self._packet = packet
        self._key = key
        self._iv = iv
        global clients
        clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clients.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        clients.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
        clients.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        clients.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 6)
        clients.connect((self._host, self._port))
        clients.send(bytes.fromhex(self._tok))
        thread = threading.Thread(target=self.sockf1, args=(self._tok, "154.223.134.35", 39699, self._packet, self._key, self._iv))
        threads.append(thread)
        thread.start()
        self.resume_autospam()
        while True:
            try:
                data = clients.recv(9999)
                if not data:
                    raise ConnectionResetError
                raw_hex = data.hex()
                if not raw_hex.startswith("1200"):
                    continue
                parsed = json.loads(get_available_room(raw_hex[10:]))
                payload = parsed.get("5", {}).get("data", {})
                if not isinstance(payload, dict):
                    continue
                uid_sender = payload.get("1", {}).get("data")
                cmd_raw = payload.get("4", {}).get("data", "")
                nick_sender = payload.get("9", {}).get("data", {}).get("1", {}).get("data", "")
                if not isinstance(cmd_raw, str):
                    continue
                if uid_sender != BOT_ID:
                    if cmd_raw.startswith("/"):
                        print(f'[LOG] Player "{nick_sender}", {uid_sender} mandou o comando {cmd_raw}')
                    else:
                        print(f'[LOG] Player {nick_sender}, {uid_sender} mandou a mensagem: {cmd_raw}')
                if cmd_raw.startswith("[C][B]"):
                    continue
                cmd = cmd_raw.lower().strip()
                if cmd.startswith("/ai "):
                    pergunta = cmd_raw[4:].strip()
                    try:
                        r = requests.get(f"https://api.bielnetwork.com.br/chat/ai?pergunta={pergunta}", verify=False)
                        r.raise_for_status()
                        resposta = r.json().get("resposta:", "Erro na API")
                    except Exception:
                        resposta = "Erro na API AI."
                    clients.send(self.GenResponsMsg(f"[C][B][FF00FF]{resposta}", uid_sender))
                elif cmd.startswith("/likes "):
                    p = cmd_raw.split()
                    if len(p) < 2 or not p[1].isdigit():
                        clients.send(
                            self.GenResponsMsg(
                                "[C][B][FF0000]Uso correto: /likes <uid> [quantidade]",
                                uid_sender
                            )
                        )
                    else:
                        alvo = p[1]

                        # ── quantidade: default 100 se não informado ──
                        qtd_raw = p[2] if len(p) > 2 else "100"

                        # ── checa se é número inteiro ──
                        if not qtd_raw.isdigit():
                            clients.send(
                                self.GenResponsMsg(
                                    "[C][B][FFA500]Quantidade máxima é 100! E a mínima é 1!",
                                    uid_sender
                                )
                            )
                            continue   # pula restante do bloco

                        qtd_int = int(qtd_raw)

                        # ── aplica limites 1-100 ──
                        if qtd_int < 1 or qtd_int > 100:
                            clients.send(
                                self.GenResponsMsg(
                                    "[C][B][FFA500]Quantidade máxima é 100! E a mínima é 1!",
                                    uid_sender
                                )
                            )
                            continue

                        qtd = str(qtd_int)

                        try:
                            url = (
    "https://likes.ffgarena.cloud/api/v2/likes"
    f"?uid={alvo}&amount_of_likes={qtd}&auth=biel_owner7129"
                            )
                          
                            info = requests.get(url, verify=False).json()

                            # ── player não encontrado ──
                            if info.get("error") == "player_not_found":
                                msg = "[C][B][FFFF00]Player não encontrado!"
                            else:
                                msg = (
    "[C][B][00FF00]--------- • Likes Aumentados com Sucesso! • ---------[c]\n"
    f"[C][B][FFFF00]• Nome: {info.get('nickname', 'N/A')}[c]\n"
    f"[C][B][00FFFF]• Likes Antes: {info.get('likes_antes', 'N/A')}[c]\n"
    f"[C][B][00FFFF]• Likes Depois: {info.get('likes_depois', 'N/A')}[c]\n"
    "[C][B][00FF00]------------------------------------[c]"
)
                              
                        except Exception as e:
                            msg = f"[C][B][FF0000]Erro ao enviar likes: {e}"

                        clients.send(self.GenResponsMsg(msg, uid_sender))

                elif cmd.startswith("/info "):
                    p = cmd_raw.split()
                    if len(p) != 2 or not p[1].isdigit():
                        clients.send(self.GenResponsMsg("[C][B][FF0000]Uso correto: /info <uid>", uid_sender))
                    else:
                        alvo = p[1]
                        try:
                            r = requests.get(f"https://freefireinfo.squareweb.app/api/info_player?uid={alvo}&region=br&api_key=UCsA7LhLyDlPom2b3tD6", verify=False)
                            r.raise_for_status()
                            j = r.json()
                            b = j.get("basicInfo", {})
                            s = j.get("socialInfo", {})
                            nome = b.get("nickname", "")
                            lvl = b.get("level", 0)
                            lik = b.get("liked", 0)
                            bio = s.get("signature", "")
                            rel = b.get("releaseVersion", "")
                            msg = "[C][B][FFFF00]Informações básicas da conta\n" \
                                  f"[C][B][FF0000]Nome: {nome}\n" \
                                  f"Level: {lvl}\n" \
                                  f"Likes: {lik}\n" \
                                  f"Bio: {bio}\n" \
                                  f"Versão atual: {rel}"
                            clients.send(self.GenResponsMsg(msg, uid_sender))
                        except Exception as e:
                            clients.send(self.GenResponsMsg(f"[C][B][FF0000]Erro na API info: {e}", uid_sender))
                elif cmd == "biel":
                    clients.send(self.GenResponsMsg("[C][B][FF00FF]by @bielzGG", uid_sender))
                elif cmd.startswith("/5 "):
                    p = cmd_raw.split()
                    if len(p) != 2 or not p[1].isdigit():
                        clients.send(self.GenResponsMsg("[C][B][FFDD00]Uso correto: /5 <id>", uid_sender))
                    else:
                        tgt = p[1].replace("***", "106")
                        socket_client.send(self.skwad_maker())
                        time.sleep(1)
                        socket_client.send(self.changes(4))
                        socket_client.send(self.invite_skwad(tgt))
                        clients.send(self.GenResponsMsg("[C][B][00BFFF]Squad Montado! [C][B][7B68EE] Aceite o pedido em até 3s!", uid_sender))
                        threading.Timer(3, restart_program).start()
                elif cmd.startswith("/spamroom "):
                    p = cmd_raw.split(maxsplit=2)
                    if len(p) < 2 or not p[1].isdigit():
                        clients.send(self.GenResponsMsg("[C][B][FFDD00]Uso correto: /spamroom <id> [nome]", uid_sender))
                    else:
                        tgt = p[1].replace("***", "106")
                        if len(p) == 3 and p[2].strip():
                            nome = p[2].strip()
                            if len(nome) > 18:
                                clients.send(self.GenResponsMsg("[C][B][FF0000]Nome muito longo! Máximo 18 caracteres.", uid_sender))
                                continue
                        else:
                            defaults = ["CRASHO KKKK!", "BIEL  DOMINA", "BIEL DO CAPS", "BUGOU O SISTEMA", "BUGOU!!!!"]
                            nome = random.choice(defaults)
                        convite = generate_random_color() + nome
                        socket_client.send(self.createpacketinfo(tgt))
                        time.sleep(0.3)
                        if self.tempdata and ("IN ROOM" in self.tempdata or "Failed to get status" in self.tempdata):
                            sala = get_idroom_by_idplayer(self.data22) if hasattr(self, 'data22') else None
                            if sala:
                                spam = self.spam_room(sala, tgt, convite)
                                for _ in range(20):
                                    threading.Thread(target=self.try_send, args=(socket_client, spam)).start()
                                clients.send(self.GenResponsMsg("[C][B][00FF00]STATUS: success (spam sent!)", uid_sender))
                            else:
                                clients.send(self.GenResponsMsg("[C][B][00FF00]STATUS: success (Failed to get room ID, but spam sent!)", uid_sender))
                        else:
                            clients.send(self.GenResponsMsg("[C][B][FF00FF]O jogador não está na sala", uid_sender))
                elif cmd.startswith("/autospam "):
                    p = cmd_raw.split(maxsplit=2)
                    if len(p) < 2 or not p[1].isdigit():
                        clients.send(self.GenResponsMsg("[C][B][FF0000]Uso correto: /autospam <uid> [nome]", uid_sender))
                    else:
                        tgt = p[1].replace("***", "106")
                        nome = p[2].strip() if len(p) == 3 and p[2].strip() else random.choice(["CRASHO KKKK!", "BIEL  DOMINA", "BIEL DO CAPS", "BUGOU O SISTEMA", "BUGOU!!!!"])
                        if len(nome) > 18:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Nome muito longo! Máx 18 caracteres.", uid_sender))
                        elif tgt in self.autospam_active:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Este alvo já está recebendo autospam", uid_sender))
                        else:
                            self.autospam_active[tgt] = time.time()
                            with open("autospam_state.json", "w") as f:
                                json.dump(self.autospam_active, f)
                            threading.Thread(target=self.auto_spam, args=(tgt, uid_sender, nome), daemon=True).start()
                            
                elif cmd.startswith("/check "):
                    p = cmd_raw.split()
                    if len(p) != 2 or not p[1].isdigit():
                        clients.send(self.GenResponsMsg("[C][B][FFDD00]Use /check <id>!", uid_sender))
                    else:
                        alvo = p[1]
                        try:
                            r = requests.get(f"https://system.ffgarena.cloud/api/isbanned?id={alvo}", verify=False)
                            r.raise_for_status()
                            j = r.json()
                            if j.get("status") == "error":
                                clients.send(self.GenResponsMsg("[C][B][FF00FF]Este player não existe!", uid_sender))
                            else:
                                d = j.get("details", {})
                                nick = d.get("PlayerNickname", "")
                                reg = d.get("PlayerRegion", "")
                                ban = "Sim" if d.get("is_banned") == "yes" else "Não"
                                msg = f"[C][B][0000FF]NickName: {nick}\nRegião: {reg}\nEstá banido: {ban}"
                                clients.send(self.GenResponsMsg(msg, uid_sender))
                        except Exception:
                            clients.send(self.GenResponsMsg("[C][B][FF00FF]Erro na API!", uid_sender))
                elif cmd == "/cmd":
                    welcome_msg = (
                        "[C][B][00FFFF]--------------------------------\n\n"
                        f"[C][B][FFFFFF]Seja bem-vindo - {nick_sender}\n\n"
                        "[C][B][00FFFF]--------------------------------"
                    )
                    clients.send(self.GenResponsMsg(welcome_msg, uid_sender))
                    time.sleep(0.3)
                    menu = (
                        "[C][B][8A2BE2]Dev: @bielzGG\n\n\n"
                        "[C][B][E0FFFF]Comandos disponíveis:\n\n"
                        "[C][B][00FFFF]• /spamroom {id do player} [FFFF00]- Spamma vários convites para entrar em uma sala personalizada. (A sala precisa de senha).\n\n"
                        "[C][B][00FFFF]• /5 {id} [FFFF00]- Cria uma equipe com capacidade de 5 pessoas.\n\n"
                        "[C][B][00FFFF]• /likes {id} [FFFF00]- Envia likes para um player pelo ID dele (Máx: 100)\n\n"
                        "[C][B][00FFFF]• /info {id} [FFFF00]- Procura informações sobre um player.\n\n"
                        "[C][B][00FFFF]• /check {id} [FFFF00]- Checa se um player está banido.\n\n"
                        "[C][B][00FFFF]• /autospam {id do player} [FFFF00]- Envia spam automático por 50 segundos."
                    )
                    clients.send(self.GenResponsMsg(menu, uid_sender))
            except (ConnectionResetError, socket.error):
                try:
                    clients.close()
                except:
                    pass
                time.sleep(2)
                clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                clients.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                clients.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                clients.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                clients.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 6)
                clients.connect((self._host, self._port))
                clients.send(bytes.fromhex(self._tok))

    def parse_my_message(self, serialized_data):
        MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
        MajorLogRes.ParseFromString(serialized_data)
        
        timestamp = MajorLogRes.kts
        key = MajorLogRes.ak
        iv = MajorLogRes.aiv
        BASE64_TOKEN = MajorLogRes.token
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(timestamp)
        timestamp_seconds = timestamp_obj.seconds
        timestamp_nanos = timestamp_obj.nanos
        combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
        return combined_timestamp, key, iv, BASE64_TOKEN

    def GET_PAYLOAD_BY_DATA(self,JWT_TOKEN , NEW_ACCESS_TOKEN,date):
        token_payload_base64 = JWT_TOKEN.split('.')[1]
        token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
        decoded_payload = base64.urlsafe_b64decode(token_payload_base64).decode('utf-8')
        decoded_payload = json.loads(decoded_payload)
        NEW_EXTERNAL_ID = decoded_payload['external_id']
        SIGNATURE_MD5 = decoded_payload['signature_md5']
        now = datetime.now()
        now =str(now)[:len(str(now))-7]
        formatted_time = date
        payload = bytes.fromhex("1a13323032352d30352d32342031383a35333a3232220966726565206669726528013a07312e3131312e344241416e64726f6964204f53203130202f204150492d32392028514434412e3230303830352e3030332f656e672e776f726b2e32303233313231382e313633393333294a0848616e6468656c645a045749464960800a68d00572033332307a1d41524d3634204650204153494d4420414553207c2032323038207c2038800198738a01094d616c692d4736313092013e4f70656e474c20455320332e322076312e67313270302d3031656163302e64383031363465326635623337636333363637313033383331633637613863309a012b476f6f676c657c32663961326335622d643763322d343039642d396139642d333939343234373233383131a2010c34332e3233302e31322e3835aa0102656eb201206633376539306439303739623761363738363533616433303364636130386232ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d4e39373030ea014032623030613136396239373332653136336133303632643636303931383465316664323132323538353532663733643066363362323839326438336239643663f00101d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003c4a30de80398830af003c4a30df80398830a80048ada0a8804c4a30d90048ada0a9804c4a30dc80401d2043f2f646174612f6170702f636f6d2e6474732e667265656669726574682d6f47514152627a38592d416a30306d367753473157673d3d2f6c69622f61726d3634e00401ea045f32303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d6f47514152627a38592d416a30306d367753473157673d3d2f626173652e61706bf00403f804028a050236349a050a32303139313138333939b205094f70656e474c455332b805ff7fc00504e005e08707ea0507616e64726f6964f2055c4b7173485435706f6c6963524631345456647257536f642f395035424a5a2b6e73796b4b6f5965476c334c48317a516f756e314168595778484a6c435345657858384661767a51684f34382f484e464969326a484d615a4e5141453d8806019006019a060134a2060134b206091757434e5658080161")
        payload = payload.replace(b"2025-05-24 18:53:22", str(now).encode())
        payload = payload.replace(b"2b00a169b9732e163a3062d6609184e1fd212258552f73d0f63b2892d83b9d6c", NEW_ACCESS_TOKEN.encode("UTF-8"))
        payload = payload.replace(b"f37e90d9079b7a678653ad303dca08b2", NEW_EXTERNAL_ID.encode("UTF-8"))
        payload = payload.replace(b"7428b253defc164018c604a1ebbfebdf", SIGNATURE_MD5.encode("UTF-8"))
        PAYLOAD = payload.hex()
        PAYLOAD = encrypt_api(PAYLOAD)
        PAYLOAD = bytes.fromhex(PAYLOAD)
        ip,port = self.GET_LOGIN_DATA(JWT_TOKEN , PAYLOAD)
        return ip,port
    
    def dec_to_hex(ask):
        ask_result = hex(ask)
        final_result = str(ask_result)[2:]
        if len(final_result) == 1:
            final_result = "0" + final_result
            return final_result
        else:
            return final_result
    def convert_to_hex(PAYLOAD):
        hex_payload = ''.join([f'{byte:02x}' for byte in PAYLOAD])
        return hex_payload
    def convert_to_bytes(PAYLOAD):
        payload = bytes.fromhex(PAYLOAD)
        return payload
    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD):
        url = "https://client.us.freefiremobile.com/GetLoginData"
        headers = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {JWT_TOKEN}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB49',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host': 'clientbp.common.ggbluefox.com',
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate, br',
        }
        
        max_retries = 3
        attempt = 0

        while attempt < max_retries:
            try:
                response = requests.post(url, headers=headers, data=PAYLOAD,verify=False)
                response.raise_for_status()
                x = response.content.hex()
                json_result = get_available_room(x)
                parsed_data = json.loads(json_result)
                print(parsed_data)
                address = parsed_data['32']['data']
                ip = address[:len(address) - 6]
                port = address[len(address) - 5:]
                return ip, port
            
            except requests.RequestException as e:
                print(f"Request failed: {e}. Attempt {attempt + 1} of {max_retries}. Retrying...")
                attempt += 1
                time.sleep(2)

        print("Failed to get login data after multiple attempts.")
        return None, None

    def guest_token(self,uid , password):
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {"Host": "100067.connect.garena.com","User-Agent": f'{get_random_user_agent()}',"Content-Type": "application/x-www-form-urlencoded","Accept-Encoding": "gzip, deflate, br","Connection": "close",}
        data = {"uid": f"{uid}","password": f"{password}","response_type": "token","client_type": "2","client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3","client_id": "100067",}
        response = requests.post(url, headers=headers, data=data)
        data = response.json()
        NEW_ACCESS_TOKEN = data['access_token']
        NEW_OPEN_ID = data['open_id']
        OLD_ACCESS_TOKEN = "2b00a169b9732e163a3062d6609184e1fd212258552f73d0f63b2892d83b9d6c"
        OLD_OPEN_ID = "f37e90d9079b7a678653ad303dca08b2"
        time.sleep(0.2)
        data = self.TOKEN_MAKER(OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,uid)
        return(data)
        
    def TOKEN_MAKER(self,OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,id):
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB49',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Content-Length': '928',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.common.ggbluefox.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        data = bytes.fromhex('1a13323032352d30352d32342031383a35333a3232220966726565206669726528013a07312e3131312e344241416e64726f6964204f53203130202f204150492d32392028514434412e3230303830352e3030332f656e672e776f726b2e32303233313231382e313633393333294a0848616e6468656c645a045749464960800a68d00572033332307a1d41524d3634204650204153494d4420414553207c2032323038207c2038800198738a01094d616c692d4736313092013e4f70656e474c20455320332e322076312e67313270302d3031656163302e64383031363465326635623337636333363637313033383331633637613863309a012b476f6f676c657c32663961326335622d643763322d343039642d396139642d333939343234373233383131a2010c34332e3233302e31322e3835aa0102656eb201206633376539306439303739623761363738363533616433303364636130386232ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d4e39373030ea014032623030613136396239373332653136336133303632643636303931383465316664323132323538353532663733643066363362323839326438336239643663f00101d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003c4a30de80398830af003c4a30df80398830a80048ada0a8804c4a30d90048ada0a9804c4a30dc80401d2043f2f646174612f6170702f636f6d2e6474732e667265656669726574682d6f47514152627a38592d416a30306d367753473157673d3d2f6c69622f61726d3634e00401ea045f32303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d6f47514152627a38592d416a30306d367753473157673d3d2f626173652e61706bf00403f804028a050236349a050a32303139313138333939b205094f70656e474c455332b805ff7fc00504e005e08707ea0507616e64726f6964f2055c4b7173485435706f6c6963524631345456647257536f642f395035424a5a2b6e73796b4b6f5965476c334c48317a516f756e314168595778484a6c435345657858384661767a51684f34382f484e464969326a484d615a4e5141453d8806019006019a060134a2060134b206091757434e5658080161')
        data = data.replace(OLD_OPEN_ID.encode(),NEW_OPEN_ID.encode())
        data = data.replace(OLD_ACCESS_TOKEN.encode() , NEW_ACCESS_TOKEN.encode())
        hex = data.hex()
        d = encrypt_api(data.hex())
        Final_Payload = bytes.fromhex(d)
        URL = "https://loginbp.ggblueshark.com/MajorLogin"

        RESPONSE = requests.post(URL, headers=headers, data=Final_Payload,verify=False)
        
        combined_timestamp, key, iv, BASE64_TOKEN = self.parse_my_message(RESPONSE.content)
        if RESPONSE.status_code == 200:
            if len(RESPONSE.text) < 10:
                return False
            ip,port =self.GET_PAYLOAD_BY_DATA(BASE64_TOKEN,NEW_ACCESS_TOKEN,1)
            self.key = key
            self.iv = iv
            print(key, iv)
            return(BASE64_TOKEN,key,iv,combined_timestamp,ip,port)
        else:
            return False

    
    def time_to_seconds(hours, minutes, seconds):
        return (hours * 3600) + (minutes * 60) + seconds

    def seconds_to_hex(seconds):
        return format(seconds, '04x')
    
    def extract_time_from_timestamp(timestamp):
        dt = datetime.fromtimestamp(timestamp)
        h = dt.hour
        m = dt.minute
        s = dt.second
        return h, m, s
    
    def get_token(self):
        global g_token
        token, key, iv, Timestamp, ip, port = self.guest_token(self.id, self.password)
        g_token = token
        print(ip, port)
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            account_id = decoded.get('account_id')
            encoded_acc = hex(account_id)[2:]
            hex_value = dec_to_hex(Timestamp)
            time_hex = hex_value
            BASE64_TOKEN_ = token.encode().hex()
            print(f"Token decoded and processed. Account ID: {account_id}")
        except Exception as e:
            print(f"Error processing token: {e}")
            return

        try:
            head = hex(len(encrypt_packet(BASE64_TOKEN_, key, iv)) // 2)[2:]
            length = len(encoded_acc)
            zeros = '00000000'

            if length == 9:
                zeros = '0000000'
            elif length == 8:
                zeros = '00000000'
            elif length == 10:
                zeros = '000000'
            elif length == 7:
                zeros = '000000000'
            else:
                print('Unexpected length encountered')
            head = f'0115{zeros}{encoded_acc}{time_hex}00000{head}'
            final_token = head + encrypt_packet(BASE64_TOKEN_, key, iv)
            print("Final token constructed successfully.")
        except Exception as e:
            print(f"Error constructing final token: {e}")
        token = final_token
        self.connect(token, ip, port, 'anything', key, iv)
        
      
        return token, key, iv
        
    def run(self):
        def schedule_restart():
            while True:
                time.sleep(3 * 3600)
                restart_program()
        threading.Thread(target=schedule_restart, daemon=True).start()
        self.get_token()
with open('accs.txt', 'r') as file:
    data = json.load(file)
ids_passwords = list(data.items())
def run_client(id, password):
    client = FF_CLIENT(id, password)
    client.start()
    
max_range = 300000
num_clients = len(ids_passwords)
num_threads = 1
start = 0
end = max_range
step = (end - start) // num_threads
threads = []
for i in range(num_threads):
    ids_for_thread = ids_passwords[i % num_clients]
    id, password = ids_for_thread
    thread = threading.Thread(target=run_client, args=(id, password))
    threads.append(thread)
    time.sleep(0.1)
    thread.start()

for thread in threads:
    thread.join()

