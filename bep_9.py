import os
import socket
import base64
import bencode
import hashlib
from struct import pack,unpack

IP = "127.0.0.1" # socket.gethostbyname('router.bittorrent.com')
PORT = 61470 # 6881
BUFFER = 512
CLIENT_SOCKET       = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# CLIENT_SOCKET.bind((IP, PORT))
CLIENT_SOCKET.connect((IP,PORT))
CLIENT_SOCKET.settimeout(3)





msg = b'\x13' # = unpack('B', msg)[0] = 19
msg += b'BitTorrent protocol'
msg += b'\x00\x00\x00\x00\x10\x00\x00\x00' # "\x00\x00\x00\x00\x00\x10\x00\x00"
msg += bytearray.fromhex("F1FCDC1462D36530F526C1D9402EEC9100B7BA18")
msg += hashlib.sha1(str(os.environ).encode()).hexdigest()[:20].encode()

print(">", msg)
CLIENT_SOCKET.send(msg)

try:
    server_response = CLIENT_SOCKET.recv(BUFFER)
    print("<<<",server_response)
except socket.timeout:
    print((IP, PORT),'timeout !')


print("")


BT_MSG_ID = 20
EXT_HANDSHAKE = 0
msg = chr(BT_MSG_ID).encode() + chr(EXT_HANDSHAKE).encode() + bencode.bencode({"m":{"ut_metadata":1}}).encode()
msgLen = pack(">I",len(msg))
msg = msgLen+msg
print(">", msg)
CLIENT_SOCKET.send(msg)

try:
    server_response = CLIENT_SOCKET.recv(BUFFER)
    print("<<<",server_response)
except socket.timeout:
    print((IP, PORT),'timeout !')


# print("")


# msg = chr(BT_MSG_ID).encode() + chr(EXT_HANDSHAKE).encode() + bencode.bencode(bencode.bencode({'msg_type': 0, 'piece': 0})).encode() 
# msgLen = pack(">I",len(msg))
# msg = msgLen+msg
# print(">", msg)
# CLIENT_SOCKET.send(msg)

# try:
#     server_response = CLIENT_SOCKET.recv(BUFFER)
#     print("<<<",server_response)
# except socket.timeout:
#     print((IP, PORT),'timeout !')

CLIENT_SOCKET.close()
# clear;cd /home/groot/Documents/bt-dht-scraper/;watch python3 bep_9.py
