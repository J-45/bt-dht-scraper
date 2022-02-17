import os
import socket
import base64
import bencode
import hashlib
from struct import pack,unpack

ip = "127.0.0.1" # socket.gethostbyname('router.bittorrent.com')
port = 61470 # 6881
client_socket       = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
# client_socket.bind((ip, port))
client_socket.settimeout(1)






BT_PROTOCOL = "Bittorrent protocol"
info_hash = bytearray.fromhex("1675404082c58d61ee41d3bd1c66b6f0b9326bf1")
# print(info_hash)
bt_header = str(len(BT_PROTOCOL)) + BT_PROTOCOL
bt_ext_byte = "\x00\x00\x00\x00\x00\x10\x00\x00"
peerId = hashlib.sha1(str(os.environ).encode('utf-8')).hexdigest()[:20]
msg = bt_header.encode() + bt_ext_byte.encode() + info_hash + peerId.encode()

print(">",msg)
client_socket.sendto(msg, (ip, port))

try:
    server_response = client_socket.recv(1024)
    print("<",server_response.decode('ascii', 'backslashreplace'))
except socket.timeout:
    print((ip, port),'timeout !')





BT_MSG_ID = 20
EXT_HANDSHAKE = 0
msg = chr(BT_MSG_ID).encode() + chr(EXT_HANDSHAKE).encode() + bencode.bencode({'msg_type': 0, 'piece': 0}).encode() 
msgLen = pack(">I",len(msg))
msg = msgLen+msg
print(">",msg)
client_socket.sendto(msg, (ip, port))

try:
    server_response = client_socket.recv(1024)
    print("<",server_response.decode('ascii', 'backslashreplace'))
except socket.timeout:
    print((ip, port),'timeout !')





msg = chr(BT_MSG_ID).encode() + chr(EXT_HANDSHAKE).encode() + bencode.bencode(bencode.bencode({'msg_type': 0, 'piece': 0})).encode() 
msgLen = pack(">I",len(msg))
msg = msgLen+msg
print(">",msg)
client_socket.sendto(msg, (ip, port))

try:
    server_response = client_socket.recv(1024)
    print("<",server_response.decode('ascii', 'backslashreplace'))
except socket.timeout:
    print((ip, port),'timeout !')

# clear;cd /home/groot/Documents/bt-dht-scraper/;watch python3 handshake.py
