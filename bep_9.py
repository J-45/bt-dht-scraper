import bencode
import sys

# print(bencode.bdecode("d1:md11:ut_metadatai9e6:ut_pexi8ee13:metadata_sizei234481e1:pi3666e1:v12:aria2/1.35.0e"))
# print(bencode.bdecode("d1:ei0e1:md11:ut_metadatai2e6:ut_pexi0ee13:metadata_sizei234481e1:pi51005e4:reqqi2048e1:v17:libTorrent 0.13.8e"))
# sys.exit(0)

import os
import re
import sys
import math
import socket
import base64
import bencode
import hashlib
import struct

IP = "127.0.0.1" # socket.gethostbyname('router.bittorrent.com')
PORT = 6881 # 6881
BUFFER = 512
CLIENT_SOCKET       = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# CLIENT_SOCKET.bind((IP, PORT))
CLIENT_SOCKET.connect((IP,PORT))
CLIENT_SOCKET.settimeout(7)




# http://www.bittorrent.org/beps/bep_0010.html
PROTOCOL_IDENTIFIER = b'BitTorrent protocol'
msg = struct.pack('B', len(PROTOCOL_IDENTIFIER)) # struct.pack('B', 19) = b'\x13' = 19 length of 'string identifier of the protocol' below
msg += PROTOCOL_IDENTIFIER # string identifier of the protocol
msg += b'\x00\x00\x00\x00\x00\x10\x00\x05' # eight (8) reserved bytes
msg += bytearray.fromhex("F1FCDC1462D36530F526C1D9402EEC9100B7BA18") # info_hash
msg += b"-J4" + b"0001" + b"-" + hashlib.sha1(str(os.environ).encode()).hexdigest()[9:20].encode() # peer_id Azureus-style

print(">>>", msg)
CLIENT_SOCKET.send(msg)

try:
    server_response = CLIENT_SOCKET.recv(BUFFER)
    print("<<<",server_response)
except socket.timeout:
    print((IP, PORT),'timeout !')


print("")


# http://www.bittorrent.org/beps/bep_0009.html
BITTORRENT_MESSAGE_ID = 20
EXTENDED_MESSAGE_ID = 0
msg = chr(BITTORRENT_MESSAGE_ID).encode() # struct.pack("B",20)
msg += chr(EXTENDED_MESSAGE_ID).encode() # struct.pack("B",0)
msg += bencode.bencode({"m":{"ut_metadata":1}}).encode()

LENGTH_PREFIX = struct.pack(">I",len(msg)) # len(msg).to_bytes(4, 'big') # struct.pack(">I",len(msg))
msg = LENGTH_PREFIX+msg
print(">>>", msg)
CLIENT_SOCKET.send(msg)

try:
    server_response = CLIENT_SOCKET.recv(BUFFER)
    print("<<<",server_response)

    # get metadata_size
    regex =  re.compile(r"metadata_sizei(\d+)e")
    matches = regex.search(server_response.decode("utf-8", "ignore"))
    metadata_size = matches.group(1)
    print("metadata_size", metadata_size)
    print("metadata_size", int(metadata_size) / (16*1024) )
    print("metadata_size rounds", math.ceil(int(metadata_size) / (16*1024)) )

    

except socket.timeout:
    print((IP, PORT),'timeout !')


# print("")


# msg = chr(BT_MSG_ID).encode() + chr(EXT_HANDSHAKE).encode() + bencode.bencode(bencode.bencode({'msg_type': 0, 'piece': 0})).encode() 
# msgLen = struct.pack(">I",len(msg))
# msg = msgLen+msg
# print(">>>", msg)
# CLIENT_SOCKET.send(msg)

# try:
#     server_response = CLIENT_SOCKET.recv(BUFFER)
#     print("<<<",server_response)
# except socket.timeout:
#     print((IP, PORT),'timeout !')

CLIENT_SOCKET.close()
