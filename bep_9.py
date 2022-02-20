import bencode
import sys

# print(bencode.bdecode("d8:msg_typei0e5:piecei0ee"))
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

IP = "192.168.1.28" # socket.gethostbyname('router.bittorrent.com')
PORT = 6881 # 6881
BUFFER = 4096
CLIENT_SOCKET       = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# CLIENT_SOCKET.bind((IP, PORT))
CLIENT_SOCKET.connect((IP,PORT))
CLIENT_SOCKET.settimeout(3)


print("\n",'-' * 21,"HANDSHAKE",'-' * 21,"\n")

# http://www.bittorrent.org/beps/bep_0010.html
PROTOCOL_IDENTIFIER = b'BitTorrent protocol'
msg = struct.pack('B', len(PROTOCOL_IDENTIFIER)) # struct.pack('B', 19) = b'\x13' = 19 length of 'string identifier of the protocol' below
msg += PROTOCOL_IDENTIFIER # string identifier of the protocol
msg += b'\x00\x00\x00\x00\x00\x10\x00\x01' # https://www.bittorrent.org/beps/bep_0004.html
msg += bytearray.fromhex("f1fcdc1462d36530f526c1d9402eec9100b7ba18") # info_hash
msg += b"-J4" + b"0001" + b"-" + hashlib.sha1(str(os.environ).encode()).hexdigest()[9:20].encode() # peer_id Azureus-style

print(">>>", msg)
CLIENT_SOCKET.send(msg)

try:
    server_response = CLIENT_SOCKET.recv(BUFFER)
    print("<<<",server_response)
except socket.timeout:
    print((IP, PORT),'timeout !')


print("\n",'-' * 21,"EXTENDED HANDSHAKE",'-' * 21,"\n")


# http://www.bittorrent.org/beps/bep_0009.html
BITTORRENT_MESSAGE_ID = 20
extended_message_id = 1
msg = chr(BITTORRENT_MESSAGE_ID).encode() # struct.pack("B",20)
msg += chr(extended_message_id).encode() # struct.pack("B",0)
msg += bencode.bencode({"m":{"ut_metadata":1}}).encode()

LENGTH_PREFIX = struct.pack(">I",len(msg)) # len(msg).to_bytes(4, 'big') # struct.pack(">I",len(msg))
msg = LENGTH_PREFIX+msg
print(">>>", msg)
CLIENT_SOCKET.send(msg)

try:
    server_response = CLIENT_SOCKET.recv(BUFFER)
    print("<<<",server_response)
except socket.timeout:
    print((IP, PORT),'timeout !')


print("\n",'-' * 21,"REQUEST PIECE",'-' * 21,"\n")


# get metadata_size
regex =  re.compile(r"metadata_sizei(\d+)e")
matches = regex.search(server_response.decode("ascii", "ignore"))
metadata_size = matches.group(1)
# print("metadata_size", metadata_size)
# print("metadata_size", int(metadata_size) / (16*1024) )
ut_metadata_pieces = math.ceil(int(metadata_size) / (16*1024)) # The metadata is handled in blocks of 16KiB = 16384 Bytes = 16*1024
print("metadata_size rounds:", ut_metadata_pieces)

extended_message_id = 20
for metadata_piece in range(ut_metadata_pieces + 1):
    # msg = struct.pack("B", BITTORRENT_MESSAGE_ID) # struct.pack("B",20)
    msg = struct.pack("B", extended_message_id) # struct.pack("B",0)
    msg += bencode.bencode({'msg_type': 0, 'piece': metadata_piece}).encode()

    LENGTH_PREFIX = struct.pack(">I",len(msg)) # len(msg).to_bytes(4, 'big') # struct.pack(">I",len(msg))
    print("len",len(msg))
    msg = LENGTH_PREFIX+msg
    print(">>>", msg)
    CLIENT_SOCKET.send(msg)
    try:
        metadata = CLIENT_SOCKET.recv(BUFFER)
        print("<<< M", metadata)
    except socket.timeout:
        print((IP, PORT),'msg_type 0: timeout !')
        break

CLIENT_SOCKET.close()
