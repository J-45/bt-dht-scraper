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
BUFFER = 1024
CLIENT_SOCKET       = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# CLIENT_SOCKET.bind((IP, PORT))
CLIENT_SOCKET.connect((IP,PORT))
CLIENT_SOCKET.settimeout(7)


print("\n",'-' * 21,"HANDSHAKE",'-' * 21,"\n") # ---------------------

# http://www.bittorrent.org/beps/bep_0010.html
PROTOCOL_IDENTIFIER = b'BitTorrent protocol'
msg = struct.pack('B', len(PROTOCOL_IDENTIFIER)) # struct.pack('B', 19) = b'\x13' = 19 length of 'string identifier of the protocol' below
msg += PROTOCOL_IDENTIFIER # string identifier of the protocol
msg += b'\x00\x00\x00\x00\x00\x18\x00\x05' # https://www.bittorrent.org/beps/bep_0004.html
msg += bytearray.fromhex("f1fcdc1462d36530f526c1d9402eec9100b7ba18") # info_hash
msg += b"-J4" + b"0001" + b"-" + hashlib.sha1(str(os.environ).encode()).hexdigest()[8:20].encode() # peer_id Azureus-style

print(">>>", msg)
CLIENT_SOCKET.sendall(msg)

try:
    server_response = CLIENT_SOCKET.recv(BUFFER)
    print("<<<",server_response)
except socket.timeout:
    print((IP, PORT),'timeout !')


print("\n",'-' * 21,"EXTENDED HANDSHAKE",'-' * 21,"\n") # ---------------------

# http://www.bittorrent.org/beps/bep_0009.html
BITTORRENT_MESSAGE_ID = 20
extended_message_id = 0
msg = chr(BITTORRENT_MESSAGE_ID).encode() # struct.pack("B",20)
msg += chr(extended_message_id).encode() # struct.pack("B",0)
msg += bencode.bencode({"m":{"ut_metadata":1}}).encode()

LENGTH_PREFIX = struct.pack(">I",len(msg)) # len(msg).to_bytes(4, 'big') # struct.pack(">I",len(msg))
msg = LENGTH_PREFIX+msg
print(">>>", len(msg), msg)
CLIENT_SOCKET.sendall(msg)

try:
    server_response = CLIENT_SOCKET.recv(BUFFER)
    print("<<<",server_response)
except socket.timeout:
    print((IP, PORT),'timeout !')

# ---------------------

# get metadata_size
regex =  re.compile(r"metadata_sizei(\d+)e")
matches = regex.search(server_response.decode("ascii", "ignore"))
metadata_size = matches.group(1)
print("\n")
print("metadata_size", metadata_size)
# print("metadata_size", int(metadata_size) / (16*1024) )
if int(metadata_size) / (16*1024) < 1:
    end = 0
else:
    end = 1
ut_metadata_pieces = math.ceil(int(metadata_size) / (16*1024)) # The metadata is handled in blocks of 16KiB = 16384 Bytes = 16*1024
print("metadata_size loops:", ut_metadata_pieces + end)

print("\n",'-' * 21,"REQUEST PIECE",'-' * 21,"\n") # ---------------------

extended_message_id = 20
metadata = b""

for metadata_piece in range(ut_metadata_pieces + end):
    msg = b''
    # msg += chr(BITTORRENT_MESSAGE_ID).encode() # struct.pack("B",20)
    msg += chr(extended_message_id).encode() # struct.pack("B",0)
    msg += chr(3).encode()
    msg += bencode.bencode({'msg_type': 0, 'piece': metadata_piece}).encode()

    LENGTH_PREFIX = struct.pack(">I",len(msg)) # len(msg).to_bytes(4, 'big') # struct.pack(">I",len(msg))
    msg = LENGTH_PREFIX+msg
    print("SENT:", len(msg), msg)

    CLIENT_SOCKET.sendall(msg)
    new_metadata_size = 0
    while True:
        print(".", end="", flush=True)
        try:
            new_metadata = CLIENT_SOCKET.recv(BUFFER)
            if new_metadata:
                if 0 == len(metadata):
                    start = new_metadata.decode(encoding='utf-8', errors="ignore").find("ee")
                    # print("GOT PART:", start, new_metadata[0:200])
                    new_metadata = new_metadata[start+2:]
                    # print("GOT PART:", new_metadata[0:200])
                # print("GOT PART:", len(new_metadata), new_metadata)
                # sys.exit(42)
                metadata += new_metadata
                new_metadata_size += len(new_metadata)
        except socket.timeout as e:
            print('TO')
            break
        except BaseException as e:
            print((IP, PORT), e)
            break
        except:
            print("Unexpected error:", sys.exc_info()[0])
    print("GOT:", new_metadata_size, flush=True)
metadata = metadata[0:metadata_size-1]
print("metadata:", len(metadata), flush=True)
CLIENT_SOCKET.close()

# b'\x00\x00@0\x14\x01d8:msg_typei1e5:piecei0e10:total_sizei237879eed6:lengthi3116482560e4:name30:ubuntu-21.10-desktop-amd64.iso12:piece lengthi262144e6:pieces237780:
