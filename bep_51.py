#!/usr/bin/python3

import os
import time
import struct
import socket
import hashlib
import bencode # sudo pip3 install bencode-python3

print(str(os.environ).encode('utf-8'))

CHARSET_ENCODING    = 'ISO-8859-1'

def make_KRPC_Query(query, ip=socket.gethostbyname('router.bittorrent.com'), port=6881):
    if ip == 0:
        print('Invalid port !')
        return []
    SOCKET_BUFFER_SIZE  = 1024
    NODE_IP_PORT        = (ip, port)
    BENCODEDQUERY       = bencode.bencode(query)
    client_socket       = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    client_socket.settimeout(0.25)
    client_socket.sendto(bytes(BENCODEDQUERY, CHARSET_ENCODING), NODE_IP_PORT)

    try:
        server_response = client_socket.recvfrom(SOCKET_BUFFER_SIZE)[0]
    except socket.timeout:
        print(NODE_IP_PORT,'timeout !')
        return []
    server_response     = server_response.decode(CHARSET_ENCODING)

    try:
        BDECODEDMSG     = bencode.bdecode(server_response)
        return BDECODEDMSG
    except Exception as e:
        print("Invalid server answer\n\n")
        # print(server_response)
        return []    

MY_NODE_ID          = hashlib.sha1(str(os.environ).encode('utf-8')).hexdigest()[:20] # fingerprint
TRANSACTION_ID      = MY_NODE_ID[:2]

# QUERY:ping
pingQuery           = {"t":TRANSACTION_ID, "y":"q", "q":"ping", "a":{"id": MY_NODE_ID}}
bdecodedPingMsg     = make_KRPC_Query(pingQuery)
target_node_id      = bdecodedPingMsg['r']['id']

# QUERY:find_nodes
findNodeQuery       = {"t":TRANSACTION_ID, "y":"q", "q":"find_node", "a": {"id": MY_NODE_ID, "target": target_node_id}}
bdecodedFindNodeMsg = make_KRPC_Query(findNodeQuery)

nodes               = bdecodedFindNodeMsg['r']['nodes']
nodes_pool          = list(map(''.join, zip(*[iter(nodes)]*26)))
tested              = 0
hashes_seen         = 0
delay               = 60*60

while True:
    for node in nodes_pool:
        node_id     = node[0:20]
        nodes_ip    = bytes(node[20:24], CHARSET_ENCODING)
        nodes_port  = bytes(node[24:26], CHARSET_ENCODING)
        ip          = socket.inet_ntop(socket.AF_INET, nodes_ip)
        port        = struct.unpack(">H",nodes_port)[0]

        print(f"Tested {tested}/{len(nodes_pool)} nodes - {hashes_seen} info hashes\n")
        print(
        '[ID]', node_id.encode('utf-8').hex(), # raw value are hardly printable
        '[IP]', ip,
        '[PORT]', port
        )

        # If you want to make a server and listen to: get_peers & announce_peer
        #
        # public_ip   = "xx.xx.xx.xx"
        # public_port = 6881
        # packed_public_ip = socket.inet_pton(socket.AF_INET, public_ip)
        # findHashesQuery       = {
        #     "m":{"p":public_port,"yourip":packed_public_ip},
        #     "t":"aa", "y":"q", "q":"sample_infohashes",
        #     "a": {"id":MY_NODE_ID, "target":node_id}
        # }

        # QUERY:sample_infohashes
        findHashesQuery         = {
                                "t":TRANSACTION_ID, "y":"q",
                                "q":"sample_infohashes", 
                                "a": {"id":MY_NODE_ID, "target":node_id}
                                }
        bdecodedFindHashesMsg   = make_KRPC_Query(findHashesQuery, ip, port)
        tested                  += 1

        if bdecodedFindHashesMsg != []:
            if 'r' in bdecodedFindHashesMsg:
                if 'samples' in bdecodedFindHashesMsg['r']:
                    info_hashes     = bdecodedFindHashesMsg['r']['samples']
                    interval        = bdecodedFindHashesMsg['r']['interval']
                    remaining_hashes= bdecodedFindHashesMsg['r']['num']

                    print(f'{round(len(info_hashes)/20)}/{round((len(info_hashes)/20))+remaining_hashes} info_hashes ({len(info_hashes)} bytes) interval {interval} seconds')

                    for v in range(0, len(info_hashes), 20):
                        hashe       = info_hashes[v:v+20]
                        hex_hashe   = hashe.encode('latin1').hex()
                        print(f"magnet:?xt=urn:btih:{hex_hashe}")
                        hashes_seen   += 1

                else:
                    print('No info_hashes found, fetching nodes...')

                    # QUERY:find_nodes
                    findNodeQuery_backup    = {
                        "t":TRANSACTION_ID, "y":"q",
                        "q":"find_node", 
                        "a": {"id":MY_NODE_ID, "target":target_node_id}
                        }
                    BDECODEDMSG_backup      = make_KRPC_Query(findNodeQuery_backup, ip, port)

                    if BDECODEDMSG_backup != [] and 'r' in BDECODEDMSG_backup:
                        if 'nodes' in BDECODEDMSG_backup['r']:
                            new_nodes           = BDECODEDMSG_backup['r']['nodes']
                            new_nodes_list      = list(map(''.join, zip(*[iter(new_nodes)]*26)))
                            added               = 0

                            for new_nodE in new_nodes_list:
                                if new_nodE not in nodes_pool:
                                    nodes_pool  += [new_nodE]
                                    added       += 1
                                    # sys.exit(0)
                            print(f'{added} nodes added!')
    
    print(f'Waiting {delay} seconds...')
    time.sleep(delay) # wait before send requests to the same IPs
