import socket
import sys
import time
import os
import glob

LOCAL_HOST = '127.0.0.1'

def create_socket(host, port):
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Note: friend used a tuple (host, port) correctly
        soc.connect((host, port))
    except:
        print("Connection Error to", port)
        sys.exit()
    return soc

def read_csv(path):
    table_file = open(path, "r")
    table = table_file.readlines()
    table_list = []
    for line in table:
        elements = [el.strip() for el in line.split(",")]
        table_list.append(elements)
    table_file.close()
    return table_list

def find_default_gateway(table):
    for row in table:
        if row[0] == '0.0.0.0':
            return row[3]

def generate_forwarding_table_with_range(table):
    new_table = []
    for row in table:
        if row[0] != '0.0.0.0':
            # Converting to binary once and storing as INT
            network_dst_int = ip_to_bin(row[0])
            netmask_int = ip_to_bin(row[1])
            ip_range = find_ip_range(network_dst_int, netmask_int)
            
            # Row structure: [min_ip, max_ip, port]
            new_table.append([ip_range[0], ip_range[1], row[3]])
    return new_table

def ip_to_bin(ip):
    ip_octets = ip.split('.')
    ip_bin_string = ""
    for octet in ip_octets:
        bin_octet_string = bin(int(octet))[2:].zfill(8)
        ip_bin_string += bin_octet_string
    return int(ip_bin_string, 2)

def find_ip_range(network_dst_int, netmask_int):
    bitwise_and = network_dst_int & netmask_int
    compliment = (1 << 32) - 1 - netmask_int
    return [bitwise_and, bitwise_and + compliment]

def write_to_file(path, packet_to_write, send_to_router=None):
    # Ensure directory exists
    if not os.path.exists('./output'):
        os.makedirs('./output')
    out_file = open(path, "a")
    if send_to_router is None:
        out_file.write(packet_to_write + "\n")
    else:
        out_file.write(packet_to_write + " to Router " + send_to_router + "\n")
    out_file.close()

# --- Main Program ---

files = glob.glob('./output/*')
for f in files:
    os.remove(f)

soc2 = create_socket(LOCAL_HOST, 8002)
soc4 = create_socket(LOCAL_HOST, 8004)

forwarding_table = read_csv('./input/router_1_table.csv')
default_gateway_port = find_default_gateway(forwarding_table)
forwarding_table_with_range = generate_forwarding_table_with_range(forwarding_table)

packets_table = read_csv('./input/packets.csv')

for packet in packets_table:
    sourceIP, destinationIP, payload, ttl = packet[0], packet[1], packet[2], packet[3]
    new_ttl = int(ttl) - 1
    new_packet = f"{sourceIP},{destinationIP},{payload},{new_ttl}"

    
    destinationIP_int = ip_to_bin(destinationIP)

    # Search for match
    sending_port = None
    for row in forwarding_table_with_range:
        if row[0] <= destinationIP_int <= row[1]:
            sending_port = row[2]
            break

    if sending_port is None:
        sending_port = default_gateway_port

    # Packet Forwarding Logic
    if sending_port == '127.0.0.1':
        print("OUT:", payload)
        write_to_file("./output/out_router_1.txt", payload)
    elif new_ttl <= 0:
        print("DISCARD", new_packet)
        write_to_file("./output/discarded_by_router_1.txt", new_packet)
    elif sending_port == '8002':
        print("sending packet to Router 2")
        soc2.send(new_packet.encode())
        write_to_file("./output/sent_by_router_1.txt", new_packet, "2")
    elif sending_port == '8004':
        print("sending packet to Router 4")
        soc4.send(new_packet.encode())
        write_to_file("./output/sent_by_router_1.txt", new_packet, "4")
    else:
        print("DISCARD (No Route):", new_packet)
        write_to_file("./output/discarded_by_router_1.txt", new_packet)

    time.sleep(1)