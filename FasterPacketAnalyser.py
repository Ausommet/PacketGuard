from scapy.all import rdpcap
from tqdm import tqdm
import dpkt
import os
from scapy.all import IP, TCP, UDP
from collections import defaultdict

#I HATE THIS WARNING WITH A PASSION OMG IT'S SO ANNOYING





# Function to get the service name based on the port number
def get_service_name(port):
    service_mapping = {
        20: "ftp-data",
        21: "ftp",
        22: "ssh",
        25: "smtp",
        53: "dns",
        80: "http",
        194: "irc",
    }
    # Return the service name if mapped, otherwise return "-"
    return service_mapping.get(port, "-")



def get_ttl(packet):
    if IP in packet:
        ip_layer = packet.getlayer(IP)
        return ip_layer.ttl, ip_layer.dttl if hasattr(
            ip_layer, 'dttl') else "0"
    elif TCP in packet:
        tcp_layer = packet.getlayer(TCP)
        return tcp_layer.ttl, "0"  # TCP does not have TTL values
    elif UDP in packet:
        udp_layer = packet.getlayer(UDP)
        return udp_layer.ttl, "0"  # UDP does not have TTL values
    else:
        return "0", "0"


def calculate_rate(prev_packet, curr_packet):
    if IP in prev_packet and IP in curr_packet:
        time_diff = curr_packet.time - prev_packet.time
        bytes_sent = curr_packet[IP].len - prev_packet[IP].len

        if time_diff != 0:
            rate = max(
                (bytes_sent * 8) / time_diff,
                0)  # Ensure rate is non-negative
            return rate
        else:
            return 0  # or any other appropriate value indicating zero rate
    else:
        return "0"


# Initialize keys
keys = [
    #"id",
    "dur",
    "proto",
    "service",
    "state",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sttl",
    "dttl",
    "sload",
    "dload",
    "sloss",
    "dloss",
    "sinpkt",
    "dinpkt",
    "sjit",
    "djit",
    "swin",
    "stcpb",
    "dtcpb",
    "dwin",
    "tcprtt",
    "synack",
    "ackdat",
    "smean",
    "dmean",
    "trans_depth",
    "response_body_len",
    "ct_srv_src",
    "ct_state_ttl",
    "ct_dst_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "is_ftp_login",
    "ct_ftp_cmd",
    "ct_flw_http_mthd",
    "ct_src_ltm",
    "ct_srv_dst",
    "is_sm_ips_ports"
    #"attack_cat",
    #"label"
    ]

# Initialised variables
running_avg_sinpkt = 0
running_avg_dinpkt = 0
syn_time = 0
synack_time = 0
ackdat_time = 0
synack_delay = 0
ackdat_delay = 0
total_spacket_size = 0
total_dpacket_size = 0
spacket_count = 0
dpacket_count = 0
trans_depth = 0
service_src_counts = defaultdict(int)
state_ttl_counts = defaultdict(lambda: defaultdict(int))
# Dictionary to store destination IP addresses and their connection timestamps
dest_conn_timestamps = defaultdict(lambda: deque(maxlen=100))
# Dictionary to store source address and destination port tuples and their
# connection timestamps
src_dst_conn_timestamps = defaultdict(lambda: deque(maxlen=100))
# Dictionary to store destination address and source port tuples and their
# connection timestamps
dst_src_conn_timestamps = defaultdict(lambda: deque(maxlen=100))
# Dictionary to store destination address and source address tuples and
# their connection timestamps
dst_sport_conn_timestamps = defaultdict(lambda: deque(maxlen=100))
src_conn_timestamps = defaultdict(lambda: deque(maxlen=100))
srv_dst_connections = defaultdict(lambda: deque(maxlen=100))


def packet_generator(filename):
    with open(filename, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            yield (timestamp, eth)

# Read the pcap file
packets = packet_generator('pcap/1.pcap')

# List to store extracted information
packet_data = []

# Variables to keep track of the current and next packet
timestamp, packet = next(packets, (None, None))
next_timestamp, next_packet = next(packets, (None, None))

# Variable to keep track of the previous timestamp
prev_timestamp = None

# Get the size of the pcap file in bytes
file_size = os.path.getsize('pcap/1.pcap')

# Estimate the average size of a packet in bytes
# This is a rough estimate and may not be accurate for all pcap files
avg_packet_size = 525  # You may need to adjust this value based on your pcap files

# Estimate the total number of packets
total_packets = file_size // avg_packet_size

# Create a progress bar
pbar = tqdm(total=total_packets)

# Iteration over each packet and extract the information
i = 1
packet_info = {}

while packet is not None:
    pbar.update(1)  # update the progress bar
    packet_info["id"] = i + 1  # Packet ID starts from 1, as stated above drop id for now
    # Some extra variables that need to be fresh for every iteration since its
    # only a 1 or 0 value i.e True or False
    http_flows = set()  # To store unique HTTP flows
    ct_flw_http_mthd = 0  # Counter for flows with HTTP methods
    ftp_sessions = set()  # To store unique FTP sessions
    ct_ftp_cmd = 0  # Counter for flows with FTP commands

    # duration
    if next_packet:
        packet_info["dur"] = round(next_timestamp - timestamp, 6)
    else:
        packet_info["dur"] = "0"
    
    # protocol
    if IP in packet:
        packet_info["proto"] = packet[IP].get_field(
            'proto').i2repr(packet[IP], packet[IP].proto)
    else:
        packet_info["proto"] = "-"

    # service
    if TCP in packet:
        service = packet[TCP].dport
        packet_info["service"] = get_service_name(service)
    else:
        packet_info["service"] = "-"

    # state
    tcp_flags = packet[TCP].flags if TCP in packet else ""
    if "F" in tcp_flags:
        packet_info["state"] = "FIN"
    elif "S" in tcp_flags:
        packet_info["state"] = "SYN"
    elif "R" in tcp_flags:
        packet_info["state"] = "RST"
    elif "P" in tcp_flags:
        packet_info["state"] = "PSH"
    elif "A" in tcp_flags:
        packet_info["state"] = "ACK"
    elif "C" in tcp_flags:
        packet_info["state"] = "CON"
    elif "I" in tcp_flags:
        packet_info["state"] = "INT"
    elif "Q" in tcp_flags:
        packet_info["state"] = "REQ"
    else:
        packet_info["state"] = "-"

    # packet counts
    if IP in packet:
        packet_info["spkts"] = packet[IP].len
    else:
        packet_info["spkts"] = "-"

    if next_packet and IP in next_packet:
        packet_info["dpkts"] = next_packet[IP].len
    else:
        packet_info["dpkts"] = "-"

    # bytes
    if IP in packet:
        packet_info["sbytes"] = packet[IP].len
    else:
        packet_info["sbytes"] = "-"

    if next_packet and IP in next_packet:
        packet_info["dbytes"] = next_packet[IP].len
    else:
        packet_info["dbytes"] = "-"

    # rate
    packet_info["rate"] = calculate_rate(packet, next_packet)

    # sttl & dttl
    packet_info["sttl"], packet_info["dttl"] = get_ttl(packet)

    # sload & dload
    if packet_info["dur"] != 0 and packet_info["sbytes"] != "-" and packet_info["dbytes"] != "-":
        packet_info["sload"] = round(
            (packet_info["sbytes"] * 8) / (packet_info["dur"] * 1000), 6)  # Duration in seconds
        packet_info["dload"] = round(
            max((packet_info["dbytes"] * 8) / (packet_info["dur"] * 1000), 0), 6)
    else:
        packet_info["sload"] = "0"
        packet_info["dload"] = "0"

    # sloss & dloss
    if packet_info["spkts"] != "-" and packet_info["dpkts"] != "-":
        packet_info["sloss"] = max(
            packet_info["spkts"] - packet_info["dpkts"], 0)
        packet_info["dloss"] = max(
            packet_info["dpkts"] - packet_info["spkts"], 0)
    else:
        packet_info["sloss"] = "0"
        packet_info["dloss"] = "0"

    # Sinpkt & Dinpkt | sjit & djit
    if prev_timestamp is not None:
        # Convert to milliseconds
        sinpkt = (timestamp - prev_timestamp) * 1000
        packet_info["sinpkt"] = round(sinpkt, 6)
        running_avg_sinpkt = ((i - 1) * running_avg_sinpkt + sinpkt) / i
        packet_info["sjit"] = round(abs(sinpkt - running_avg_sinpkt), 6)
    else:
        packet_info["sinpkt"] = "0"
        packet_info["sjit"] = "0"

    if next_packet:
        dinpkt = (next_timestamp - timestamp) * 1000  # Convert to milliseconds
        packet_info["dinpkt"] = round(dinpkt, 6)
        running_avg_dinpkt = (i * running_avg_dinpkt + dinpkt) / (i + 1)
        packet_info["djit"] = round(abs(dinpkt - running_avg_dinpkt), 6)
    else:
        packet_info["dinpkt"] = "0"
        packet_info["djit"] = "0"

    # swin & dwin
    if TCP in packet:
        packet_info["swin"] = packet[TCP].window
    else:
        packet_info["swin"] = "-"

    if next_packet and TCP in next_packet:
        packet_info["dwin"] = next_packet[TCP].window
    else:
        packet_info["dwin"] = "-"

    # stcpb & dtcpb
    if TCP in packet:
        packet_info["stcpb"] = packet[TCP].seq
    else:
        packet_info["stcpb"] = "-"

    if next_packet and TCP in next_packet:
        packet_info["dtcpb"] = next_packet[TCP].seq
    else:
        packet_info["dtcpb"] = "-"

    # calculate tcprtt, synack and ackdat
    if TCP in packet:
        if "S" in packet[TCP].flags:
            syn_time = packet.time
        elif "A" in packet[TCP].flags and next_packet and TCP in next_packet:
            if "S" in next_packet[TCP].flags:
                synack_time = packet.time
                synack_delay = synack_time - syn_time
            elif "A" in next_packet[TCP].flags:
                ackdat_time = packet.time
                ackdat_delay = ackdat_time - syn_time
                tcprtt = synack_delay + ackdat_delay

                packet_info["tcprtt"] = round(tcprtt, 6)
                packet_info["synack"] = round(synack_delay, 6)
                packet_info["ackdat"] = round(ackdat_delay, 6)
            # Handle the case where SYN or ACK flags are not set
        else:
            packet_info["tcprtt"] = "0"
            packet_info["synack"] = "0"
            packet_info["ackdat"] = "0"
        # Handle cases where packet is not TCP
    else:
        packet_info["tcprtt"] = "0"
        packet_info["synack"] = "0"
        packet_info["ackdat"] = "0"

    # Replace '-' with '0' where applicable
    for key in ["tcprtt", "synack", "ackdat"]:
        if key not in packet_info:
            packet_info[key] = "0"

    # Smean & Dmean
    if IP in packet:
        total_spacket_size += packet[IP].len
        spacket_count += 1
    if next_packet and IP in next_packet:
        total_dpacket_size += next_packet[IP].len
        dpacket_count += 1
    smeansz = total_spacket_size / spacket_count if spacket_count > 0 else 0
    dmeansz = total_dpacket_size / dpacket_count if dpacket_count > 0 else 0
    packet_info["smean"] = round(smeansz)
    packet_info["dmean"] = round(dmeansz)

    # trans_depth | response_body_len
    response_body_len = 0
    # Increment trans_depth if the packet is an HTTP request
    if TCP in packet and packet[TCP].dport == 80 and 'A' in packet[TCP].flags:
        trans_depth += 1

    # Decrement trans_depth if the packet is an HTTP response
    if TCP in packet and packet[TCP].sport == 80 and 'A' in packet[TCP].flags:
        trans_depth -= 1
        if Raw in packet:
            response_body_len += len(packet[Raw])

    trans_depth = max(trans_depth, 0)
    packet_info["trans_depth"] = trans_depth
    packet_info["response_body_len"] = response_body_len

    # Calculate ct_srv_src
    if TCP in packet:
        service = packet[TCP].dport
        src_address = packet[IP].src
        service_src_counts[(service, src_address)] += 1

        packet_info["ct_srv_src"] = service_src_counts[(service, src_address)]
    else:
        packet_info["ct_srv_src"] = "0"

    # calculate ct_state_ttl
    sttl, dttl = get_ttl(packet)
    state = packet_info["state"]
    if int(sttl) <= 64:
        sttl_range = "0-64"
    elif int(sttl) <= 128:
        sttl_range = "65-128"
    else:
        sttl_range = "129-255"

    if int(dttl) <= 64:
        dttl_range = "0-64"
    elif int(dttl) <= 128:
        dttl_range = "65-128"
    else:
        dttl_range = "129-255"

    state_ttl_counts[(sttl_range, dttl_range)][state] += 1

    # Update packet_info with ct_state_ttl count
    packet_info["ct_state_ttl"] = state_ttl_counts[(
        sttl_range, dttl_range)][state]

    # calculate ct_dst_ltm
    if IP in packet:
        dst_ip = packet[IP].dst

        # Update destination connection timestamps
        dest_conn_timestamps[dst_ip].append(packet.time)

        # Calculate ct_dst_ltm
        packet_info["ct_dst_ltm"] = len(dest_conn_timestamps[dst_ip])
    else:
        packet_info["ct_dst_ltm"] = "0"

    # calculate ct_src_dport_ltm
    if IP in packet and TCP in packet:
        src_address = packet[IP].src
        dst_port = packet[TCP].dport
        src_dst_tuple = (src_address, dst_port)

        # Update source address and destination port connection timestamps
        src_dst_conn_timestamps[src_dst_tuple].append(packet.time)
        # Calculate ct_src_dport_ltm
        packet_info["ct_src_dport_ltm"] = len(
            src_dst_conn_timestamps[src_dst_tuple])
    else:
        packet_info["ct_src_dport_ltm"] = "0"

    # calculate ct_dst_sport_ltm
    if IP in packet and TCP in packet:
        dst_address = packet[IP].dst
        src_port = packet[TCP].sport
        dst_src_tuple = (dst_address, src_port)

        # Update destination address and source port connection timestamps
        dst_sport_conn_timestamps[dst_src_tuple].append(packet.time)

        # Calculate ct_dst_sport_ltm
        packet_info["ct_dst_sport_ltm"] = len(
            dst_sport_conn_timestamps[dst_src_tuple])
    else:
        packet_info["ct_dst_sport_ltm"] = "0"

    # calculate ct_dst_src_ltm

    if IP in packet:
        src_address = packet[IP].src
        dst_address = packet[IP].dst
        dst_src_tuple = (src_address, dst_address)

        # Update destination address and source address connection timestamps
        dst_src_conn_timestamps[dst_src_tuple].append(packet.time)

        # Calculate ct_dst_src_ltm
        packet_info["ct_dst_src_ltm"] = len(
            dst_src_conn_timestamps[dst_src_tuple])
    else:
        packet_info["ct_dst_src_ltm"] = "0"

    # check if is_ftp_login

    if TCP in packet and packet[TCP].dport == 21 and Raw in packet:
        # Extract raw data
        raw_data = packet[Raw].load.decode("utf-8", "ignore")
        # Check for typical FTP login commands
        if "USER" in raw_data and "PASS" in raw_data:
            packet_info["is_ftp_login"] = "1"  # Login detected
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            # Add the tuple to the set of FTP sessions
            ftp_sessions.add((src_ip, dst_ip))
        else:
            packet_info["is_ftp_login"] = "0"  # Login not detected
    else:
        packet_info["is_ftp_login"] = "0"  # Not an FTP packet

    # Calculate ct_ftp_cmd as the size of the set containing FTP sessions
    ct_ftp_cmd = len(ftp_sessions)

    # Add ct_ftp_cmd to packet_info
    packet_info["ct_ftp_cmd"] = ct_ftp_cmd

    # calculate ct_flow_http_mthd
    if TCP in packet and packet[TCP].dport == 80 and Raw in packet:
        raw_data = packet[Raw].load.decode("utf-8", "ignore")
        if "GET" in raw_data or "POST" in raw_data:  # Check for HTTP methods
            # Extract source and destination IP addresses
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            # Add the tuple to the set of HTTP flows
            http_flows.add((src_ip, dst_ip))

    # Calculate ct_flw_http_mthd as the size of the set containing HTTP flows
    ct_flw_http_mthd = len(http_flows)

    # Add ct_flw_http_mthd to packet_info
    packet_info["ct_flw_http_mthd"] = ct_flw_http_mthd

    # caluclate ct_src_ltm
    if IP in packet:
        src_ip = packet[IP].src

        # Update source connection timestamps
        src_conn_timestamps[src_ip].append(packet.time)

        # Calculate ct_src_ltm as the length of the deque containing connection
        # timestamps
        ct_src_ltm = len(src_conn_timestamps[src_ip])

        # Add ct_src_ltm to packet_info
        packet_info["ct_src_ltm"] = ct_src_ltm
    else:
        packet_info["ct_src_ltm"] = "0"

    # calculate ct_srv_dst
    if TCP in packet:
        service = packet[TCP].dport
        dst_address = packet[IP].dst
        srv_dst_tuple = (service, dst_address)

        # Update service and destination address connection timestamps
        srv_dst_connections[srv_dst_tuple].append(packet.time)

        # Calculate ct_srv_dst
        packet_info["ct_srv_dst"] = len(srv_dst_connections[srv_dst_tuple])
    else:
        packet_info["ct_srv_dst"] = "0"

    # Calculate is_sm_ips_ports
    if IP in packet:
        if (packet[IP].src == next_packet.src and
            packet[IP].dst == next_packet.dst and
            packet[TCP].sport == next_packet.sport and
                packet[TCP].dport == next_packet.dport):
            packet_info['is_sm_ips_ports'] = 1
        else:
            packet_info['is_sm_ips_ports'] = 0
    else:
        packet_info['is_sm_ips_ports'] = 0

    # other features To be implemented later
    # Keep Normal since we are not classifying the packets yet
    packet_info["attack_cat"] = "Normal"
    # Keep 0 since we are not classifying the packets yet
    packet_info["label"] = "0"

    packet_data.append(packet_info)
    
    #Next Packet
    prev_timestamp = timestamp
    timestamp, packet = next_timestamp, next_packet
    if next_packet is not None:  # Only get the next packet if the current one is not None
        next_timestamp, next_packet = next(packets, (None, None))
    i += 1

pbar.close()  # close the progress bar when done

# Write the extracted information to a CSV file
with open('packet_data.csv', 'w') as f:
    # Write the header
    f.write(",".join(keys) + "\n")

    # Write the data
    for packet_info in packet_data:
        row = ",".join(str(packet_info[key]) for key in keys)
        f.write(row + "\n")
