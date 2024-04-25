from scapy.all import IP, TCP, UDP, rdpcap, Raw, ICMP, Ether, ARP, deque
from collections import defaultdict
import socket
from tqdm import tqdm
import os

# Initialize data structures and variables
running_avg_sinpkt = 0
running_avg_dinpkt = 0
total_spacket_size = 0
total_dpacket_size = 0
spacket_count = 0
dpacket_count = 0
trans_depth = 0
service_src_counts = defaultdict(int)
state_ttl_counts = defaultdict(lambda: defaultdict(int))
dest_conn_timestamps = defaultdict(lambda: deque(maxlen=100))
src_dst_conn_timestamps = defaultdict(lambda: deque(maxlen=100))
dst_src_conn_timestamps = defaultdict(lambda: deque(maxlen=100))
dst_sport_conn_timestamps = defaultdict(lambda: deque(maxlen=100))
src_conn_timestamps = defaultdict(lambda: deque(maxlen=100))
srv_dst_connections = defaultdict(lambda: deque(maxlen=100))


def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except OSError:
        return "-"


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
    

def extract_duration(packet_info, packet, next_packet):
    if next_packet:
        packet_info["dur"] = round(next_packet.time - packet.time, 6)
    else:
        packet_info["dur"] = "0"

def extract_protocol(packet_info, packet):
    if IP in packet:
        packet_info["proto"] = packet[IP].get_field('proto').i2repr(packet[IP], packet[IP].proto)
    else:
        packet_info["proto"] = "-"

def extract_service(packet_info, packet):
    if TCP in packet:
        service = packet[TCP].dport
        packet_info["service"] = get_service_name(service)
    else:
        packet_info["service"] = "-"

def extract_state(packet_info, packet):
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
    else:
        packet_info["state"] = "-"

def extract_packet_counts(packet_info, packet, next_packet):
    if IP in packet:
        packet_info["spkts"] = packet[IP].len
        packet_info["swin"] = packet[TCP].window if TCP in packet else "-"
    else:
        packet_info["spkts"] = "-"
        packet_info["swin"] = "-"

    if next_packet and IP in next_packet:
        packet_info["dpkts"] = next_packet[IP].len
        packet_info["dwin"] = next_packet[TCP].window if TCP in next_packet else "-"
    else:
        packet_info["dpkts"] = "-"
        packet_info["dwin"] = "-"

def extract_bytes(packet_info, packet, next_packet):
    if IP in packet:
        packet_info["sbytes"] = packet[IP].len
    else:
        packet_info["sbytes"] = "-"
    
    if next_packet and IP in next_packet:
        packet_info["dbytes"] = next_packet[IP].len
        packet_info["dwin"] = next_packet[TCP].window if TCP in next_packet else "-"
    else:
        packet_info["dbytes"] = "-"
        packet_info["dwin"] = "-"


def extract_rate(packet_info, packet, next_packet):
    packet_info["rate"] = calculate_rate(packet, next_packet)

def extract_ttl(packet_info, packet):
    packet_info["sttl"], packet_info["dttl"] = get_ttl(packet)

def extract_load(packet_info):
    if packet_info["dur"] != 0 and packet_info["sbytes"] != "-" and packet_info["dbytes"] != "-":
        packet_info["sload"] = round((packet_info["sbytes"] * 8) / (packet_info["dur"] * 1000), 6)  # Duration in seconds
        packet_info["dload"] = round(max((packet_info["dbytes"] * 8) / (packet_info["dur"] * 1000), 0), 6)
    else:
        packet_info["sload"] = "0"
        packet_info["dload"] = "0"

def extract_packet_loss(packet_info):
    if packet_info["spkts"] != "-" and packet_info["dpkts"] != "-":
        packet_info["sloss"] = max(packet_info["spkts"] - packet_info["dpkts"], 0)
        packet_info["dloss"] = max(packet_info["dpkts"] - packet_info["spkts"], 0)
    else:
        packet_info["sloss"] = "0"
        packet_info["dloss"] = "0"

def extract_packet_size_means(packet_info, packet, next_packet):
    global total_spacket_size, total_dpacket_size, spacket_count, dpacket_count

    if IP in packet:
        total_spacket_size += packet[IP].len
        spacket_count += 1
    if next_packet and IP in next_packet:
        total_dpacket_size += next_packet[IP].len
        dpacket_count += 1
    smeansz = total_spacket_size / spacket_count if spacket_count > 0 else 0
    dmeansz = total_dpacket_size / dpacket_count if dpacket_count > 0 else 0
    packet_info["smeansz"] = round(smeansz)
    packet_info["dmeansz"] = round(dmeansz)


def extract_trans_depth_and_response_body_len(packet_info, packet):
    response_body_len = 0
    trans_depth = 0
    if TCP in packet and packet[TCP].dport == 80 and 'A' in packet[TCP].flags:
        trans_depth += 1

    if TCP in packet and packet[TCP].sport == 80 and 'A' in packet[TCP].flags:
        trans_depth -= 1
        if Raw in packet:
            response_body_len += len(packet[Raw])

    trans_depth = max(trans_depth, 0)
    packet_info["trans_depth"] = trans_depth
    packet_info["response_body_len"] = response_body_len

def calculate_tcprtt_synack_ackdat(packet_info, packet, next_packet):
    syn_time = 0  # Initialize syn_time with default value
    synack_time = 0  # Initialize synack_time with default value
    ackdat_time = 0  # Initialize ackdat_time with default value
    synack_delay = 0  # Initialize synack_delay with default value
    ackdat_delay = 0  # Initialize ackdat_delay with default value
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




def calculate_ct_srv_src(packet_info, packet):
    if TCP in packet:
        service = packet[TCP].dport
        src_address = packet[IP].src
        service_src_counts[(service, src_address)] += 1

        packet_info["ct_srv_src"] = service_src_counts[(service, src_address)]
    else:
        packet_info["ct_srv_src"] = "0"

def calculate_ct_state_ttl(packet_info, packet):
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

    packet_info["ct_state_ttl"] = state_ttl_counts[(sttl_range, dttl_range)][state]

def calculate_ct_dst_ltm(packet_info, packet):
    if IP in packet:
        dst_ip = packet[IP].dst

        dest_conn_timestamps[dst_ip].append(packet.time)

        packet_info["ct_dst_ltm"] = len(dest_conn_timestamps[dst_ip])
    else:
        packet_info["ct_dst_ltm"] = "0"

def calculate_ct_src_dport_ltm(packet_info, packet):
    if TCP in packet:
        src_addr = packet[IP].src
        dst_port = packet[TCP].dport

        src_dst_conn_timestamps[(src_addr, dst_port)].append(packet.time)

        packet_info["ct_src_dport_ltm"] = len(src_dst_conn_timestamps[(src_addr, dst_port)])
    else:
        packet_info["ct_src_dport_ltm"] = "0"

def calculate_ct_dst_sport_ltm(packet_info, packet):
    if TCP in packet:
        dst_addr = packet[IP].dst
        src_port = packet[TCP].sport

        dst_src_conn_timestamps[(dst_addr, src_port)].append(packet.time)

        packet_info["ct_dst_sport_ltm"] = len(dst_src_conn_timestamps[(dst_addr, src_port)])
    else:
        packet_info["ct_dst_sport_ltm"] = "0"

def calculate_ct_dst_src_ltm(packet_info, packet):
    if IP in packet:
        src_addr = packet[IP].src
        dst_addr = packet[IP].dst

        dst_sport_conn_timestamps[(dst_addr, src_addr)].append(packet.time)

        packet_info["ct_dst_src_ltm"] = len(dst_sport_conn_timestamps[(dst_addr, src_addr)])
    else:
        packet_info["ct_dst_src_ltm"] = "0"

def calculate_is_ftp_login(packet_info, packet):
    ftp_sessions = set()  # Define ftp_sessions as an empty set
    if TCP in packet:
        if packet[TCP].sport == 21 and 'A' in packet[TCP].flags:
            ftp_sessions.add(packet[IP].src)
            packet_info["is_ftp_login"] = len(ftp_sessions)
        else:
            packet_info["is_ftp_login"] = "0"
    else:
        packet_info["is_ftp_login"] = "0"

def calculate_ct_ftp_cmd(packet_info, packet):
    ct_ftp_cmd = 0  # Initialize ct_ftp_cmd with default value
    
    if TCP in packet:
        if packet[TCP].dport == 21 and 'A' in packet[TCP].flags:
            ct_ftp_cmd += 1
            packet_info["ct_ftp_cmd"] = ct_ftp_cmd
        else:
            packet_info["ct_ftp_cmd"] = "0"
    else:
        packet_info["ct_ftp_cmd"] = "0"


def calculate_ct_flw_http_mthd(packet_info, packet):
    http_flows = set()  # Define http_flows as an empty set
    if TCP in packet:
        if packet[TCP].dport == 80:
            http_flows.add(packet[IP].src + packet[IP].dst)
            ct_flw_http_mthd = len(http_flows)
            packet_info["ct_flw_http_mthd"] = ct_flw_http_mthd
        else:
            packet_info["ct_flw_http_mthd"] = "0"
    else:
        packet_info["ct_flw_http_mthd"] = "0"

def calculate_ct_src_ltm(packet_info, packet):
    if IP in packet:
        src_ip = packet[IP].src

        src_conn_timestamps[src_ip].append(packet.time)

        packet_info["ct_src_ltm"] = len(src_conn_timestamps[src_ip])
    else:
        packet_info["ct_src_ltm"] = "0"

def calculate_ct_srv_dst(packet_info, packet):
    if IP in packet and TCP in packet:
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport

        srv_dst_connections[(dst_port, dst_ip)].append(packet.time)

        packet_info["ct_srv_dst"] = len(srv_dst_connections[(dst_port, dst_ip)])
    else:
        packet_info["ct_srv_dst"] = "0"


def calculate_is_sm_ips_ports(packet_info, packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if src_ip == dst_ip:
            packet_info["is_sm_ips_ports"] = "1"
        else:
            packet_info["is_sm_ips_ports"] = "0"
    else:
        packet_info["is_sm_ips_ports"] = "0"


def extract_tcp_sequence_numbers(packet_info, packet):
    if TCP in packet:
        packet_info["stcpb"] = packet[TCP].seq
        packet_info["dtcpb"] = packet[TCP].ack
    else:
        packet_info["stcpb"] = "-"
        packet_info["dtcpb"] = "-"

def calculate_interarrival_time(packet_info, packet, prev_packet):
    if prev_packet:
        interarrival_time = packet.time - prev_packet.time
        return interarrival_time
    else:
        return 0

def extract_interarrival_times(packet_data):
    sinpkt_values = []
    dinpkt_values = []

    for i, packet_info in enumerate(packet_data):
        sinpkt = calculate_interarrival_time(packet_info, packet_data[i], packet_data[i-1])
        dinpkt = calculate_interarrival_time(packet_info, packet_data[i], packet_data[i+1] if i+1 < len(packet_data) else None)
        sinpkt_values.append(sinpkt)
        dinpkt_values.append(dinpkt)

    return sinpkt_values, dinpkt_values

def calculate_sinpkt_dinpkt(packet_info,i, packet, packets):
    running_avg_sinpkt = 0
    running_avg_dinpkt = 0
    if i > 0:
        # Convert to milliseconds
        sinpkt = (packet.time - packets[i - 1].time) * 1000
        packet_info["sinpkt"] = round(sinpkt, 6)
        running_avg_sinpkt = ((i - 1) * running_avg_sinpkt + sinpkt) / i
        packet_info["sjit"] = round(abs(sinpkt - running_avg_sinpkt), 6)
    else:
        packet_info["sinpkt"] = "0"
        packet_info["sjit"] = "0"

    if i + 1 < len(packets):
        dinpkt = (packets[i + 1].time - packet.time) * 1000  # Convert to milliseconds
        packet_info["dinpkt"] = round(dinpkt, 6)
        running_avg_dinpkt = (i * running_avg_dinpkt + dinpkt) / (i + 1)
        packet_info["djit"] = round(abs(dinpkt - running_avg_dinpkt), 6)
    else:
        packet_info["dinpkt"] = "0"
        packet_info["djit"] = "0"

def generate_packet_data(filename, save_file):
    # Initialize keys
    keys = [
        #"id", Drop Id to increase performance, maybe add later when user wants to save data.
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
        "dwin",
        "stcpb",
        "dtcpb",
        "tcprtt",
        "synack",
        "ackdat",
        "smeansz",
        "dmeansz",
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
        #"attack_cat", Removed to increase performance, will be added when classifying packets anyways.
        #"label", Removed to increase performance, will be added when classifying packets anyways.
        ]
    print("Reading packets from file... (Larger files may take longer)")
    packets = rdpcap(filename)
    
    packet_data = []

    # Iterate over each packet and extract information
    for i in tqdm(range(len(packets) - 1), desc="Generating Packet Data..."):
        packet = packets[i]
        next_packet = packets[i + 1] if i + 1 < len(packets) else None
        packet_info = {}

        # Extract packet information
        extract_duration(packet_info, packet, next_packet)
        extract_protocol(packet_info, packet)
        extract_service(packet_info, packet)
        extract_state(packet_info, packet)
        extract_packet_counts(packet_info, packet, next_packet)
        extract_bytes(packet_info, packet, next_packet)
        extract_rate(packet_info, packet, next_packet)
        extract_ttl(packet_info, packet)
        extract_load(packet_info)
        extract_packet_loss(packet_info)
        extract_packet_size_means(packet_info, packet, next_packet)
        extract_trans_depth_and_response_body_len(packet_info, packet)
        extract_tcp_sequence_numbers(packet_info, packet)

        # Calculate derived metrics
        calculate_sinpkt_dinpkt(packet_info, i, packet, packets)
        calculate_tcprtt_synack_ackdat(packet_info, packet, next_packet)
        calculate_ct_srv_src(packet_info, packet)
        calculate_ct_state_ttl(packet_info, packet)
        calculate_ct_dst_ltm(packet_info, packet)
        calculate_ct_src_dport_ltm(packet_info, packet)
        calculate_ct_dst_sport_ltm(packet_info, packet)
        calculate_ct_dst_src_ltm(packet_info, packet)
        calculate_is_ftp_login(packet_info, packet)
        calculate_ct_ftp_cmd(packet_info, packet)
        calculate_ct_flw_http_mthd(packet_info, packet)
        calculate_ct_src_ltm(packet_info, packet)
        calculate_ct_srv_dst(packet_info, packet)
        calculate_is_sm_ips_ports(packet_info, packet)


        # Append packet info to packet_data list
        packet_data.append(packet_info)

    # Write the extracted information to a CSV file if save_file is '1'
    if save_file == 'y':
        directory = 'Results/Generated Data/'
        if not os.path.exists(directory):
            os.makedirs(directory)
        
        with open(directory + 'generated_data.csv', 'w') as f:
            # Write the header
            f.write(",".join(keys) + "\n")
            for packet_info in packet_data:
                row = ",".join(str(packet_info[key]) for key in keys)
                f.write(row + "\n")


    
    return packet_data
        
