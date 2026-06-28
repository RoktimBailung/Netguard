from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
import mysql.connector
import time

# 1. DATABASE CONNECTION SETUP

print("Connecting to MySQL Database...")
try:
    db_connection = mysql.connector.connect(
        host="localhost",
        user="root",
        password="Your_Password", 
        database="netguard_db"
    )
    cursor = db_connection.cursor()
    print("Database Connected Successfully!\n")
except Exception as e:
    print(f"Database Connection Failed: {e}")
    print("Please check if your MySQL server is running and the password is correct.")
    exit()


# 2. PROTOCOL TRANSLATOR
PROTOCOL_MAP = {
    80: ("HTTP", " Visiting an Unsecure Website"),
    443: ("HTTPS", " Secure Web Traffic (Streaming/Browsing)"),
    53: ("DNS", " Searching for a Website Address"),
    21: ("FTP", " File Transfer"),
    22: ("SSH", " Secure Remote Access"),
    25: ("SMTP", " Sending an Email"),
    143: ("IMAP", " Receiving an Email"),
    3306: ("MySQL", " Database Communication")
}

def get_service_info(src_port, dst_port):
    if src_port in PROTOCOL_MAP:
        return PROTOCOL_MAP[src_port]
    elif dst_port in PROTOCOL_MAP:
        return PROTOCOL_MAP[dst_port]
    else:
        return ("Other", "Background App/System Traffic")



# 3. THE CORE PACKET PROCESSOR

def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        size_kb = round(len(packet) / 1024, 2)

        protocol_name = "Unknown"
        action_desc = "Background Traffic"
        extra_info = ""
        
        # Default ports to 0 in case the packet isn't TCP/UDP
        src_port = 0
        dst_port = 0

        # A. Analyze the Traffic Type & Extract Ports
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            try:
                queried_domain = packet[DNSQR].qname.decode('utf-8').strip('.')
                protocol_name = "DNS"
                action_desc = " User is searching for a website"
                extra_info = f"-> [Target Website: {queried_domain}]"
                if packet.haslayer(UDP):
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
            except:
                pass
        elif packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol_name, action_desc = get_service_info(src_port, dst_port)
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol_name, action_desc = get_service_info(src_port, dst_port)

        # B. Save to MySQL Database 
        try:
            sql_query = "INSERT INTO traffic_logs (src_ip, dst_ip, src_port, dst_port, protocol, packet_size, description) VALUES (%s, %s, %s, %s, %s, %s, %s)"
            values = (src_ip, dst_ip, src_port, dst_port, protocol_name, size_kb, action_desc)
            cursor.execute(sql_query, values)
            db_connection.commit()
            db_status = "[Saved to DB]"
        except Exception as e:
            db_status = f"[DB Error: {e}]"

  
        print(f"{action_desc} {db_status}")
        print(f"   [Protocol: {protocol_name}] | Size: {size_kb} KB")
        print(f"   [Path]: {src_ip}:{src_port}  --->  {dst_ip}:{dst_port}")
        if extra_info:
            print(f"   {extra_info}")
        print("-" * 65)


# 4. START THE ENGINE

print(" NetGuard Master Engine Active (Sniffing + DB Logging)")
print(" Waiting to intercept network activity...")

# Start intercepting packets
sniff(filter="ip", prn=process_packet, store=False)