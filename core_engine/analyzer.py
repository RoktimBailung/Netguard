import mysql.connector
import time

# 1. DATABASE CONNECTION

def connect_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Your_Password",
        database="netguard_db"
    )

def log_threat(cursor, db_connection, target_or_attacker, threat_type, description):
    """Helper function to insert alerts into the database."""
    query = "INSERT INTO threat_alerts (src_ip, threat_type, description) VALUES (%s, %s, %s)"
    values = (target_or_attacker, threat_type, description)
    try:
        cursor.execute(query, values)
        db_connection.commit()
    except Exception as e:
        print(f"Failed to log threat to DB: {e}")


# 2. THREAT DETECTION ALGORITHMS


def check_ddos_attack(cursor, db_connection):
    """Rule 1: Detects High-Volume DoS (Massive packet flood from a single IP)."""
    query = """
        SELECT src_ip, COUNT(*) as total_packets 
        FROM traffic_logs 
        WHERE timestamp >= NOW() - INTERVAL 5 SECOND 
        GROUP BY src_ip 
        HAVING total_packets > 400;
    """
    cursor.execute(query)
    for row in cursor.fetchall():
        attacker_ip, count = row[0], row[1]
        print(f"[DoS ALERT] {attacker_ip} is flooding the network ({count} pkts/5s)!")
        log_threat(cursor, db_connection, attacker_ip, "DoS Flood", f"Flooded with {count} pkts/5s")

def check_port_scan(cursor, db_connection):
    """Rule 2: Detects Reconnaissance (An IP probing > 50 distinct ports in 10s)."""
    query = """
        SELECT src_ip, COUNT(DISTINCT dst_port) as unique_ports 
        FROM traffic_logs 
        WHERE timestamp >= NOW() - INTERVAL 10 SECOND 
        GROUP BY src_ip 
        HAVING unique_ports > 50;
    """
    cursor.execute(query)
    for row in cursor.fetchall():
        attacker_ip, ports = row[0], row[1]
        print(f"[SCAN ALERT] {attacker_ip} probed {ports} unique ports in 10s!")
        log_threat(cursor, db_connection, attacker_ip, "Port Scan", f"Probed {ports} distinct ports")

def check_brute_force(cursor, db_connection):
    """Rule 3: Detects Brute-Force (High volume of connection attempts to SSH/FTP/RDP ports)."""
    
    query = """
        SELECT src_ip, COUNT(*) as total_packets 
        FROM traffic_logs 
        WHERE dst_port = 22 
        AND timestamp >= (SELECT MAX(timestamp) FROM traffic_logs) - INTERVAL 10 SECOND 
        GROUP BY src_ip 
        HAVING total_packets > 80;
    """
    cursor.execute(query)
    for row in cursor.fetchall():
        attacker_ip, count = row[0], row[1]
        print(f"[BRUTE FORCE ALERT] {attacker_ip} made {count} login attempts to secure ports in 60s!")
        log_threat(cursor, db_connection, attacker_ip, "Brute-Force Authentication", f"{count} attempts in 60s")

def check_data_exfiltration(cursor, db_connection):
    """Rule 4: Detects Data Theft (Unusually large outbound data transfer > 50MB in 1 minute)."""
    query = """
        SELECT src_ip, dst_ip, SUM(packet_size) as total_kb_sent 
        FROM traffic_logs 
        WHERE timestamp >= NOW() - INTERVAL 1 MINUTE 
        GROUP BY src_ip, dst_ip 
        HAVING total_kb_sent > 50000;
    """
    cursor.execute(query)
    for row in cursor.fetchall():
        src_ip, dst_ip, size_kb = row[0], row[1], row[2]
        size_mb = round(size_kb / 1024, 2)
        print(f"[EXFILTRATION ALERT] {src_ip} secretly uploaded {size_mb} MB to {dst_ip} in 60s!")
        log_threat(cursor, db_connection, src_ip, "Data Exfiltration", f"Transferred {size_mb} MB to {dst_ip}")

def check_dns_tunneling(cursor, db_connection):
    """Rule 5: Detects DNS Tunneling / C2 (Abnormal volume of DNS requests)."""
    query = """
        SELECT src_ip, COUNT(*) as dns_queries 
        FROM traffic_logs 
        WHERE (protocol = 'DNS' OR dst_port = 53) 
        AND timestamp >= NOW() - INTERVAL 10 SECOND 
        GROUP BY src_ip 
        HAVING dns_queries > 50;
    """
    cursor.execute(query)
    for row in cursor.fetchall():
        infected_ip, count = row[0], row[1]
        print(f"[C2 ALERT] {infected_ip} generated {count} DNS queries in 10s (Possible Malware Tunneling)!")
        log_threat(cursor, db_connection, infected_ip, "DNS Tunneling (C2)", f"{count} DNS requests in 10s")


# 3. THE MAIN IDS LOOP

print(" NetGuard IDS Analyzer Active")
print(" Continuously scanning database for Advanced Persistent Threats...")


while True:
    try:
        db = connect_db()
        cursor = db.cursor()
        
        # Execute the advanced security sweeps
        check_ddos_attack(cursor, db)
        check_port_scan(cursor, db)
        check_brute_force(cursor, db)
        check_data_exfiltration(cursor, db)
        check_dns_tunneling(cursor, db)
        
        cursor.close()
        db.close()
        
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
    
    # Pause for 3 seconds before the next sweep
    time.sleep(3)