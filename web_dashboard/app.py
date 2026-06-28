from flask import Flask, render_template, jsonify
import mysql.connector

app = Flask(__name__)


# DATABASE CONNECTION

def connect_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Your_password",
        database="netguard_db"
    )

# ROUTES

@app.route('/')
def dashboard():
    return render_template('index.html')

@app.route('/api/data')
def get_live_data():
    try:
        db = connect_db()
        cursor = db.cursor(dictionary=True)
        
        # 1. Fetch recent alerts 
        query = """
            SELECT MAX(timestamp) as timestamp, src_ip, threat_type 
            FROM threat_alerts 
            GROUP BY src_ip, threat_type 
            ORDER BY timestamp DESC 
            LIMIT 8
        """
        cursor.execute(query)
        alerts = cursor.fetchall()
        for alert in alerts:
            alert['timestamp'] = alert['timestamp'].strftime('%I:%M:%S %p')
        
        # 2. Fetch recent traffic
        cursor.execute("SELECT * FROM traffic_logs ORDER BY timestamp DESC LIMIT 15")
        traffic = cursor.fetchall()
        for log in traffic:
            log['timestamp'] = log['timestamp'].strftime('%I:%M:%S %p')
            
        # 3. Fetch Data for the Live Distribution Chart
        cursor.execute("SELECT threat_type, COUNT(*) as count FROM threat_alerts GROUP BY threat_type")
        distribution = cursor.fetchall()
        
        cursor.close()
        db.close()
        
        return jsonify({
            "status": "success",
            "alerts": alerts,
            "traffic": traffic,
            "distribution": distribution
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)