-- NetGuard IDS - Database Schema

-- Create the database if it doesn't already exist
CREATE DATABASE IF NOT EXISTS netguard_db;
USE netguard_db;


-- Table: traffic_logs
-- Purpose: High-speed ingestion buffer for all raw captured packets

CREATE TABLE IF NOT EXISTS traffic_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    src_ip VARCHAR(45) NULL,   -- 45 chars ensures IPv6 compatibility
    dst_ip VARCHAR(45) NULL,
    src_port INT DEFAULT 0,
    dst_port INT DEFAULT 0,
    protocol VARCHAR(20) NULL,
    packet_size FLOAT NULL,    -- Stored in KB for volumetric analysis
    description VARCHAR(255) NULL
);


-- Table: threat_alerts
-- Purpose: Curated intelligence table for the Flask SOC Dashboard

CREATE TABLE IF NOT EXISTS threat_alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    src_ip VARCHAR(45) NULL,
    threat_type VARCHAR(50) NULL,
    description VARCHAR(255) NULL
);


-- Note: No strict Foreign Keys are used between these tables to ensure 
-- maximum write-speed during volumetric (DDoS) attacks and to allow 
-- independent log rotation/purging.
