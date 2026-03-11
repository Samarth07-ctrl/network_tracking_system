# Implementation Plan: Campus Network Traffic Analyzer and Security Monitor

## Overview

This implementation plan breaks down the Campus Network Traffic Analyzer system into discrete coding tasks. The system consists of three main components:
- Backend: Python with FastAPI for REST API, Scapy for packet capture
- Database: MySQL for persistent storage
- Frontend: React for admin dashboard

Tasks are organized to build incrementally, starting with core infrastructure, then packet capture and analysis, security detection, and finally the frontend dashboard. Each task references specific requirements for traceability.

## Tasks

- [x] 1. Set up project structure and database schema
  - [x] 1.1 Create project directory structure and configuration files
    - Create backend directory with Python package structure
    - Create frontend directory with React app structure
    - Create configuration file template for system parameters
    - Set up requirements.txt for Python dependencies (FastAPI, Scapy, MySQL connector, asyncio)
    - Set up package.json for React dependencies
    - _Requirements: 19.1, 19.2, 20.6, 22.2_
  
  - [x] 1.2 Design and implement MySQL database schema
    - Create wifi_networks table (id, ssid, subnet_range, location, capture_interface)
    - Create connected_devices table (id, mac_address, ip_address, wifi_network_id, first_seen, last_seen, is_active)
    - Create packet_logs table (id, timestamp, source_ip, dest_ip, source_mac, protocol, source_port, dest_port, packet_size, wifi_network_id)
    - Create security_alerts table (id, timestamp, alert_type, severity, source_ip, source_mac, target_ip, metadata, wifi_network_id)
    - Create performance_metrics table (id, timestamp, wifi_network_id, throughput_bps, packet_rate, avg_packet_size)
    - Create prohibited_websites table (id, domain, category)
    - Add indexes on timestamp, wifi_network_id, mac_address, ip_address fields
    - _Requirements: 1.4, 3.4, 2.5, 6.4, 13.4, 16.1, 16.2, 16.3, 16.4, 16.5_
  
  - [x] 1.3 Create database access layer module
    - Implement DatabaseManager class with connection pooling
    - Implement methods for inserting packet_logs, security_alerts, performance_metrics
    - Implement methods for querying wifi_networks, connected_devices, packet_logs
    - Implement methods for managing prohibited_websites
    - Handle database connection errors and retries
    - _Requirements: 20.5, 16.1-16.7_

- [x] 2. Implement packet capture module
  - [x] 2.1 Create PacketCaptureModule class with Scapy integration
    - Implement packet sniffing using Scapy's sniff() function
    - Support capturing from multiple network interfaces concurrently
    - Parse packet headers to extract IP addresses, MAC addresses, protocol, ports, packet size
    - Create PacketLog data structure with all required fields
    - Implement asynchronous packet processing using asyncio
    - _Requirements: 2.1, 2.2, 15.1, 15.2, 15.3, 18.1_
  
  - [x] 2.2 Implement multi-network concurrent capture
    - Create separate capture sessions for each configured WiFi network
    - Use threading or asyncio to handle concurrent captures
    - Implement packet queue with capacity monitoring
    - Add logging for performance warnings when queue exceeds 80% capacity
    - _Requirements: 1.1, 1.2, 1.3, 18.2, 18.3, 18.5_
  
  - [ ]* 2.3 Write unit tests for packet parsing
    - Test IP header extraction with sample packets
    - Test TCP/UDP port extraction
    - Test MAC address extraction
    - Test handling of malformed packets
    - _Requirements: 15.1, 15.2, 15.3_

- [x] 3. Implement traffic analyzer module
  - [x] 3.1 Create TrafficAnalyzer class for packet classification
    - Implement protocol classification (TCP, UDP, ICMP, DNS, HTTP, HTTPS)
    - Extract DNS query domain names from DNS packets
    - Maintain packet and byte counters per protocol type
    - Process packets within 100ms requirement
    - _Requirements: 2.2, 2.3, 2.6, 2.7_
  
  - [x] 3.2 Implement device tracking and registry
    - Extract source MAC and IP from packets to identify devices
    - Maintain in-memory registry of connected devices per WiFi network
    - Update device last_seen timestamp on each packet
    - Mark devices inactive after 300 seconds of no activity
    - Persist device records to database
    - _Requirements: 3.1, 3.2, 3.3, 3.4_
  
  - [x] 3.3 Implement bandwidth and throughput calculation
    - Calculate total bytes transmitted/received per device
    - Calculate network throughput in bytes per second every 10 seconds
    - Calculate packet rate in packets per second every 10 seconds
    - Calculate average packet size every 60 seconds
    - Rank devices by bandwidth consumption
    - _Requirements: 2.4, 5.1, 5.2, 13.1, 13.2, 13.3_
  
  - [x] 3.4 Implement traffic region analysis
    - Calculate total throughput per WiFi network every 60 seconds
    - Rank WiFi networks by throughput
    - Generate capacity warning when network exceeds 80% of configured bandwidth
    - Store performance metrics to database
    - _Requirements: 4.1, 4.2, 4.5, 13.4_
  
  - [ ]* 3.5 Write unit tests for traffic analysis
    - Test protocol classification with sample packets
    - Test bandwidth calculation accuracy
    - Test device activity timeout logic
    - Test throughput calculation
    - _Requirements: 2.3, 2.7, 5.1, 13.1_

- [ ] 4. Checkpoint - Ensure packet capture and analysis work correctly
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Implement intrusion detection engine
  - [x] 5.1 Create IntrusionDetectionEngine class with rule-based detection
    - Implement base detection framework with alert generation
    - Create SecurityAlert data structure with all required fields
    - Implement alert persistence to database
    - _Requirements: 6.2, 6.3, 6.4, 20.3_
  
  - [x] 5.2 Implement port scan detection
    - Track TCP SYN packets per source device
    - Detect when device sends SYN to >20 distinct ports on single target within 60s
    - Generate security alert with source IP, MAC, target IP, port range, severity
    - Alert generation within 5 seconds of detection
    - _Requirements: 6.1, 6.2, 6.3, 6.5_
  
  - [x] 5.3 Implement DDoS detection
    - Track packet rate per target IP from multiple sources
    - Detect when target receives >1000 packets/sec from 5+ sources within 30s
    - Generate critical severity alert with target IP, source list, packet rate
    - Update alert every 10 seconds while attack persists
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_
  
  - [x] 5.4 Implement brute force attack detection
    - Track failed authentication attempts to SSH (22), RDP (3389), HTTP auth (80/443)
    - Detect >10 failed attempts from single source within 120 seconds
    - Generate security alert with source IP, MAC, target IP, port, attempt count
    - _Requirements: 8.1, 8.2, 8.3, 8.4_
  
  - [x] 5.5 Implement prohibited website monitoring
    - Load prohibited website domains from database
    - Monitor DNS query packets for prohibited domains
    - Generate security alert when prohibited domain is requested
    - Include source IP, MAC, domain, policy violation category in alert
    - _Requirements: 9.1, 9.2, 9.3, 9.4_
  
  - [x] 5.6 Implement high bandwidth usage alerts
    - Monitor device bandwidth consumption
    - Generate alert when device exceeds 5GB within 1 hour
    - _Requirements: 5.5_
  
  - [ ]* 5.7 Write unit tests for intrusion detection
    - Test port scan detection with simulated traffic
    - Test DDoS detection with high packet rate scenarios
    - Test brute force detection with repeated auth attempts
    - Test prohibited website detection with DNS queries
    - _Requirements: 6.1, 7.1, 8.1, 9.2_

- [x] 6. Implement backend REST API with FastAPI
  - [x] 6.1 Create FastAPI application and core endpoints
    - Set up FastAPI app with CORS middleware
    - Implement health check endpoint
    - Implement error handling and HTTP status codes
    - _Requirements: 17.10, 17.11, 20.4_
  
  - [x] 6.2 Implement WiFi network endpoints
    - GET /api/networks - retrieve list of all WiFi networks
    - GET /api/networks/{id} - retrieve specific network details
    - GET /api/networks/{id}/devices - retrieve connected devices for network
    - GET /api/networks/{id}/metrics - retrieve performance metrics for network
    - _Requirements: 17.1, 17.2, 17.5, 1.5_
  
  - [x] 6.3 Implement packet and traffic endpoints
    - GET /api/packets - retrieve packet logs with time range and network filters
    - GET /api/protocols/{network_id} - retrieve protocol distribution for network
    - GET /api/bandwidth/{network_id} - retrieve top bandwidth consumers
    - _Requirements: 17.3, 17.6, 17.7_
  
  - [x] 6.4 Implement security alert endpoints
    - GET /api/alerts - retrieve security alerts with severity and time filters
    - GET /api/alerts/{network_id} - retrieve alerts for specific network
    - _Requirements: 17.4, 6.5, 12.7_
  
  - [x] 6.5 Implement prohibited website management endpoints
    - POST /api/prohibited-websites - add prohibited domain
    - DELETE /api/prohibited-websites/{id} - remove prohibited domain
    - GET /api/prohibited-websites - list all prohibited domains
    - _Requirements: 17.8, 17.9, 9.5_
  
  - [x] 6.6 Implement data formatting and serialization
    - Create Pydantic models for all API request/response schemas
    - Implement JSON serialization for PacketLog objects
    - Implement round-trip serialization (JSON -> object -> JSON)
    - _Requirements: 15.4, 15.5, 15.6_
  
  - [ ]* 6.7 Write API integration tests
    - Test all GET endpoints with sample data
    - Test POST/DELETE endpoints for prohibited websites
    - Test error handling and validation
    - Test response format and status codes
    - _Requirements: 17.1-17.11_

- [ ] 7. Checkpoint - Ensure backend API works correctly
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. Implement system configuration and initialization
  - [x] 8.1 Create configuration file parser
    - Define configuration file schema (YAML or JSON)
    - Implement configuration loader with validation
    - Support WiFi network definitions (SSID, subnet, interface)
    - Support intrusion detection thresholds
    - Support database connection parameters
    - Support packet log retention period
    - Log descriptive errors for invalid configuration
    - _Requirements: 19.1, 19.2, 19.3, 19.4, 19.5, 19.6_
  
  - [x] 8.2 Create main application orchestrator
    - Implement startup sequence: load config, connect database, initialize modules
    - Start packet capture sessions for all configured networks
    - Start traffic analyzer workers
    - Start intrusion detection engine
    - Start FastAPI server
    - Implement graceful shutdown handling
    - _Requirements: 1.2, 18.1, 18.4, 20.6_
  
  - [x] 8.3 Implement subnet-based network segmentation
    - Parse subnet ranges from configuration
    - Classify devices by subnet based on IP address
    - Store subnet configuration in database
    - _Requirements: 14.1, 14.2, 14.3_
  
  - [ ]* 8.4 Write configuration validation tests
    - Test valid configuration loading
    - Test invalid configuration error handling
    - Test subnet parsing
    - _Requirements: 19.6, 14.1_

- [ ] 9. Implement data retention and archival
  - [ ] 9.1 Create data retention manager
    - Implement scheduled task to check packet log age
    - Archive or delete packet logs older than 30 days
    - Retain security alerts for at least 365 days
    - Log retention operations
    - _Requirements: 16.6, 16.7_

- [x] 10. Implement React frontend - Core structure
  - [x] 10.1 Set up React application with routing
    - Create React app with TypeScript
    - Set up React Router for navigation
    - Create layout components (header, sidebar, main content)
    - Set up API client for backend communication
    - _Requirements: 11.6, 12.1, 20.4_
  
  - [x] 10.2 Create campus network overview dashboard
    - Display total count of monitored WiFi networks
    - Display total count of active connected devices
    - Display aggregate network throughput
    - Display count of security alerts in last 24 hours
    - Display list of WiFi networks with traffic load indicators
    - Update data every 5 seconds
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 10.5_
  
  - [x] 10.3 Create WiFi network detail view
    - Display network configuration (SSID, subnet, location)
    - Display current throughput, packet rate, active device count
    - Display top 10 bandwidth consumers
    - Display protocol distribution pie chart
    - Display list of all connected devices
    - Display security alerts for the network
    - _Requirements: 12.2, 12.3, 12.4, 12.5, 12.6, 12.7_

- [ ] 11. Implement React frontend - Real-time visualizations
  - [x] 11.1 Create live packet feed component
    - Display most recent 100 captured packets
    - Show timestamp, source, destination, protocol, size for each packet
    - Update every 5 seconds with new data
    - _Requirements: 10.1, 10.5_
  
  - [x] 11.2 Create protocol distribution chart
    - Implement pie chart showing percentage breakdown by protocol
    - Support filtering by WiFi network
    - Update every 5 seconds
    - _Requirements: 10.2, 10.5, 10.6_
  
  - [x] 11.3 Create bandwidth and packet rate graphs
    - Implement line graph for throughput over last 60 minutes
    - Implement line graph for packet rate over last 60 minutes
    - Support filtering by WiFi network
    - Update every 5 seconds
    - _Requirements: 10.3, 10.4, 10.5, 10.6_
  
  - [ ] 11.4 Create traffic heatmap visualization
    - Display relative traffic density for each campus location
    - Use color coding for traffic levels (low, medium, high)
    - _Requirements: 4.3_

- [x] 12. Implement React frontend - Security panel
  - [x] 12.1 Create security alerts display component
    - Display security alerts with real-time updates
    - Show alert type, severity, source, target, timestamp
    - Support filtering by severity and time range
    - Highlight critical alerts prominently
    - Update every 5 seconds
    - _Requirements: 6.5, 7.4, 8.4, 9.4, 10.5_
  
  - [x] 12.2 Create device information display
    - Display detailed device information (IP, MAC, connection duration, data usage)
    - Show device activity status
    - _Requirements: 3.5, 3.6_
  
  - [x] 12.3 Create prohibited website management interface
    - Display list of prohibited websites
    - Implement form to add new prohibited domains
    - Implement delete functionality for domains
    - _Requirements: 9.5_

- [ ] 13. Implement React frontend - Performance metrics
  - [ ] 13.1 Create performance metrics dashboard
    - Display current throughput, packet rate, average packet size
    - Display historical metrics with trend indicators
    - Support time range selection
    - _Requirements: 13.6, 4.4_
  
  - [ ] 13.2 Create bandwidth consumer ranking display
    - Display top 10 bandwidth consumers with IP, MAC, data usage
    - Support filtering by WiFi network
    - Support custom time range selection
    - _Requirements: 5.3, 5.4_

- [ ] 14. Integration and system testing
  - [ ] 14.1 Wire all components together
    - Connect packet capture module to traffic analyzer
    - Connect traffic analyzer to intrusion detection engine
    - Connect all modules to database layer
    - Connect backend API to all data sources
    - Connect frontend to backend API
    - _Requirements: 20.6, 20.7_
  
  - [ ] 14.2 Create sample data and test scenarios
    - Create sample PCAP files with normal traffic
    - Create sample PCAP files with port scan activity
    - Create sample PCAP files with DDoS patterns
    - Create sample PCAP files with brute force attempts
    - Create sample configuration file
    - _Requirements: 22.3, 22.6_
  
  - [ ]* 14.3 Write end-to-end integration tests
    - Test packet capture to database flow
    - Test security alert generation and display
    - Test API endpoints with real data
    - Test frontend data refresh
    - _Requirements: 18.2, 18.5_

- [ ] 15. Documentation and deployment preparation
  - [x] 15.1 Create README and installation guide
    - Document system requirements and dependencies
    - Provide installation instructions for Python and Node.js dependencies
    - Provide database setup instructions
    - Provide quick start guide with sample configuration
    - Document how to run the system locally
    - _Requirements: 21.1, 22.1, 22.2, 22.4, 22.5_
  
  - [ ] 15.2 Create API documentation
    - Document all REST API endpoints
    - Provide request and response examples
    - Document error codes and messages
    - _Requirements: 21.3_
  
  - [ ] 15.3 Create database schema documentation
    - Document all tables and their columns
    - Document relationships and foreign keys
    - Document indexes and their purpose
    - _Requirements: 21.4_
  
  - [ ] 15.4 Create configuration documentation
    - Document all configuration parameters
    - Provide valid value ranges and formats
    - Provide example configuration files
    - _Requirements: 21.5_
  
  - [x] 15.5 Add inline code comments
    - Add comments explaining networking concepts
    - Document implementation decisions
    - Document component interfaces
    - _Requirements: 21.2, 20.7_
  
  - [ ] 15.6 Create architecture diagram
    - Create diagram showing all components
    - Show data flow between components
    - Show external dependencies
    - _Requirements: 21.6_

- [ ] 16. Final checkpoint - System validation
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- The system uses Python/FastAPI/Scapy for backend, MySQL for database, and React for frontend
- Packet capture requires appropriate network permissions (may need sudo/admin rights)
- For local testing, use PCAP files instead of live network interfaces
- Performance requirements: handle 10,000 packets/sec, process packets within 100ms
- Security alert generation must occur within 5 seconds of detection
- Frontend updates every 5 seconds for real-time monitoring
