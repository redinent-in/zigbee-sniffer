#!/usr/bin/env python3

import argparse
import time
import signal
import sys
import os
import yaml
import array
from datetime import datetime
from scapy.all import wrpcap, Dot15d4, Dot15d4FCS, conf, ZigbeeNWK
from nrf52840_patched import NRF52840
from elasticsearch import Elasticsearch
import json
import uuid

# Define the pcaps directory
PCAPS_DIR = os.path.join("pcaps")

# Define the config file path
CONFIG_PATH = os.path.join("config.yaml")

# Set the 802.15.4 protocol to Zigbee
conf.dot15d4_protocol = "zigbee"

class ZigbeeSniffer:
    def __init__(self, channel, output_pcap, packet_count=None, duration=None, live_save=False):
        """Initialize the Zigbee sniffer.
        
        Args:
            channel (int): Zigbee channel number (11-26)
            output_pcap (str): Path to save the pcap file
            packet_count (int, optional): Number of packets to capture before stopping
            duration (int, optional): Duration in seconds to capture before stopping
            live_save (bool): Whether to save decoded packets to Elasticsearch
        """
        self.channel = channel
        self.output_pcap = os.path.join(PCAPS_DIR, output_pcap)
        self.packet_count = packet_count
        self.duration = duration
        self.live_save = live_save
        self.device = None
        self.running = True
        self.captured_packets = []
        self.start_time = None
        self.es = None
        
        # Create pcaps directory if it doesn't exist
        os.makedirs(PCAPS_DIR, exist_ok=True)
        
        # Register signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        
    def check_zigbee_driver(self):
        """Check connectivity to the Zigbee driver."""
        try:
            print("[*] Checking Zigbee driver connectivity...")
            self.device = NRF52840()
            self.device.device_radio_on()
            self.device.device_set_channel(self.channel)
            print("[+] Zigbee driver connectivity check passed")
            return True
        except Exception as e:
            print(f"[-] Zigbee driver connectivity check failed: {e}")
            self.cleanup()  # Ensure device is cleaned up on failure
            return False
            
    def check_elasticsearch(self):
        """Check connectivity to Elasticsearch."""
        if not self.live_save:
            return True
            
        try:
            print("[*] Checking Elasticsearch connectivity...")
            with open(CONFIG_PATH, 'r') as f:
                config = yaml.safe_load(f)
                es_config = config.get('elasticsearch', {})
                es_hosts = es_config.get('hosts', ['http://localhost:9200'])
                
                # Create Elasticsearch client with configuration
                client_kwargs = {
                    'hosts': es_hosts
                }
                
                # Add authentication if configured
                if 'basic_auth' in es_config:
                    client_kwargs['basic_auth'] = es_config['basic_auth']
                
                # Add SSL configuration if present
                if 'ssl' in es_config:
                    ssl_config = es_config['ssl']
                    if ssl_config.get('verify_certs'):
                        client_kwargs['verify_certs'] = True
                        if 'ca_certs' in ssl_config:
                            client_kwargs['ca_certs'] = ssl_config['ca_certs']
                    else:
                        client_kwargs['verify_certs'] = False
                
                self.es = Elasticsearch(**client_kwargs)
                
                if not self.es.ping():
                    raise Exception("Could not connect to Elasticsearch")
                print(f"[+] Elasticsearch connectivity check passed at {es_hosts[0]}")
                return True
        except Exception as e:
            print(f"[-] Elasticsearch connectivity check failed: {e}")
            print("[*] Continuing without Elasticsearch integration")
            self.live_save = False
            return True  # Return True to allow continuing without ES
            
    def initialize(self):
        """Initialize all components and perform connectivity checks."""
        try:
            # Check Zigbee driver connectivity
            if not self.check_zigbee_driver():
                return False
                
            # Check Elasticsearch connectivity if live save is enabled
            if self.live_save:
                self.check_elasticsearch()  # Don't fail if ES check fails
                
            return True
        except Exception as e:
            print(f"[-] Initialization error: {e}")
            self.cleanup()
            return False
            
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully."""
        print("\n[*] Stopping sniffer...")
        self.running = False
        
    def cleanup(self):
        """Clean up resources."""
        if self.device:
            try:
                self.device.device_sniffer_off()
                self.device.device_radio_off()
                print("[+] Radio turned off")
            except Exception as e:
                print(f"[-] Error during cleanup: {e}")
            finally:
                self.device = None
        
    def initialize_device(self):
        """Initialize the NRF52840 device."""
        try:
            self.device = NRF52840()
            self.device.device_radio_on()
            print("[+] Device initialized successfully")
            
            self.device.device_set_channel(self.channel)
            print(f"[+] Set channel to {self.channel}")
            
            return True
        except Exception as e:
            print(f"[-] Failed to initialize device: {e}")
            return False
            
    def decode_packet(self, raw_packet):
        """Decode raw packet into relevant fields.
        
        Args:
            raw_packet: Raw packet data (array.array or bytes)
            
        Returns:
            dict: Decoded packet fields
        """
        try:
            if isinstance(raw_packet, array.array):
                packet_bytes = bytes(raw_packet)
            else:
                packet_bytes = raw_packet
                
            # Create Scapy packet for parsing
            scapy_packet = Dot15d4FCS(packet_bytes)
            
            # Extract frame control field components
            frame_type = scapy_packet.fcf_frametype
            security_enabled = scapy_packet.fcf_security
            frame_pending = scapy_packet.fcf_pending
            ack_request = scapy_packet.fcf_ackreq
            pan_id_compression = scapy_packet.fcf_panidcompress
            dest_addr_mode = scapy_packet.fcf_destaddrmode
            src_addr_mode = scapy_packet.fcf_srcaddrmode
            
            # Define frame types mapping
            frame_types = {
                0: "Beacon",
                1: "Data",
                2: "Acknowledgment",
                3: "MAC Command",
                4: "Reserved",
                5: "Reserved",
                6: "Reserved",
                7: "Reserved"
            }
            
            # Get friendly frame type name
            frame_type_name = frame_types.get(frame_type, "Unknown")
            
            # Extract PAN IDs and addresses based on addressing modes
            source_pan = None
            destination_pan = None
            source_addr = None
            destination_addr = None
            source_addr_raw = None
            destination_addr_raw = None
            pan_id_raw = None
            
            # Get PAN IDs if present
            if pan_id_compression:
                if hasattr(scapy_packet, 'dest_panid'):
                    destination_pan = hex(scapy_packet.dest_panid)
                    source_pan = destination_pan  # When PAN ID compression is used, source PAN = dest PAN
                    pan_id_raw = scapy_packet.dest_panid
            else:
                if hasattr(scapy_packet, 'dest_panid'):
                    destination_pan = hex(scapy_packet.dest_panid)
                    pan_id_raw = scapy_packet.dest_panid
                if hasattr(scapy_packet, 'src_panid'):
                    source_pan = hex(scapy_packet.src_panid)
            
            # Get addresses based on addressing modes
            if dest_addr_mode == 2:  # Short address
                if hasattr(scapy_packet, 'dest_addr'):
                    destination_addr = hex(scapy_packet.dest_addr)
                    destination_addr_raw = scapy_packet.dest_addr
            elif dest_addr_mode == 3:  # Extended address
                if hasattr(scapy_packet, 'dest_addr'):
                    destination_addr = hex(scapy_packet.dest_addr)
                    destination_addr_raw = scapy_packet.dest_addr
                    
            if src_addr_mode == 2:  # Short address
                if hasattr(scapy_packet, 'src_addr'):
                    source_addr = hex(scapy_packet.src_addr)
                    source_addr_raw = scapy_packet.src_addr
            elif src_addr_mode == 3:  # Extended address
                if hasattr(scapy_packet, 'src_addr'):
                    source_addr = hex(scapy_packet.src_addr)
                    source_addr_raw = scapy_packet.src_addr
            
            # Format addresses as strings with colons
            def format_addr_str(addr):
                if addr is None:
                    return None
                addr_bytes = addr.to_bytes(8, 'big')
                return ':'.join(f'{b:02x}' for b in addr_bytes)
            
            # Format PAN ID as string with colons
            def format_pan_str(pan):
                if pan is None:
                    return None
                pan_bytes = pan.to_bytes(2, 'big')
                return ':'.join(f'{b:02x}' for b in pan_bytes)
            
            # Extract network layer information if present
            nwk_source_raw = None
            nwk_destination_raw = None
            nwk_radius = None
            nwk_seqnum = None
            nwk_security = False
            
            # Check if packet has network layer payload
            if hasattr(scapy_packet, 'payload') and isinstance(scapy_packet.payload, ZigbeeNWK):
                nwk = scapy_packet.payload
                nwk_source_raw = getattr(nwk, 'source', None)
                nwk_destination_raw = getattr(nwk, 'destination', None)
                nwk_radius = getattr(nwk, 'radius', None)
                nwk_seqnum = getattr(nwk, 'sequence', None)
                nwk_security = getattr(nwk, 'security', False)
            
            # Generate scan ID
            scan_id = str(uuid.uuid4())
            
            # Extract relevant fields
            decoded = {
                'timestamp': datetime.now().isoformat(),
                'scan_id': scan_id,
                'length': len(packet_bytes),
                'rssi': -61,  # This should come from the device if available
                'channel': self.channel,
                'raw_bytes': packet_bytes.hex(),
                'frame_type': frame_type,
                'frame_type_name': frame_type_name,
                'security_enabled': security_enabled,
                'frame_pending': frame_pending,
                'ack_request': ack_request,
                'pan_id_compression': pan_id_compression,
                'dest_addr_raw': str(destination_addr_raw) if destination_addr_raw is not None else None,
                'source_addr_raw': str(source_addr_raw) if source_addr_raw is not None else None,
                'pan_id_raw': str(pan_id_raw) if pan_id_raw is not None else None,
                'dest_addr_str': format_addr_str(destination_addr_raw),
                'source_addr_str': format_addr_str(source_addr_raw),
                'pan_id_str': format_pan_str(pan_id_raw),
                'security_level': 5,  # This should be extracted from the packet if available
                'nwk_source_raw': str(nwk_source_raw) if nwk_source_raw is not None else None,
                'nwk_destination_raw': str(nwk_destination_raw) if nwk_destination_raw is not None else None,
                'nwk_source_str': format_addr_str(nwk_source_raw),
                'nwk_destination_str': format_addr_str(nwk_destination_raw),
                'nwk_radius': nwk_radius,
                'nwk_seqnum': nwk_seqnum,
                'nwk_security': nwk_security,
                'raw_packet': packet_bytes.hex()
            }
            return decoded
        except Exception as e:
            print(f"[-] Error decoding packet: {e}")
            import traceback
            traceback.print_exc()  # Print full traceback for debugging
            return None
            
    def print_packet_info(self, decoded_packet):
        """Print formatted packet information."""
        if not decoded_packet:
            return
            
        print(f"[+] Packet #{len(self.captured_packets)}:")
        print(f"    Type: {decoded_packet['frame_type_name']} (0x{decoded_packet['frame_type']:02x})")
        if decoded_packet['pan_id_str']:
            print(f"    PAN ID: {decoded_packet['pan_id_str']}")
        if decoded_packet['source_addr_str']:
            print(f"    Source Address: {decoded_packet['source_addr_str']}")
        if decoded_packet['dest_addr_str']:
            print(f"    Destination Address: {decoded_packet['dest_addr_str']}")
        if decoded_packet['nwk_source_str']:
            print(f"    Network Source: {decoded_packet['nwk_source_str']}")
        if decoded_packet['nwk_destination_str']:
            print(f"    Network Destination: {decoded_packet['nwk_destination_str']}")
        if decoded_packet['nwk_seqnum'] is not None:
            print(f"    Network Sequence: {decoded_packet['nwk_seqnum']}")
        print(f"    RSSI: {decoded_packet['rssi']} dBm")
        print(f"    Channel: {decoded_packet['channel']}")
        print()

    def should_stop_capture(self):
        """Check if capture should stop based on count or duration."""
        if self.packet_count and len(self.captured_packets) >= self.packet_count:
            print(f"\n[*] Reached packet count limit ({self.packet_count})")
            return True
            
        if self.duration and time.time() - self.start_time >= self.duration:
            print(f"\n[*] Reached duration limit ({self.duration} seconds)")
            return True
            
        return False
        
    def save_to_elasticsearch(self, decoded_packet):
        """Save decoded packet to Elasticsearch."""
        if not self.es:
            return
            
        try:
            self.es.index(index='redbee_pcap', document=decoded_packet)
        except Exception as e:
            print(f"[-] Error saving to Elasticsearch: {e}")
        
    def capture_packets(self):
        """Listen for and capture Zigbee packets."""
        print("[*] Starting Zigbee packet capture...")
        if self.packet_count:
            print(f"[*] Will capture {self.packet_count} packets")
        if self.duration:
            print(f"[*] Will capture for {self.duration} seconds")
        print()
        
        try:
            self.device.device_sniffer_on(self.channel)
            self.start_time = time.time()
            
            while self.running and not self.should_stop_capture():
                pkt_data = self.device.device_read(timeout=100)
                if pkt_data and isinstance(pkt_data, dict):
                    raw_packet = pkt_data.get("packet")
                    if raw_packet:
                        # Create Scapy packet for pcap
                        packet_bytes = bytes(raw_packet)
                        scapy_packet = Dot15d4FCS(packet_bytes)
                        self.captured_packets.append(scapy_packet)
                        
                        # Decode and display packet information
                        decoded_packet = self.decode_packet(raw_packet)
                        self.print_packet_info(decoded_packet)
                        
                        # Save to Elasticsearch if enabled
                        if self.live_save and decoded_packet:
                            self.save_to_elasticsearch(decoded_packet)
                            
            # Save captured packets to pcap
            if self.captured_packets:
                wrpcap(self.output_pcap, self.captured_packets)
                print(f"[+] Saved {len(self.captured_packets)} packets to {self.output_pcap}")
                
        except Exception as e:
            print(f"[-] Error during capture: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.device.device_sniffer_off()
            
def main():
    parser = argparse.ArgumentParser(description="Zigbee Traffic Sniffer")
    parser.add_argument("-c", "--channel", type=int, required=True,
                      help="Zigbee channel number (11-26)")
    parser.add_argument("-o", "--output", type=str, default=None,
                      help=f"Output pcap file (saved in {PCAPS_DIR}, default: zigbee_capture_<timestamp>.pcap)")
    parser.add_argument("-n", "--count", type=int,
                      help="Stop after capturing N packets")
    parser.add_argument("-t", "--time", type=int,
                      help="Stop capturing after T seconds")
    parser.add_argument("-l", "--live", action="store_true",
                      help="Enable live saving of decoded packets to Elasticsearch")
    
    args = parser.parse_args()
    
    # Validate channel
    if not (11 <= args.channel <= 26):
        print("[-] Error: Channel must be between 11 and 26")
        sys.exit(1)
        
    # Generate default output filename if not specified
    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"zigbee_capture_{timestamp}.pcap"
        
    # Initialize sniffer
    sniffer = ZigbeeSniffer(
        channel=args.channel,
        output_pcap=args.output,
        packet_count=args.count,
        duration=args.time,
        live_save=args.live
    )
    
    try:
        # Perform all connectivity checks
        if not sniffer.initialize():
            print("[-] Initialization failed. Please check the connectivity issues above.")
            sys.exit(1)
            
        sniffer.capture_packets()
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        sniffer.cleanup()

if __name__ == "__main__":
    main() 