# Zigbee Sniffer

A simple Python-based tool for capturing and analyzing Zigbee network traffic using an nRF52840 Dongle.  Based on https://github.com/expliot-framework/expliot. 


## Features
- Real-time Zigbee packet capture
- Support for channels 11-26
- Packet decoding and analysis
- PCAP file output
- Elasticsearch integration for packet storage and analysis
- Configurable capture duration and packet count limits

## Requirements
- Python 3.x
- nRF52840 device
- Elasticsearch (optional, for packet storage)
- Required Python packages (see requirements.txt)
- Zigbee_sniffer.py needs to be run as Root User or su. (ex - sudo python3 zigbee_sniffer.py -c 24)

## Configuration
Edit `config.yml` to configure Elasticsearch connection settings.

## Setup

1. Clone the repository:
```bash
git clone <repository-url>
```

2. Set up the Zigbee Sniffer:
```bash
cd zigbee-sniffer
pip install -r requirements.txt
```

## Usage
```bash
python zigbee_sniffer.py --channel <channel> --output <output.pcap> [--count <packet_count>] [--duration <seconds>] [--live-save]
```

Options:
- `--channel`: Zigbee channel (11-26)
- `--output`: Output PCAP file name
- `--count`: Number of packets to capture (optional)
- `--duration`: Capture duration in seconds (optional)
- `--live-save`: Enable live saving to Elasticsearch

## Results

```bash
python3 zigbee_sniffer.py -c 24 
[*] Checking Zigbee driver connectivity...
[+] Zigbee driver connectivity check passed
[*] Starting Zigbee packet capture...

[+] Packet #1:
    Type: MAC Command (0x03)
    PAN ID: 52:7c
    Source Address: 00:00:00:00:00:00:04:01
    Destination Address: 00:00:00:00:00:00:04:00
    RSSI: -61 dBm
    Channel: 24

[+] Packet #2:
    Type: Acknowledgment (0x02)
    RSSI: -61 dBm
    Channel: 24

[+] Packet #3:
    Type: MAC Command (0x03)
    PAN ID: 52:7c
    Source Address: 00:00:00:00:00:00:04:01
    Destination Address: 00:00:00:00:00:00:04:00
    RSSI: -61 dBm
    Channel: 24

[+] Packet #4:
    Type: Acknowledgment (0x02)
    RSSI: -61 dBm
    Channel: 24

[+] Packet #5:
    Type: Data (0x01)
    PAN ID: 23:f8
    Source Address: 00:00:00:00:00:00:00:00
    Destination Address: 00:00:00:00:00:00:ff:ff
    RSSI: -61 dBm
    Channel: 24

[+] Packet #6:
    Type: Data (0x01)
    PAN ID: 52:7c
    Source Address: 1e:da:0f:d8:98:8b:c9:b3
    Destination Address: 00:00:00:00:00:00:ff:ff
    RSSI: -61 dBm
    Channel: 24

^C
[*] Stopping sniffer...
[+] Saved 6 packets to pcaps/zigbee_capture_20250326_061637.pcap
[+] Radio turned off
```


## License
This project is licensed under the terms specified in the LICENSE file.

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer
This tool is for educational and research purposes only. Always ensure you have permission to analyze any network before using these tools. 
