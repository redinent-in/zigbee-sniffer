# Zigbee Sniffer

A Python-based tool for capturing and analyzing Zigbee network traffic using an nRF52840 device.  Based on https://github.com/expliot-framework/expliot. 


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

## License
This project is licensed under the terms specified in the LICENSE file.

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer
This tool is for educational and research purposes only. Always ensure you have permission to analyze any network before using these tools. 