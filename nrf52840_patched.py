"""Patched NRF52840 driver that fixes the tostring() deprecation."""
import array
import struct
import time
import usb.core
import usb.util
from expliot.core.interfaces.zbauditor.nrf52840 import NRF52840 as BaseNRF52840

class NRF52840(BaseNRF52840):
    """Patched NRF52840 driver that fixes the deprecated tostring() method."""
    
    def _process_sniffer_response(self, rxframe):
        """Return dictionary of Zigbee packet and timestamp.
        
        This is a patched version that uses tobytes() instead of tostring().

        Args:
            rxframe: Frame data array
        Returns:
            dictionary {"packet": zbpacket, "timestamp": 32bit timestamp}
        """
        # Get Start of Frame byte & encap len
        # Start of Frame @ 0th byte = 00
        # Frame Length @ 1st byte of frame
        # Frame Length = Zigbee packet len + 5
        (sof_byte, encap_len) = struct.unpack_from("<BH", rxframe)

        if self.SOF_BYTE != sof_byte:
            return None

        # Ignore first 3 bytes, read remaining bytes
        pktstream = array.array("B", rxframe[3:])
        if len(pktstream) == encap_len:
            # IEEE 802.15.4 Packet Length @ 7st byte of frame
            (timestamp, payloadlen) = struct.unpack_from("IB", pktstream)

            # Get Zigbee packet from 8th bytes on word
            payload = pktstream[5:]

            if len(payload) != payloadlen:
                return None

            # Last byte of mac payload is CRC OK MASK (0x80) & LQI
            crc_lqi = payload[-1]
            if (crc_lqi & 0x80) == 0x80:
                packet = payload[:-2]
                crc = self.calculate_crc(payload[:-2])
                for byte in crc:
                    packet.append(byte)
            else:
                packet = payload

            # Now we have valid packet - use tobytes() instead of tostring()
            ret = {"packet": packet.tobytes(), "timestamp": timestamp}
            return ret
        return None 
