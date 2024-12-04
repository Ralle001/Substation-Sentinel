from struct import pack

from scapy.packet import Packet
from scapy.fields import XShortField, XByteField, XIntField, ConditionalField, StrLenField
from scapy.all import bind_layers


class SV(Packet):
    name = "SV"
    fields_desc = [
        XShortField("appid", 0),         # Application Identifier
        XShortField("length", 8),        # Length of the SV packet
        XShortField("reserved1", 0),     # Reserved field 1
        XShortField("reserved2", 0),     # Reserved field 2
        XByteField("noASDU", 1),         # Number of ASDUs in the frame
    ]

    def post_build(self, packet, payload):
        sv_pdu_length = len(packet) + len(payload)
        packet = packet[:2] + pack('!H', sv_pdu_length) + packet[4:]
        return packet + payload

class SVPDU(Packet):
    name = "SVPDU"
    fields_desc = [
        XByteField("ID", 0x60),               # Identifier for the SV PDU (Default 0x60)
        XByteField("DefLen", 0x64),           # Length of the PDU
        ConditionalField(XByteField("PDU1ByteLen", 0x00), lambda pkt: pkt.DefLen ^ 0x80 == 1),  # PDU 1-byte length
        ConditionalField(XShortField("PDU2BytesLen", 0x0000), lambda pkt: pkt.DefLen ^ 0x80 == 2)  # PDU 2-byte length
    ]


class ASDU(Packet):
    name = "ASDU"
    fields_desc = [
        XByteField("svID", 0),                # Sampled Value ID
        #XIntField("datSet", 0),               # Data set reference
        XByteField("smpCnt", 0),              # Sample count
        XByteField("confRev", 0),             # Configuration revision
        XByteField("smpSynch", 0),            # Synchronization state
    ]

    def post_build(self, packet, payload):
        # Automatically adjust length of the ASDU if required
        return packet + payload


# Binding SV and SVPDU layers
bind_layers(SV, SVPDU)

# Binding SVPDU and ASDU layers
bind_layers(SVPDU, ASDU)
