import scapy.all as scapy
import yaml
import ruamel.yaml.scalarstring


def _find_destination_mac(frame):
    mac_type = frame[0:12]
    mac_type = _format_mac_address(mac_type)
    return mac_type


def _find_source_mac(frame):
    mac_type = frame[12:24]
    mac_type = _format_mac_address(mac_type)
    return mac_type


def _format_mac_address(mac_type):
    mac_type = mac_type.upper()
    mac_type = mac_type[:2] + ":" + mac_type[2:]
    mac_type = mac_type[:5] + ":" + mac_type[5:]
    mac_type = mac_type[:8] + ":" + mac_type[8:]
    mac_type = mac_type[:11] + ":" + mac_type[11:]
    mac_type = mac_type[:14] + ":" + mac_type[14:]
    # print(mac_type)
    return mac_type


def _find_frame_type(frame):
    typeInt = int(frame[24:28], 16)
    if typeInt >= 1536:
        return "ETHERNET II"
    elif typeInt <= 1500 and frame[28:32] == "ffff":
        return "IEE 802.3 - Raw"
    elif typeInt <= 1500 and frame[28:32] == "aaaa":
        return "IEE 802.3 s LLC a SNAP"  # od piateho bajtu PID protocol pre snap
    elif typeInt <= 1500:
        return "IEE 802.3 LLC"


def _find_sap_type(frame):
    # typeInt = int(frame[24:28], 16)
    with open("Protocols/l2.txt", "r") as protocol_file:
        for line in protocol_file:
            print(line)

    # print(f.read())
    pass


def _format_frame(frame):
    # print("frame to format:", frame)

    new_frame = ''
    counter = 0
    for char in frame:
        if counter == 1:
            new_frame += char + ' ' * 1
            counter = 0
        else:
            new_frame += char
            counter += 1

    counter = 0
    new_frame_with_spaces = ''
    for char in new_frame:
        if counter == 47:
            new_frame_with_spaces += char + '\n' * 1
            counter = 0
        else:
            new_frame_with_spaces += char
            counter += 1

    # new_frame = new_frame.upper()
    # print(new_frame)
    new_frame_with_spaces = new_frame_with_spaces.upper()
    # print(new_frame_with_spaces)
    return new_frame_with_spaces


if __name__ == '__main__':

    # fileName = input("Zadajte názov súboru: ")
    # pcap = scapy.rdpcap(fileName)
    pcap = scapy.rdpcap("pcap_files/trace-26.pcap")
    order = 1
    initial_dictionary = {'name': 'PKS2022/23',
                          'pcap_name': 'all.cap'}
    packets_dictionary = {"packets": []}

    with open("frames.yaml", "w") as file:
        init_file = yaml.dump(initial_dictionary, file, default_flow_style=False, sort_keys=False)

    for pkt in pcap:

        len_frame_pcap = int(len(pkt) / 2)
        if len_frame_pcap >= 60:
            len_frame_medium = len_frame_pcap
            len_frame_medium += 4
        else:
            len_frame_medium = 64

        frameInHex = scapy.raw(pkt).hex()
        destination_mac = _find_destination_mac(frameInHex)
        source_mac = _find_source_mac(frameInHex)
        frame_type = _find_frame_type(frameInHex)
        # sap = _find_sap_type(frameInHex)
        formated_frame = _format_frame(frameInHex)
        # print(type(formated_frame))
        # print(formated_frame)
        if frame_type == "IEE 802.3 LLC a SNAP":
            sap = _find_sap_type(frameInHex)

        frames_dictionary = {"frame_number": order,
                             "len_frame_pcap": len_frame_pcap,
                             "len_frame_medium": len_frame_medium,
                             "frame_type": frame_type,
                             "src_mac": source_mac,
                             "dst_mac": destination_mac,
                             "hexa_frame": ruamel.yaml.scalarstring.LiteralScalarString(formated_frame)}

        packets_dictionary["packets"].append(frames_dictionary)
        order += 1

    with open('frames.yaml', 'r+') as output_stream:
        yaml = ruamel.yaml.YAML()
        yaml.default_flow_style = False
        yaml.dump(packets_dictionary, output_stream)
        #documents = yaml.dump(packets_dictionary, output_stream, default_flow_style=False, sort_keys=False)

        # print("Name: PKS2022/23\n"
        #     "pcap_name: all.pcap\n"
        # "packets: \n"
        # " - frame_number: ", order, "\n"
        #                             "   len_frame_pcap: ", "\n"
        #                                                    "   len_frame_medium: ", "\n"
        #                                                                             "   frame_type: ",
        # frame_type, "\n"
        #                "   src_mac: ", source_mac, "\n"
        #                                            "   dst_mac: ", destination_mac, "\n"
        #                                                                             "   ether_type: ", "\n"
        #                                                                                                "   src_ip: ",
        # "\n"
        # "   protocol: ", "\n"
        #                  "   src_port: ", "\n"
        #                                   "   dst_port: ", "\n"
        #                                                    "   app_protocol: ", "\n"
        #                                                                         "   hexa_frame: |\n", frameInHex)
