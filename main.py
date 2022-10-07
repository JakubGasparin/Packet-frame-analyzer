import scapy.all as scapy
import yaml
import ruamel.yaml.scalarstring
import re


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
    # check_eth = frame[24:28]
    # print(check_eth)
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
    folder_line = 0
    # typeInt = int(frame[42:46], 16)
    # sap_number = frame[40:44] # PID

    sap_number = frame[28:32]
    print(sap_number)
    with open("Protocols/l2.txt", "r") as protocol_file:
        for line in protocol_file:
            # print(line)
            if line == "#LSAPs\n":
                print(line)
                # folder_line = protocol_file.readline()
                # print(folder_line)
                for line_2 in protocol_file:
                    if line_2 == "#IP Protocol numbers\n":
                        break
                    else:
                        print(line_2)
            # print(line)

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
    # new_frame_with_spaces += '\n'
    new_frame_with_spaces = new_frame_with_spaces.upper()
    # print(new_frame_with_spaces)
    return new_frame_with_spaces


def _find_second_eth_layer_protocol(frame):
    hex_number = frame[24:28]
    hex_number = str(hex_number)
    hex_number = "0x" + hex_number
    protocol = ''
    # print(hex_number)
    with open("Protocols/l2.txt", "r") as protocol_file:
        for line in protocol_file:
            if line == "#Ethertypes\n":

                for line_2 in protocol_file:
                    if line_2 == "#LSAPs\n":
                        break
                    else:
                        first_six = line_2[0:6]
                        if hex_number == first_six:
                            protocol = line_2[7:11]

    # print(hex_number)
    # print(hex_number, protocol)
    if not protocol:
        pass
    else:
        if protocol[-1] == '\n':
            protocol = protocol.strip(protocol[-1])
    # print(hex_number, protocol)
    return protocol


def _find_ip(frame, protocol):
    # print(frame, protocol)
    if protocol == "IPv4":
        src = _find_src_ip_IPv4(frame)
        dst = _find_dst_ip_IPv4(frame)
        return src, dst

    if protocol == "ARP":
        src = _find_src_ip_ARP(frame)
        dst = _find_dst_ip_ARP(frame)
        return src, dst


def _find_src_ip_IPv4(frame):
    first_number = int(frame[52:54], 16)
    second_number = int(frame[54:56], 16)
    third_number = int(frame[56:58], 16)
    fourth_number = int(frame[58:60], 16)

    first_number = str(first_number)
    second_number = str(second_number)
    third_number = str(third_number)
    fourth_number = str(fourth_number)
    src = first_number + '.' + second_number + '.' + third_number + '.' + fourth_number
    return src


def _find_dst_ip_IPv4(frame):
    first_number = int(frame[60:62], 16)
    second_number = int(frame[62:64], 16)
    third_number = int(frame[64:66], 16)
    fourth_number = int(frame[66:68], 16)

    first_number = str(first_number)
    second_number = str(second_number)
    third_number = str(third_number)
    fourth_number = str(fourth_number)
    dst = first_number + '.' + second_number + '.' + third_number + '.' + fourth_number
    return dst


def _find_src_ip_ARP(frame):
    first_number = int(frame[56:58], 16)
    second_number = int(frame[58:60], 16)
    third_number = int(frame[60:62], 16)
    fourth_number = int(frame[62:64], 16)

    first_number = str(first_number)
    second_number = str(second_number)
    third_number = str(third_number)
    fourth_number = str(fourth_number)
    src = first_number + '.' + second_number + '.' + third_number + '.' + fourth_number
    return src


def _find_dst_ip_ARP(frame):
    first_number = int(frame[76:78], 16)
    second_number = int(frame[78:80], 16)
    third_number = int(frame[80:82], 16)
    fourth_number = int(frame[82:84], 16)

    first_number = str(first_number)
    second_number = str(second_number)
    third_number = str(third_number)
    fourth_number = str(fourth_number)
    dst = first_number + '.' + second_number + '.' + third_number + '.' + fourth_number
    return dst


def _find_IPv4_protocol(frame):
    hex_number = frame[46:48]
    hex_number = str(hex_number)
    hex_number = "0x" + hex_number
    prtc = ''

    with open("Protocols/l2.txt") as protocol_file:
        for line in protocol_file:
            if line == "#IP Protocol numbers\n":
                for line_2 in protocol_file:
                    if line_2 == "#TCP ports\n":
                        break
                    else:
                        first_four = line_2[0:4]
                        if hex_number == first_four:
                            prtc = line_2[7:10]

    # print(hex_number, prtc)
    return prtc

def _find_TCP_port(frame):
    src_port_number = frame[68:72]
    dst_port_number = frame[72:76]
    src_well_known_port = ''
    dst_well_known_port = ''

    with open("Protocols/l2.txt") as port_file:
        for line in port_file:
            if line == "#TCP ports\n":
                for line_2 in port_file:
                    if line_2 == "#UDP ports\n":
                        break
                    else:
                        first_six = line_2[0:6]
                        if src_port_number == first_six:
                            src_well_known_port = " ".join(re.findall("[a-zA-Z]+", line_2))
                        if dst_port_number == first_six:
                            dst_well_known_port = " ".join(re.findall("[a-zA-Z]+", line_2))

    print(src_well_known_port, dst_well_known_port)



    #print(src_port_number)
    #print(dst_port_number)



if __name__ == '__main__':

    # fileName = input("Zadajte názov súboru: ")
    # pcap = scapy.rdpcap(fileName)
    pcap = scapy.rdpcap("pcap_files/eth-1.pcap")
    order = 1
    initial_dictionary = {'name': 'PKS2022/23',
                          'pcap_name': 'all.cap'}
    packets_dictionary = {"packets": []}

    with open("frames.yaml", "w") as file:
        yaml.dump(initial_dictionary, file, default_flow_style=False, sort_keys=False)

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
        # print(frame_type)
        if frame_type == "IEE 802.3 s LLC a SNAP":
            sap = _find_sap_type(frameInHex)
        if frame_type == "ETHERNET II":
            second_layer_protocol = _find_second_eth_layer_protocol(frameInHex)
            # print(second_layer_protocol)
            if second_layer_protocol == "ARP":
                src_ip, dst_ip = _find_ip(frameInHex, second_layer_protocol)

                frames_dictionary = {"frame_number": order,
                                     "len_frame_pcap": len_frame_pcap,
                                     "len_frame_medium": len_frame_medium,
                                     "frame_type": frame_type,
                                     "src_mac": source_mac,
                                     "dst_mac": destination_mac,
                                     "ether_type": second_layer_protocol,
                                     "src_ip": src_ip,
                                     "dst_ip": dst_ip,
                                     "hexa_frame": ruamel.yaml.scalarstring.LiteralScalarString(formated_frame)
                                     }

                packets_dictionary["packets"].append(frames_dictionary)
                order += 1

            if second_layer_protocol == "IPv4":
                src_ip, dst_ip = _find_ip(frameInHex, second_layer_protocol)
                protocol = _find_IPv4_protocol(frameInHex)

                if protocol == "TCP":
                    src_port, dst_port = _find_TCP_port(frameInHex)
                frames_dictionary = {"frame_number": order,
                                     "len_frame_pcap": len_frame_pcap,
                                     "len_frame_medium": len_frame_medium,
                                     "frame_type": frame_type,
                                     "src_mac": source_mac,
                                     "dst_mac": destination_mac,
                                     "ether_type": second_layer_protocol,
                                     "src_ip": src_ip,
                                     "dst_ip": dst_ip,
                                     "protocol": protocol,
                                     "hexa_frame": ruamel.yaml.scalarstring.LiteralScalarString(formated_frame)
                                     }

                packets_dictionary["packets"].append(frames_dictionary)
                order += 1

            else:
                frames_dictionary = {"frame_number": order,
                                     "len_frame_pcap": len_frame_pcap,
                                     "len_frame_medium": len_frame_medium,
                                     "frame_type": frame_type,
                                     "src_mac": source_mac,
                                     "dst_mac": destination_mac,
                                     "ether_type": second_layer_protocol,
                                     "hexa_frame": ruamel.yaml.scalarstring.LiteralScalarString(formated_frame)
                                     }

                packets_dictionary["packets"].append(frames_dictionary)
                order += 1

        if frame_type == "IEE 802.3 - Raw" or frame_type == "IEE 802.3 s LLC a SNAP" or frame_type == "IEE 802.3 LLC":
            frames_dictionary = {"frame_nuber": order,
                                 "len_frame_pcap": len_frame_pcap,
                                 "len_frame_medium": len_frame_medium,
                                 "frame_type": frame_type,
                                 "src_mac": source_mac,
                                 "dst_mac": destination_mac,
                                 "hexa_frame": ruamel.yaml.scalarstring.LiteralScalarString(formated_frame)
                                 }
            packets_dictionary["packets"].append(frames_dictionary)
            order += 1

    with open('frames.yaml', 'r+') as output_stream:
        yaml = ruamel.yaml.YAML()
        yaml.default_flow_style = False
        yaml.dump(packets_dictionary, output_stream)
        # documents = yaml.dump(packets_dictionary, output_stream, default_flow_style=False, sort_keys=False)

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
