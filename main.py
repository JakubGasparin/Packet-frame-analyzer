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

    with open("Protocols/pid.yaml", "r") as stream:
        get_PID = (yaml.safe_load(stream))

    sap_number = frame[40:44]
    # print(frame)
    #  print(get_PID)
    #  print(sap_number)

    if sap_number in get_PID:
        PID = get_PID[sap_number]
        # print(sap_number, PID)
        return PID

    # print(sap_number)


# with open("Protocols/l2.txt", "r") as protocol_file:
#    for line in protocol_file:
# print(line)
#   if line == "#LSAPs\n":
#   print(line)
# folder_line = protocol_file.readline()
# print(folder_line)
#       for line_2 in protocol_file:
#           if line_2 == "#IP Protocol numbers\n":
#               break
# else:
#   print(line_2)
# print(line)

# print(f.read()


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
    # print(frame )
    with open("Protocols/ether_type.yaml", "r") as stream:
        get_ethertype = (yaml.safe_load(stream))
    # print(hex_number)
    if hex_number in get_ethertype:
        ether_type = get_ethertype[hex_number]
        return ether_type
    else:
        return 0


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
    # hex_number = str(hex_number)
    #  hex_number = "0x" + hex_number

    # hex_number = frame[24:28]
    with open("Protocols/protocol.yaml", "r") as stream:
        get_protocol = (yaml.safe_load(stream))

    ipv4_protocol = get_protocol[hex_number]
    # print(ipv4_protocol)

    # with open("Protocols/l2.txt") as protocol_file:
    #   for line in protocol_file:
    #       if line == "#IP Protocol numbers\n":
    #           for line_2 in protocol_file:
    #               if line_2 == "#TCP ports\n":
    #                   break
    #    else:
    # first_four = line_2[0:4]
    #   if hex_number == first_four:
    #       prtc = line_2[7:10]

    # print(hex_number, prtc)
    return ipv4_protocol


def _find_src_TCP_app_protocol(frame):
    src_port_number = frame[68:72]
    return src_port_number
    #  src_well_known_port = '.'

    #  with open("Protocols/app_protocol.yaml", "r") as stream:
    #    check_for_app_protocol = (yaml.safe_load(stream))

    ## if src_port_number in check_for_app_protocol:
    #  print("source app protocol exists")
    #     src_well_known_port = check_for_app_protocol[src_port_number]
    #    return src_port_number, src_well_known_port
    # print(src_well_known_port)
    # else:
    # print(src_port_number)
    #     return src_port_number, src_well_known_port

    # ipv4_protocol = get_protocol[hex_number]
    src_well_known_port = ''
    dst_well_known_port = ''

    # with open("Protocols/l2.txt") as port_file:
    #    for line in port_file:
    #       if line == "#TCP ports\n":
    #           for line_2 in port_file:
    #               if line_2 == "#UDP ports\n":
    #                   break
    #               else:
    #                   first_six = line_2[0:6]
    #                   if src_port_number == first_six:
    #                       src_well_known_port = " ".join(re.findall("[a-zA-Z]+", line_2))
    #                   if dst_port_number == first_six:
    #                       dst_well_known_port = " ".join(re.findall("[a-zA-Z]+", line_2))

    #  print(src_well_known_port, dst_well_known_port)


# return src_port_number

# print(src_port_number)
# print(dst_port_number)


def _find_dst_TCP_app_protocol(frame):
    dst_port_number = frame[72:76]
    # print(dst_port_number)
    # with open("Protocols/app_protocol.yaml", "r") as stream:
    #     check_for_app_protocol = (yaml.safe_load(stream))
    # if dst_port_number in check_for_app_protocol:
    #     dst_port_number = check_for_app_protocol[dst_port_number]

    #  print(dst_port_number)

    # dst_well_known_port = ''
    return dst_port_number


#  with open("Protocols/app_protocol.yaml", "r") as stream:
#     check_for_app_protocol = (yaml.safe_load(stream))

# if dst_port_number in check_for_app_protocol:
#   # print("dst app protocol exists")
#   dst_well_known_port = check_for_app_protocol[dst_port_number]
#   return dst_port_number, dst_well_known_port
# else:
#   return dst_port_number, dst_well_known_port


def _check_if_its_is_well_known_protocol(src_port, dst_port):
    with open("Protocols/app_protocol.yaml", "r") as stream:
        check_for_app_protocol = (yaml.safe_load(stream))

    if src_port in check_for_app_protocol:
        well_known = check_for_app_protocol[src_port]
        return well_known
    elif dst_port in check_for_app_protocol:
        well_known = check_for_app_protocol[dst_port]
        return well_known
    else:
        return None


if __name__ == '__main__':
    # fileName = input("Zadajte názov súboru: ")
    # pcap = scapy.rdpcap(fileName)
    pcap = scapy.rdpcap("pcap_files/trace-27.pcap")
    order = 1
    initial_dictionary = {'name': 'PKS2022/23',
                          'pcap_name': 'all.cap'}
    packets_dictionary = {"packets": []}
    ipv4_packets_dictionary = {"ipv4_senders": []}
    max_packets_dictionary = {"max_send_packets_by": []}
    unique_src_ip_list = []
    unique_counter = []

    # for pkt in pcap:
    #    frameInHex = scapy.raw(pkt).hex()
    #   print(order, frameInHex, "\n")
    #   order = order + 1

    with open("frames.yaml", "w") as file:
        yaml.dump(initial_dictionary, file, default_flow_style=False, sort_keys=False)

    for pkt in pcap:
        len_frame_pcap = int(len(pkt))
        if len_frame_pcap >= 60:
            len_frame_medium = len_frame_pcap
            len_frame_medium += 4
        else:
            len_frame_medium = 64

        # print("\n", order,"\n", pkt)
        frameInHex = scapy.raw(pkt).hex()
        # print("\n", order, "\n", frameInHex)
        # order = 1
        # for packet in pcap:
        #    frameInHex = scapy.raw(packet).hex()
        #   print(order, frameInHex, "\n")
        #   order = order + 1
        destination_mac = _find_destination_mac(frameInHex)
        source_mac = _find_source_mac(frameInHex)
        frame_type = _find_frame_type(frameInHex)
        formated_frame = _format_frame(frameInHex)
        formated_frame += "\n"

        print(frame_type, order)

        if frame_type == "IEE 802.3 - Raw" or frame_type == "IEE 802.3 LLC":
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

        if frame_type == "IEE 802.3 s LLC a SNAP":
            pid = _find_sap_type(frameInHex)
            frames_dictionary = {"frame_number": order,
                                 "len_frame_pcap": len_frame_pcap,
                                 "len_frame_medium": len_frame_medium,
                                 "frame_type": frame_type,
                                 "src_mac": source_mac,
                                 "dst_mac": destination_mac,
                                 "pid": pid,
                                 "hexa_frame": ruamel.yaml.scalarstring.LiteralScalarString(formated_frame)
                                 }
            packets_dictionary["packets"].append(frames_dictionary)
            order += 1

        if frame_type == "ETHERNET II":
            second_layer_protocol = _find_second_eth_layer_protocol(frameInHex)

            if second_layer_protocol == 0:
                print("got here")
                frames_dictionary = {"frame_number": order,
                                     "len_frame_pcap": len_frame_pcap,
                                     "len_frame_medium": len_frame_medium,
                                     "frame_type": frame_type,
                                     "src_mac": source_mac,
                                     "dst_mac": destination_mac,
                                     "hexa_frame": ruamel.yaml.scalarstring.LiteralScalarString(formated_frame)
                                     }
                packets_dictionary["packets"].append(frames_dictionary)
                order += 1

            print(second_layer_protocol)
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

            elif second_layer_protocol == "IPv6":
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

            elif second_layer_protocol == "IPv4":
                src_ip, dst_ip = _find_ip(frameInHex, second_layer_protocol)

                if src_ip not in unique_src_ip_list:
                    unique_src_ip_list.append(src_ip)
                    index = unique_src_ip_list.index(src_ip)
                    unique_counter.append(1)

                elif src_ip in unique_src_ip_list:
                    index = unique_src_ip_list.index(src_ip)
                    unique_counter[index] = unique_counter[index] + 1

                protocol = _find_IPv4_protocol(frameInHex)

                if protocol == "TCP" or protocol == "UDP":
                    src_port = _find_src_TCP_app_protocol(frameInHex)
                    dst_port = _find_dst_TCP_app_protocol(frameInHex)
                    app_protocol = _check_if_its_is_well_known_protocol(src_port, dst_port)
                    src_port = int(src_port, 16)
                    dst_port = int(dst_port, 16)

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
                                         "src_port": src_port,
                                         "dst_port": dst_port,
                                         "app_protocol": app_protocol,
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
                                     "hexa_frame": ruamel.yaml.scalarstring.LiteralScalarString(formated_frame)}

                packets_dictionary["packets"].append(frames_dictionary)
                order += 1

    max_packets = 0
    max_send_packets_by = []
    for i in range(len(unique_counter)):
        # print(unique_counter[i])
        temp = unique_counter[i]
        if max_packets == temp:
            max_packets = temp
            max_send_packets_by.append(unique_src_ip_list[i])
        elif max_packets < temp:
            max_packets = temp
            max_send_packets_by.clear()
            max_send_packets_by.append(unique_src_ip_list[i])
        src_ip_dictionary = {"nodes": unique_src_ip_list[i],
                             "number_of_sent_packets": unique_counter[i]}
        ipv4_packets_dictionary["ipv4_senders"].append(src_ip_dictionary)

    print(max_send_packets_by)

    for i in range(len(max_send_packets_by)):
        max_packets_dictionary["max_send_packets_by"].append(max_send_packets_by[i])

    print(max_packets_dictionary)

    with open('frames.yaml', 'r+') as output_stream:
        yaml = ruamel.yaml.YAML()
        yaml.default_flow_style = False
        yaml.dump(packets_dictionary, output_stream)
        yaml.dump(ipv4_packets_dictionary, output_stream)
        yaml.dump(max_packets_dictionary, output_stream)
