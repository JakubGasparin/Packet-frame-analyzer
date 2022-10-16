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
    with open("Protocols/pid.yaml", "r") as stream:
        get_PID = (yaml.safe_load(stream))

    sap_number = frame[40:44]

    if sap_number in get_PID:
        PID = get_PID[sap_number]
        return PID
    else:
        return sap_number


def _format_frame(frame):
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
    new_frame_with_spaces = new_frame_with_spaces.upper()
    return new_frame_with_spaces


def _find_second_eth_layer_protocol(frame):
    hex_number = frame[24:28]
    with open("Protocols/ether_type.yaml", "r") as stream:
        get_ethertype = (yaml.safe_load(stream))

    if hex_number in get_ethertype:
        ether_type = get_ethertype[hex_number]
        return ether_type
    else:
        return 0


def _find_ip(frame, protocol):
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
    # print(frame)
    hex_number = frame[46:48]

    with open("Protocols/protocol.yaml", "r") as stream:
        get_protocol = (yaml.safe_load(stream))

    ipv4_protocol = get_protocol[hex_number]
    return ipv4_protocol


def _find_src_TCP_app_protocol(frame):
    src_port_number = frame[68:72]
    return src_port_number


def _find_dst_TCP_app_protocol(frame):
    dst_port_number = frame[72:76]
    return dst_port_number


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


def _start_to_analyze_TCP_communication(tcp_pcap):
    order = 1
    for tcp_pkt in tcp_pcap:
        tcp_frame = scapy.raw(tcp_pkt).hex()
        # tcp_frame = _format_frame(tcp_frame)
        # print(tcp_frame)
        # print(tcp_frame)

        # TREBA NAJST IBA TCP RAMCE
        is_IPv4 = _find_second_eth_layer_protocol(tcp_frame)
        if is_IPv4 == "IPv4":
            is_tcp_protocol = _find_IPv4_protocol(tcp_frame)
            if is_tcp_protocol == "TCP":  # nasiel som TCP protokol, tak idem riešiť komunikácie
                if _check_for_three_hand_handshake(tcp_frame, order, tcp_pcap):


        order += 1


def _check_for_three_hand_handshake(frame, check_order, tcp_pcap):  # zistiť začiatok komunikácie
    order = 1
    flag = _get_flags(frame)
    flag2 = 0
    flag3 = 0
    # print(flag)

    if flag == "000010":  # found SYN, time to check next two packets
        for check_for_next_two_packets in tcp_pcap:
            tcp_frame = scapy.raw(check_for_next_two_packets).hex()
            if order == check_order + 1:  # check for second packet, aka check for SYN, ACK
                flag2 = _get_flags(tcp_frame)

            if order == check_order + 2:  # check for third packet, aka check for ACK
                flag3 = _get_flags(tcp_frame)

            order += 1
    if flag == "000010" and flag2 == "010010" and flag3 == "010000":  # found start of a communication
        return True
    else:
        return False


def _get_flags(frame):
    flag = int(frame[93:96], 16)
    flag = (bin(flag)[2:].zfill(8)[2:])
    return flag


if __name__ == '__main__':
    # fileName = input("Zadajte názov súboru: ")
    # pcap = scapy.rdpcap

    switch = input("Chcete analyzovať aj komunikáciu? (-p)")
    switch_protocol = input("Zvolte si typ protokolu: ")
    pcap = scapy.rdpcap("pcap_files/eth-4.pcap")

    if switch == "-p":
        if switch_protocol == "HTTP" or switch_protocol == "TELNET" or switch_protocol == "SSH" or switch_protocol == "FTP radiace" or switch_protocol == "FTP datove":
            _start_to_analyze_TCP_communication(pcap)

    order = 1
    initial_dictionary = {'name': 'PKS2022/23',
                          'pcap_name': 'all.cap'}
    packets_dictionary = {"packets": []}
    ipv4_packets_dictionary = {"ipv4_senders": []}
    max_packets_dictionary = {"max_send_packets_by": []}
    unique_src_ip_list = []
    unique_counter = []

    with open("frames.yaml", "w") as file:
        yaml.dump(initial_dictionary, file, default_flow_style=False, sort_keys=False)

    for pkt in pcap:
        len_frame_pcap = int(len(pkt))
        if len_frame_pcap >= 60:
            len_frame_medium = len_frame_pcap
            len_frame_medium += 4
        else:
            len_frame_medium = 64

        frameInHex = scapy.raw(pkt).hex()
        destination_mac = _find_destination_mac(frameInHex)
        source_mac = _find_source_mac(frameInHex)
        frame_type = _find_frame_type(frameInHex)
        formated_frame = _format_frame(frameInHex)
        formated_frame += "\n"

        # print(frame_type, order)

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

    for i in range(len(max_send_packets_by)):
        max_packets_dictionary["max_send_packets_by"].append(max_send_packets_by[i])

    with open('frames.yaml', 'r+') as output_stream:
        yaml = ruamel.yaml.YAML()
        yaml.default_flow_style = False
        yaml.dump(packets_dictionary, output_stream)
        yaml.dump(ipv4_packets_dictionary, output_stream)
        yaml.dump(max_packets_dictionary, output_stream)
