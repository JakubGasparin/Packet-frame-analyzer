import scapy.all as scapy
import yaml
import ruamel.yaml.scalarstring

global_tcp_packet_list = []
global_first_unfinished_packet = []

global_TFTP_packet_list = []
global_TFTP_counter = 1


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


def _check_for_first_unfinished(tcp_pcap):
    found_SYN = None
    for pkt in tcp_pcap:
        tcp_frame = scapy.raw(pkt).hex()
        if _check_if_its_TCP(tcp_frame):
            flag = _get_flags(tcp_frame)
            flag = list(flag)

            if flag[4] == "1":  # na tejto pozíci je vlajka SYN
                found_SYN = _get_packet_information(tcp_frame)
                if _find_end(found_SYN, tcp_pcap):
                    global_first_unfinished_packet = found_SYN

            # print(flag)


def _find_end(packet, tcp_pcap):
    new_pkt = []
    for pkt in tcp_pcap:
        frame = scapy.raw(pkt).hex()
        if _check_if_its_TCP(frame):
            flag = _get_flags(tcp_pcap)
            flag = list(flag)
            if flag[5] == "1" or flag[3] == "1" or flag[2] == "1":
                if _compare_incomplete(packet, frame):
                    return True
    return False


def _compare_incomplete(pkt1, pkt2):
    if pkt1 == pkt2:
        return True
    if pkt1[0] == pkt2[1] and pkt1[1] == pkt2[0] and pkt1[2] == pkt2[3] and pkt1[3] == pkt2[2]:
        return True
    else:
        return False


def _start_to_analyze_TCP_communication(tcp_pcap):
    order = 1

    _check_for_first_unfinished(tcp_pcap)
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
                if _check_for_three_hand_handshake(tcp_frame, order, tcp_pcap, order):
                    pass

        order += 1


def _check_for_three_hand_handshake(frame, check_order, tcp_pcap, order):  # zistiť začiatok komunikácie
    flag = _get_flags(frame)
    flag2 = 0
    flag3 = 0
    source_list = []
    destination_list = []
    source_list_ACK = []
    reformat_port = 0
    check_for_dst_ip = ''
    # print(flag)

    if flag == "000010":  # found SYN, time to check next two packets
        source_list.append(_find_src_ip_IPv4(frame))
        source_list.append(_find_dst_ip_IPv4(frame))
        reformat_port = int(_find_src_TCP_app_protocol(frame), 16)
        source_list.append(reformat_port)
        reformat_port = int(_find_dst_TCP_app_protocol(frame), 16)
        source_list.append(reformat_port)
        source_list.append(order)

        order = 1

        for THH_pkt in tcp_pcap:  # prehladavam cely subor ci najdem SYN, ACK
            tcp_frame = scapy.raw(THH_pkt).hex()
            destination_list.append(_find_src_ip_IPv4(tcp_frame))
            destination_list.append(_find_dst_ip_IPv4(tcp_frame))
            reformat_port = int(_find_src_TCP_app_protocol(tcp_frame), 16)
            destination_list.append(reformat_port)
            reformat_port = int(_find_dst_TCP_app_protocol(tcp_frame), 16)
            destination_list.append(reformat_port)
            destination_list.append(order)

            if source_list[0] == destination_list[1] and source_list[1] == destination_list[0] and source_list[2] == \
                    destination_list[3] and source_list[3] == destination_list[2]:
                flag2 = _get_flags(tcp_frame)
                break
            else:
                destination_list.clear()
                order += 1

        if flag2 == "010010":  # hladam ACK
            # print("got here")
            order = 1
            for THH_pkt_2 in tcp_pcap:
                tcp_frame = scapy.raw(THH_pkt_2).hex()
                source_list_ACK.append(_find_src_ip_IPv4(tcp_frame))
                source_list_ACK.append(_find_dst_ip_IPv4(tcp_frame))
                reformat_port = int(_find_src_TCP_app_protocol(tcp_frame), 16)
                source_list_ACK.append(reformat_port)
                reformat_port = int(_find_dst_TCP_app_protocol(tcp_frame), 16)
                source_list_ACK.append(reformat_port)
                source_list_ACK.append(order)
                # flag3 = _get_flags(tcp_frame)
                # print(destination_list, source_list_ACK)

                if source_list_ACK[0] == destination_list[1] and source_list_ACK[1] == destination_list[0] and \
                        source_list_ACK[2] == destination_list[3] and source_list_ACK[3] == destination_list[2]:
                    flag3 = _get_flags(tcp_frame)
                    if flag3 == "010000":
                        # print(flag3)
                        break
                    else:
                        source_list_ACK.clear()
                        order += 1
                else:
                    source_list_ACK.clear()
                    order += 1

        # if flag3 == "010000":
        # break
        # print(source_list, "\n", destination_list,"\n", source_list_ACK)
        # print(flag, flag2, flag3)

    if flag == "000010" and flag2 == "010010" and flag3 == "010000":  # found start of a communication
        # print("found start")
        # _check_for_end_of_three_way_handshake(source_list, destination_list, tcp_pcap, source_list[4])
        _check_for_end_of_TWH(source_list, destination_list, tcp_pcap, source_list[4])
        return True
    else:
        return False


def _check_for_end_of_TWH(source_list, destination_list, tcp_pcap, order):
    ending_packet = []
    counter = 1
    possible_end_1 = ['FIN_ACK', 'ACK', 'FIN_ACK', 'ACK']
    possible_end_2 = ['FIN', 'FIN_ACK', 'ACK']
    possible_end_3 = ['FIN_ACK', 'FIN_ACK', 'ACK', 'ACK']
    possible_end_4 = ['RST']
    check_for_end_flags = ['1', '2', '3', '4']
    opposite = []
    start_of_end = []

    for find_end in tcp_pcap:
        # filler
        tcp_frame = scapy.raw(find_end).hex()
        # print(counter)
        if counter < order:
            counter += 1  # prejdem na zaciatok komunikácie
        else:
            if _check_if_its_TCP(tcp_frame):
                flag = _get_flags(tcp_frame)
                # print(check_for_end_flags)
                # print(source_list, destination_list)
                # print(flag)
                # if flag_ACK == "010100" or flag_ACK == "000100"

                # print(flag, flag[-1])

                if flag == "010001":  # first FIN_ACK, pracujem s  FIN_ACK
                    found_pkt = _get_packet_information(tcp_frame)
                    found_pkt.append(counter)
                    if _compare_packets_in_TCP_communication(found_pkt, source_list, destination_list):
                        check_for_end_flags[0] = "FIN_ACK"
                        # print(found_pkt, counter)

                if flag == "010000" and check_for_end_flags[
                    0] == "FIN_ACK":  # ACK, toto zrejme bude FIN_ACK, ACK, FIN_ACK, ACK
                    found_pkt = _get_packet_information(tcp_frame)
                    found_pkt.append(counter)
                    if _compare_packets_in_TCP_communication(found_pkt, source_list, destination_list):
                        check_for_end_flags[1] = "ACK"
                        # print(found_pkt, counter)
                if flag == "010001" and check_for_end_flags[1] == "ACK":  # druhy FIN_ACK
                    found_pkt = _get_packet_information(tcp_frame)
                    found_pkt.append(counter)
                    if _compare_packets_in_TCP_communication(found_pkt, source_list, destination_list):
                        check_for_end_flags[2] = "FIN_ACK"
                        # print(found_pkt, counter)
                if flag == "010000" and check_for_end_flags[2] == "FIN_ACK":  # druhy ACK
                    found_pkt = _get_packet_information(tcp_frame)
                    found_pkt.append(counter)
                    if _compare_packets_in_TCP_communication(found_pkt, source_list, destination_list):
                        check_for_end_flags[3] = "ACK"
                        ending_packet = found_pkt
                        ending_packet.append(counter)
                        # print(ending_packet)

                if flag == "010001" and check_for_end_flags[
                    0] == "FIN_ACK":  # druhy FIN_ACK toto zrejme bude FIN_ACK, FIN_ACK, ACK, ACK
                    found_pkt = _get_packet_information(tcp_frame)
                    found_pkt.append(counter)
                    if _compare_packets_in_TCP_communication(found_pkt, source_list, destination_list):
                        check_for_end_flags[1] = "FIN_ACK"
                if flag == "010000" and check_for_end_flags[1] == "FIN_ACK":  # ACK
                    found_pkt = _get_packet_information(tcp_frame)
                    found_pkt.append(counter)
                    if _compare_packets_in_TCP_communication(found_pkt, source_list, destination_list):
                        check_for_end_flags[2] = "ACK"
                if flag == "010000" and check_for_end_flags[2] == "ACK":  # posledny ACK
                    found_pkt = _get_packet_information(tcp_frame)
                    found_pkt.append(counter)
                    if _compare_packets_in_TCP_communication(found_pkt, source_list, destination_list):
                        check_for_end_flags[3] = "ACK"
                        ending_packet = found_pkt
                        ending_packet.append(counter)

                if flag == "010100" or flag == "000100":  # RST
                    found_pkt = _get_packet_information(tcp_frame)
                    found_pkt.append(counter)
                    if _compare_packets_in_TCP_communication(found_pkt, source_list, destination_list):
                        check_for_end_flags.clear()
                        check_for_end_flags.append("RST")
                        ending_packet = found_pkt
                # print(check_for_end_flags, counter)

                if check_for_end_flags == possible_end_1 or \
                        check_for_end_flags == possible_end_2 or \
                        check_for_end_flags == possible_end_3 or \
                        check_for_end_flags == possible_end_4:
                    print(check_for_end_flags, source_list, destination_list, ending_packet)
                    _print_TCP(source_list, destination_list, ending_packet, tcp_pcap)
                    check_for_end_flags = ['1', '2', '3', '4']
            counter += 1


def _print_TCP(source, dst, ending_packet, tcp_pcap):
    order = 1
    global global_TFTP_counter
    tcp_packets_dictionary = {"complete comms": {"number comm": global_TFTP_counter,
                                                 "src_comm": source[0],
                                                 "dst_comm": source[1],
                                                 "packets": []}}
    for TCP_print in tcp_pcap:
        if order < source[4]:
            order += 1
        elif order <= ending_packet[4]:
            frame = scapy.raw(TCP_print).hex()
            if _check_if_its_TCP(frame):
                frame_list = _get_packet_information(frame)
                frame_list.append(order)
                #print(frame_list)
                if _compare_packets_in_TCP_communication(frame_list, source, dst):
                    len_frame_pcap = int(len(tcp_pcap))
                    if len_frame_pcap >= 60:
                        len_frame_medium = len_frame_pcap
                        len_frame_medium += 4
                    else:
                        len_frame_medium = 64

                    frame_type = _find_frame_type(frame)
                    source_mac = _find_source_mac(frame)
                    destination_mac = _find_destination_mac(frame)
                    ether_type = _find_second_eth_layer_protocol(frame)
                    src_ip = _find_src_ip_IPv4(frame)
                    dst_ip = _find_dst_ip_IPv4(frame)
                    protocol = _find_IPv4_protocol(frame)
                    src_port = _find_src_TCP_app_protocol(frame)
                    dst_port = _find_dst_TCP_app_protocol(frame)
                    app_protocol = _check_if_its_is_well_known_protocol(src_port, dst_port)
                    src_port = int(src_port, 16)
                    dst_port = int(dst_port, 16)
                    formated_frame = _format_frame(frame)
                    formated_frame += "\n"

                    packet_dict = {"frame_number": order,
                                   "len_frame_pcap": len_frame_pcap,
                                   "len_frame_medium": len_frame_medium,
                                   "frame_type": frame_type,
                                   "src_mac": source_mac,
                                   "dst_mac": destination_mac,
                                   "ether_type": ether_type,
                                   "src_ip": src_ip,
                                   "dst_ip": dst_ip,
                                   "protocol": protocol,
                                   "src_port": src_port,
                                   "dst_port": dst_port,
                                   "app_protocol": app_protocol,
                                   "hexa_frame": ruamel.yaml.scalarstring.LiteralScalarString(formated_frame)
                                   }
                    tcp_packets_dictionary["complete comms"]["packets"].append(packet_dict)
            order += 1
    # print(tcp_packets_dictionary)
    global_tcp_packet_list.append(tcp_packets_dictionary)
    # print(global_tcp_packet_list)
    with open('tcp_communications.yaml', "r+") as output_stream:
        yaml = ruamel.yaml.YAML()
        yaml.default_flow_style = False
        yaml.dump(global_tcp_packet_list, output_stream)
    global_TFTP_counter += 1


def _compare_packets_in_TCP_communication_source(found, source):
    if found[0] == source[0] and found[1] == source[1] and found[1] == source[1]:
        return True
    return False


def _compare_packets_in_TCP_communication_destination(found, source):
    if found[0] == source[0] and found[1] == source[1] and found[1] == source[1]:
        return True
    return False


def _compare_packets_in_TCP_communication(found, source, destination):
    if (found[0] == source[0] and found[1] == source[1] and found[2] == source[2] and
        found[3] == source[3]) or (found[0] == destination[0] and found[1] == destination[1] and
                                   found[2] == destination[2] and found[3] == destination[3]):
        return True
    return False


def _get_packet_information(frame):
    pkt_inf = []
    pkt_inf.append(_find_src_ip_IPv4(frame))
    pkt_inf.append(_find_dst_ip_IPv4(frame))
    reformat_port = int(_find_src_TCP_app_protocol(frame), 16)
    pkt_inf.append(reformat_port)
    reformat_port = int(_find_dst_TCP_app_protocol(frame), 16)
    pkt_inf.append(reformat_port)
    return pkt_inf


def _check_if_its_TCP(frame):
    ether_type = _find_frame_type(frame)
    if ether_type == "ETHERNET II":
        second_layer_protocol = _find_second_eth_layer_protocol(frame)
        if second_layer_protocol == "IPv4":
            protocol = _find_IPv4_protocol(frame)
            if protocol == "TCP" or protocol == "UDP":
                return True
    return False


def _check_for_end_of_three_way_handshake(source_list, destination_list, tcp_pcap, order):  # hladam koniec
    # print("Source:", source_list, destination_list)
    # order = source_list[4]
    counter = 1
    source = []
    ending_packet = []
    for find_end in tcp_pcap:
        # print(counter)
        if counter < order:
            # print("check" ,counter)
            counter += 1  # prejdem na paket kde začala komunikácia
        else:
            tcp_frame = scapy.raw(find_end).hex()
            flag = _get_flags(tcp_frame)
            # print(flag)

            if flag == "010001":  # nasiel som FIN ACK, porovnavam, ci to patri mojej komunikácii a zistujem FIN ACK, ACK, FIN ACK, ACK
                # print(counter, flag, "found FIN, ACK")
                # tcp_frame = scapy.raw(tcp_frame).hex()
                found_FIN_ACK = False
                source.append(_find_src_ip_IPv4(tcp_frame))
                source.append(_find_dst_ip_IPv4(tcp_frame))
                reformat_port = int(_find_src_TCP_app_protocol(tcp_frame), 16)
                source.append(reformat_port)
                reformat_port = int(_find_dst_TCP_app_protocol(tcp_frame), 16)
                source.append(reformat_port)
                source.append(counter)
                # print(source)

                if (source[0] == source_list[0] and source[1] == source_list[1] and source[2] == source_list[2] and
                    source[3] == source_list[3]) or (
                        source[0] == destination_list[0] and source[1] == destination_list[1] and source[2] ==
                        destination_list[2] and source[3] == destination_list[
                            3]):  # nasiel som zhodu, skontrolujem, ci komunikácia ide ukoncit
                    found_FIN_ACK = True

                if found_FIN_ACK:  # idem hladat ACK od druheho paketu

                    counter_FIN_ACK = 1
                    for FIN_ACK in tcp_pcap:
                        # print(source, counter_FIN_ACK)
                        if counter_FIN_ACK < source[4]:
                            counter_FIN_ACK += 1
                        else:
                            FIN_ACK_frame = scapy.raw(FIN_ACK).hex()
                            flag_ACK = _get_flags(FIN_ACK_frame)
                            # print(source)
                            # print(flag_ACK)
                            if flag_ACK == "010100" or flag_ACK == "000100":  # found RST
                                # print("found rst")
                                ending_packet.append(_find_src_ip_IPv4(tcp_frame))
                                ending_packet.append(_find_dst_ip_IPv4(tcp_frame))
                                reformat_port = int(_find_src_TCP_app_protocol(tcp_frame), 16)
                                ending_packet.append(reformat_port)
                                reformat_port = int(_find_dst_TCP_app_protocol(tcp_frame), 16)
                                ending_packet.append(reformat_port)
                                ending_packet.append(counter_FIN_ACK)
                                _found_RST(tcp_pcap, source, ending_packet)

                            if flag_ACK == "010000":  # nasiel som ACK, zistujem, ci to patri mojej komunikácii
                                source_ACK = []
                                found_FIN_ACK = False
                                source_ACK.append(_find_src_ip_IPv4(FIN_ACK_frame))
                                source_ACK.append(_find_dst_ip_IPv4(FIN_ACK_frame))
                                reformat_port = int(_find_src_TCP_app_protocol(FIN_ACK_frame), 16)
                                source_ACK.append(reformat_port)
                                reformat_port = int(_find_dst_TCP_app_protocol(FIN_ACK_frame), 16)
                                source_ACK.append(reformat_port)
                                source_ACK.append(counter_FIN_ACK)
                                # print(source, source_ACK)

                                if source[0] == source_ACK[1] and source[1] == source_ACK[0] and source[2] == \
                                        source_ACK[3] and source[3] == source_ACK[2]:  # nasiel som ACK
                                    # print(source_ACK)
                                    found_FIN_ACK = True

                                if found_FIN_ACK:  # nasiel som FIN ACK, hladam dalsi FIN ACK od posledneho paketu
                                    found_FIN_ACK_2, source_for_ACK_2 = _find_FIN_ACK_2(tcp_pcap, source_ACK)

                                    if found_FIN_ACK_2:  # uz iba najst posledny ACK
                                        found_ACK_2, ending_packet = _find_ACK_2(tcp_pcap, source_for_ACK_2)

                                        if found_ACK_2:  # nasiel som koniec komunikácie, zakončila sa FIN ACK, ACK, FIN ACK, ACK
                                            # print(source_list, ending_packet)
                                            # ending_packet = source_for_ACK_2
                                            _def_TCP_communications_print(source_list, ending_packet, source_for_ACK_2,
                                                                          tcp_pcap)

                                # print(source, source_ACK)

                                # print("found ack", counter_FIN_ACK)

                            # print(counter_FIN_ACK, FIN_ACK_frame)
                            counter_FIN_ACK += 1

                    # print(flag)
                    # print(source, source_list, destination_list)
                source.clear()

            # print(tcp_frame)
        counter += 1


def _found_RST(tcp_pcap, source_list, ending_packet):
    destination_list = []
    destination_list.append(source_list[1])
    destination_list.append(source_list[0])
    destination_list.append(source_list[3])
    destination_list.append(source_list[2])
    # print(source_list)

    if (ending_packet[0] == source_list[0] and ending_packet[1] == source_list[1] and ending_packet[2] == source_list[2]
        and ending_packet[3] == source_list[3]) or (ending_packet[0] == destination_list[0] and
                                                    ending_packet[1] == destination_list[1] and
                                                    ending_packet[2] == destination_list[2] and
                                                    ending_packet[3] == destination_list[3]):
        print(ending_packet)


def _find_FIN_ACK_2(tcp_pcap, source):
    counter = 1
    # print(source)
    source_FIN_ACK = []
    for find_FIN_ACK in tcp_pcap:
        if counter < source[4]:
            counter += 1
        else:
            FIN_ACK_frame = scapy.raw(find_FIN_ACK).hex()
            # print(counter, FIN_ACK_frame)
            flag = _get_flags(FIN_ACK_frame)
            source_FIN_ACK = []
            if flag == "010001":  # found FIN_ACK, skontrolujem ci je to moja komunikácia
                # found_FIN_ACK = False
                source_FIN_ACK.append(_find_src_ip_IPv4(FIN_ACK_frame))
                source_FIN_ACK.append(_find_dst_ip_IPv4(FIN_ACK_frame))
                reformat_port = int(_find_src_TCP_app_protocol(FIN_ACK_frame), 16)
                source_FIN_ACK.append(reformat_port)
                reformat_port = int(_find_dst_TCP_app_protocol(FIN_ACK_frame), 16)
                source_FIN_ACK.append(reformat_port)
                source_FIN_ACK.append(counter)

                if source[0] == source_FIN_ACK[0] and source[1] == source_FIN_ACK[1] and source[2] == source_FIN_ACK[
                    2] and source[3] == source_FIN_ACK[
                    3]:  # nasiel som druhy FIN_ACK, uz iba ACK od druheho zdroja a mam kompletnu komunikáciu
                    # print(source_FIN_ACK)
                    return True, source_FIN_ACK

            counter += 1

    return False, source_FIN_ACK


def _find_ACK_2(tcp_pcap, source):
    # print(source)
    source_ACK_2 = []
    counter = 1
    for find_ACK_2 in tcp_pcap:
        if counter < source[4]:
            counter += 1
        else:
            ACK_2_frame = scapy.raw(find_ACK_2).hex()
            source_ACK_2 = []
            # print(counter,ACK_2_frame)
            flag = _get_flags(ACK_2_frame)
            if flag == "010000":
                source_ACK_2.append(_find_src_ip_IPv4(ACK_2_frame))
                source_ACK_2.append(_find_dst_ip_IPv4(ACK_2_frame))
                reformat_port = int(_find_src_TCP_app_protocol(ACK_2_frame), 16)
                source_ACK_2.append(reformat_port)
                reformat_port = int(_find_dst_TCP_app_protocol(ACK_2_frame), 16)
                source_ACK_2.append(reformat_port)
                source_ACK_2.append(counter)

                if source[0] == source_ACK_2[1] and source[1] == source_ACK_2[0] and source[2] == source_ACK_2[3] and \
                        source[3] == source_ACK_2[2]:  # nasiel som druhy ACK
                    # print(source, source_ACK_2)
                    return True, source_ACK_2

                # print(source, source_ACK_2)

                # print(flag)
            counter += 1

    return False, source_ACK_2


def _def_TCP_communications_print(source_packet, ending_packet, opposite_packet, tcp_pcap):
    start = 1
    end = ending_packet[4]
    # print(source_packet, ending_packet)
    tcp_packets_dictionary = {"complete comms": {"number comm": start,
                                                 "src_comm": source_packet[0],
                                                 "dst_comm": source_packet[1],
                                                 "packets": []}}
    for TCP_print in tcp_pcap:
        frame_flag = False
        if start < source_packet[4]:
            tcp_frame = scapy.raw(TCP_print).hex()
            # print(start, tcp_frame)
            start += 1
        elif start <= end:
            frame = scapy.raw(TCP_print).hex()
            # print(start, frame)
            frame_list = _get_the_needed_info_for_comparison(frame)
            frame_list.append(start)
            # print(frame_list)
            if (frame_list[0] == source_packet[0] and frame_list[1] == source_packet[1] and frame_list[2] ==
                source_packet[2] and frame_list[3] == source_packet[3]) or (frame_list[0] == opposite_packet[0] and
                                                                            frame_list[1] == opposite_packet[1] and
                                                                            frame_list[2] == opposite_packet[2] and
                                                                            frame_list[3] ==
                                                                            opposite_packet[3]):
                # print(frame_list)
                len_frame_pcap = int(len(tcp_frame))
                if len_frame_pcap >= 60:
                    len_frame_medium = len_frame_pcap
                    len_frame_medium += 4
                else:
                    len_frame_medium = 64

                frame_type = _find_frame_type(tcp_frame)
                source_mac = _find_source_mac(tcp_frame)
                destination_mac = _find_destination_mac(tcp_frame)
                ether_type = _find_second_eth_layer_protocol(tcp_frame)
                src_ip = _find_src_ip_IPv4(tcp_frame)
                dst_ip = _find_dst_ip_IPv4(tcp_frame)
                protocol = _find_IPv4_protocol(tcp_frame)
                src_port = _find_src_TCP_app_protocol(tcp_frame)
                dst_port = _find_dst_TCP_app_protocol(tcp_frame)
                app_protocol = _check_if_its_is_well_known_protocol(src_port, dst_port)
                src_port = int(src_port, 16)
                dst_port = int(dst_port, 16)
                formated_frame = _format_frame(tcp_frame)
                packet_dict = {"frame_number": start,
                               "len_frame_pcap": len_frame_pcap,
                               "len_frame_medium": len_frame_medium,
                               "frame_type": frame_type,
                               "src_mac": source_mac,
                               "dst_mac": destination_mac,
                               "ether_type": ether_type,
                               "src_ip": src_ip,
                               "dst_ip": dst_ip,
                               "protocol": protocol,
                               "src_port": src_port,
                               "dst_port": dst_port,
                               "app_protocol": app_protocol,
                               "hexa_frame": ruamel.yaml.scalarstring.LiteralScalarString(formated_frame)
                               }
                tcp_packets_dictionary["complete comms"]["packets"].append(packet_dict)
                # order += 1

                # pass

            start += 1

    # print(ending_packet)
    # print(tcp_packets_dictionary)
    # global_tcp_packet_list.append(tcp_packets_dictionary)
    #print(global_tcp_packet_list)
    with open('tcp_communications.yaml', 'r+') as output_stream:
        yaml = ruamel.yaml.YAML()
        yaml.default_flow_style = False
        # yaml.dump(global_tcp_packet_list, output_stream)
        # yaml.dump(tcp_packets_dictionary, output_stream)

    # with open('tcp_communications.yaml','r') as yamlfile:
    #   cur_yaml = yaml.safe_load(yamlfile)
    # if cur_yaml:
    #   with open('tcp_communications.yaml','w') as yamlfile:
    # yaml.dump(tcp_packets_dictionary, yamlfile)

    pass


def _get_the_needed_info_for_comparison(frame):
    list = []
    list.append(_find_src_ip_IPv4(frame))
    list.append(_find_dst_ip_IPv4(frame))
    reformat_port = int(_find_src_TCP_app_protocol(frame), 16)
    list.append(reformat_port)
    reformat_port = int(_find_dst_TCP_app_protocol(frame), 16)
    list.append(reformat_port)
    return list


def _get_flags(frame):
    flag = int(frame[93:96], 16)
    # print("int flag:" ,flag)
    flag = (bin(flag)[2:].zfill(8)[2:])
    # print(flag)
    return flag


def _check_if_switch_protocol_exists(protocol):
    with open("Protocols/app_protocol.yaml", "r") as stream:  # TCP/UDP protokoly
        get_file = (yaml.safe_load(stream))
        if protocol in get_file.values():
            return True, "TCP/UDP"
    with open("Protocols/protocol.yaml", "r") as stream:  # IPv4 protokoly
        get_file = (yaml.safe_load(stream))
        if protocol in get_file.values():
            return True, "IPv4"
    with open("Protocols/ether_type.yaml", "r") as stream:  # ether type like ARP, IPv4 etc.
        get_file = (yaml.safe_load(stream))
        if protocol in get_file.values():
            return True, "Ether_type"

    return False, None


def _start_analyzing_TFTP(pcap):
    order = 1

    for TFTP_comm in pcap:
        TFTP_frame = scapy.raw(TFTP_comm).hex()
        if _check_if_its_UDP(TFTP_frame):
            app_protocol = _find_dst_TCP_app_protocol(TFTP_frame)
            # print(app_protocol)
            app_protocol = int(app_protocol, 16)
            # print(app_protocol)
            if app_protocol == 69:
                first_source_port = int(_find_src_TCP_app_protocol(TFTP_frame), 16)
                # print(first_source_port)
                first_packet = _get_packet_information(TFTP_frame)
                _find_TFTP_comm(first_packet, pcap)
                # print(first_packet)


def _find_TFTP_comm(original, pcap):
    order = 1
    comm = False
    for TFTP in pcap:
        TFTP_frame = scapy.raw(TFTP).hex()
        if _check_if_its_UDP(TFTP_frame):
            frame_info = _get_packet_information(TFTP_frame)
            if frame_info[0] == original[1] and frame_info[1] == original[0] and frame_info[3] == original[
                2]:  # porovnavam vsetko okrem jedneho portu
                # print(frame_info)
                second_packet = frame_info
                comm = True
            if comm and frame_info[0] == second_packet[1] and frame_info[1] == second_packet[0] and frame_info[
                2] == second_packet[3] and frame_info[3] == second_packet[2]:
                first_packet = frame_info
                break
                # print(first_packet, second_packet)
                # print(order)

        order += 1
    #print(original)
    _print_TFTP(first_packet, second_packet, original, pcap)


def _print_TFTP(first_packet, second_packet, original_packet, pcap):
    # print(first_packet, second_packet, original_packet)
    global global_TFTP_counter
    order = 1
    udp_packets_dictionary = {"complete comms": {"number comm": global_TFTP_counter,
                                                 "src_comm": original_packet[0],
                                                 "dst_comm": original_packet[1],
                                                 "packets": []}}

    # udp_packets_dictionary["complete comms"]["packets"].append(packet_dict)
    # order = 1

    found_checkpoint = False

    for TFTP in pcap:
        TFTP_frame = scapy.raw(TFTP).hex()
        if _check_if_its_UDP(TFTP_frame):
            frame = _get_packet_information(TFTP_frame)
            if frame == original_packet:
                found_checkpoint = True
                len_frame_pcap = int(len(TFTP_frame))
                if len_frame_pcap >= 60:
                    len_frame_medium = len_frame_pcap
                    len_frame_medium += 4
                else:
                    len_frame_medium = 64
                list_for_orignal, formated_frame, app_protocol = _get_UDP_info(TFTP_frame)

                packets_dictionary = {"frame_number": order,
                                      "len_frame_pcap": len_frame_pcap,
                                      "len_frame_medium": len_frame_medium,
                                      "frame_type": list_for_orignal[0],
                                      "src_mac": list_for_orignal[1],
                                      "dst_mac": list_for_orignal[2],
                                      "ether_type": "ETHERNET II",
                                      "src_ip": list_for_orignal[3],
                                      "dst_ip": list_for_orignal[4],
                                      "protocol": list_for_orignal[5],
                                      "src_port": list_for_orignal[6],
                                      "dst_port": list_for_orignal[7],
                                      "app_protocol": app_protocol,
                                      "hexa_frame": ruamel.yaml.scalarstring.LiteralScalarString(formated_frame)
                                      }

                udp_packets_dictionary["complete comms"]["packets"].append(packets_dictionary)
                #order += 1

            if found_checkpoint:
                if frame == first_packet or frame == second_packet:
                    len_frame_pcap = int(len(TFTP_frame))
                    if len_frame_pcap >= 60:
                        len_frame_medium = len_frame_pcap
                        len_frame_medium += 4
                    else:
                        len_frame_medium = 64
                    list_for_rest, formated_frame, app_protocol = _get_UDP_info(TFTP_frame)
                    packet_dict = {"frame_number": order,
                                   "len_frame_pcap": len_frame_pcap,
                                   "len_frame_medium": len_frame_medium,
                                   "frame_type": list_for_rest[0],
                                   "src_mac": list_for_rest[1],
                                   "dst_mac": list_for_rest[2],
                                   "ether_type": "ETHERNET II",
                                   "src_ip": list_for_rest[3],
                                   "dst_ip": list_for_rest[4],
                                   "protocol": list_for_rest[5],
                                   "src_port": list_for_rest[6],
                                   "dst_port": list_for_rest[7],
                                   "app_protocol": app_protocol,
                                   "hexa_frame": ruamel.yaml.scalarstring.LiteralScalarString(formated_frame)
                                   }
                    # print(order, frame_to_compare)
                    udp_packets_dictionary["complete comms"]["packets"].append(packet_dict)


               # for TFTP2 in pcap:
                    #    in_loop_order = order
                    #rame_2 = scapy.raw(TFTP2).hex()
                    #frame_to_compare = _get_packet_information(frame_2)
                    # if frame_to_compare == first_packet or frame_to_compare == second_packet:
                    #   len_frame_pcap = int(len(TFTP_frame))
                    #   if len_frame_pcap >= 60:
                    #       len_frame_medium = len_frame_pcap
                    #       len_frame_medium += 4
                    #   else:
                    #       len_frame_medium = 64
                    #   list_for_rest, formated_frame, app_protocol = _get_UDP_info(frame_2)
                    #   packet_dict = {"frame_number": in_loop_order,
                    #                  "len_frame_pcap": len_frame_pcap,
                    #                  "len_frame_medium": len_frame_medium,
                    ###                  "frame_type": list_for_rest[0],
                    #                "src_mac": list_for_rest[1],
                    #                  "dst_mac": list_for_rest[2],
                    #                  "ether_type": "ETHERNET II",
                    #                  "src_ip": list_for_rest[3],
                    #####                  "dst_ip": list_for_rest[4],
                    #              "protocol": list_for_rest[5],
                    #                  "src_port": list_for_rest[6],
                    #                  "dst_port": list_for_rest[7],
                    #                  "app_protocol": app_protocol,
                    #                  "hexa_frame": ruamel.yaml.scalarstring.LiteralScalarString(formated_frame)
                    #                  }
                        # print(order, frame_to_compare)
                    #   udp_packets_dictionary["complete comms"]["packets"].append(packet_dict)
            #   in_loop_order += 1
        order += 1

                #order += 1
    global_TFTP_packet_list.append(udp_packets_dictionary)
    # print(global_TFTP_packet_list)
    with open('udp_communications.yaml', "r+") as output_stream:
        yaml = ruamel.yaml.YAML()
        yaml.default_flow_style = False
        yaml.dump(global_TFTP_packet_list, output_stream)
    global_TFTP_counter += 1


def _check_if_its_UDP(frame):
    ether_type = _find_frame_type(frame)
    if ether_type == "ETHERNET II":
        second_layer_protocol = _find_second_eth_layer_protocol(frame)
        if second_layer_protocol == "IPv4":
            protocol = _find_IPv4_protocol(frame)
            if protocol == "UDP":
                return True
    return False


def _get_UDP_info(frame):
    list = []
    #print(frame)
    #print(type(frame))
   # list.append(_find_frame_type(frame))
    list.append(_find_source_mac(frame))
    list.append(_find_destination_mac(frame))
    list.append(_find_second_eth_layer_protocol(frame))
    list.append(_find_src_ip_IPv4(frame))
    list.append(_find_dst_ip_IPv4(frame))
    list.append(_find_IPv4_protocol(frame))
    src_port = _find_src_TCP_app_protocol(frame)
    dst_port = _find_dst_TCP_app_protocol(frame)
    src_port = int(src_port, 16)
    dst_port = int(dst_port, 16)
    list.append(src_port)
    list.append(dst_port)
    app_protocol = _check_if_its_is_well_known_protocol(src_port, dst_port)
    formated_frame = _format_frame(frame)
    #print(list)
    return list, formated_frame, app_protocol


if __name__ == '__main__':
    # fileName = input("Zadajte názov súboru: ")
    # pcap = scapy.rdpcap
    switch_flag = False
    protocol_origin = None
    switch_protocol = None
    switch = input("Chcete analyzovať aj komunikáciu? (-p)")
    if switch == "-p":
        while not switch_flag:
            switch_protocol = input("Zvolte si typ protokolu: ")
            switch_flag, protocol_origin = _check_if_switch_protocol_exists(switch_protocol)
            if not switch_flag:
                print("Zadali ste zly protokol")
    # print(switch_protocol)
    # switch_flag = False
    pcap = scapy.rdpcap(
        "pcap_files/trace-15.pcap")  # NAZOV SEM!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    # if switch_protocol in

    # print(switch_flag)

    if switch == "-p":
        if switch_protocol == "HTTP" or switch_protocol == "TELNET" or switch_protocol == "SSH" or switch_protocol == \
                "FTP-CONTROl" or switch_protocol == "FTP-DATA":
            _start_to_analyze_TCP_communication(pcap)
        if switch_protocol == "TFTP":
            _start_analyzing_TFTP(pcap)

    order = 1
    initial_dictionary = {'name': 'PKS2022/23',
                          'pcap_name': 'all.cap'}
    packets_dictionary = {"packets": []}
    ipv4_packets_dictionary = {"ipv4_senders": []}
    max_packets_dictionary = {"max_send_packets_by": []}
    unique_src_ip_list = []
    unique_counter = []
    filtered_list = []

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
            if not switch_flag:
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
            if not switch_flag:
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

                if not switch_flag:
                    packets_dictionary["packets"].append(frames_dictionary)
                order += 1

            # print(second_layer_protocol)
            elif second_layer_protocol == "ARP":
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
                if not switch_flag:
                    packets_dictionary["packets"].append(frames_dictionary)
                if switch_flag and switch_protocol == "ARP":
                    packets_dictionary["packets"].append(frames_dictionary)
                order += 1
                # if switch_flag and protocol == "ARP":
                #   packets_dictionary

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
                if not switch_flag:
                    packets_dictionary["packets"].append(frames_dictionary)
                if switch_flag and switch_protocol == "IPv6":
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
                    # print(app_protocol)

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
                    if not switch_flag:
                        packets_dictionary["packets"].append(frames_dictionary)
                    # print(switch_flag, protocol_origin, app_protocol)
                    # print(app_protocol)
                    # print(switch_flag, protocol_origin, switch_protocol, protocol)
                    if switch_flag and protocol_origin == "TCP/UDP" and switch_protocol == app_protocol:
                        # print(switch_protocol)
                        packets_dictionary["packets"].append(frames_dictionary)
                    if switch_flag and protocol_origin == "IPv4" and switch_protocol == protocol:
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
                    if not switch_flag:
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
                if not switch_flag:
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
