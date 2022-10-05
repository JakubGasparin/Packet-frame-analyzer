import scapy.all as scapy
import yaml


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
        return "IEE 802.3 s LLC a SNAP"
    elif typeInt <= 1500:
        return "IEE 802.3 LLC"


def _find_sap_type(frame):
    typeInt = int(frame[24:28], 16)
    pass


if __name__ == '__main__':

    # fileName = input("Zadajte názov súboru: ")
    # pcap = scapy.rdpcap(fileName)
    pcap = scapy.rdpcap("pcap_files/eth-3.pcap")
    order = 1
    initial_dictionary = {'name': 'PKS2022/23',
                          'pcap_name': 'all.cap'}
    packets_dictionary = {"packets": []}

    with open("frames.yaml", "w") as file:
        init_file = yaml.dump(initial_dictionary, file, default_flow_style=False, sort_keys=False)

    for pkt in pcap:
        len_frame_cap = len(pkt)
        frameInHex = scapy.raw(pkt).hex()
        destination_mac = _find_destination_mac(frameInHex)
        source_mac = _find_source_mac(frameInHex)
        frame_type = _find_frame_type(frameInHex)

        if frame_type == "IEE 802.3 - Raw" or frame_type == "IEE 802.3 s LLC a SNAP" or frame_type == "IEE 802.3 LLC":
            sap = _find_sap_type(frameInHex)

        frames_dictionary = {"frame_number": order,
                             "len_frame_cap": len_frame_cap,
                             "frame_type": frame_type,
                             "src_mac": source_mac,
                             "dst_mac": destination_mac,
                             "string": frameInHex}

        packets_dictionary["packets"].append(frames_dictionary)
        order += 1

    with open('frames.yaml', 'r+') as output_stream:
        documents = yaml.safe_load(output_stream)
        documents = yaml.dump(packets_dictionary, output_stream, default_flow_style=False, sort_keys=False)

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
