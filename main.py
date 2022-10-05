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


def _find_ethernet_type(frame):
    typeInt = int(frame[24:28], 16)
    if typeInt >= 1536:
        return "ETHERNET II"
    elif typeInt <= 1500 and frame[28:32] == "ffff":
        return "IEE 802.3 - Raw"
    elif typeInt <= 1500 and frame[28:32] == "aaaa":
        return "IEE 802.3 s LLC a SNAP"
    elif typeInt <= 1500:
        return "IEE 802.3 LLC"


if __name__ == '__main__':

    # fileName = input("Zadajte názov súboru: ")
    # pcap = scapy.rdpcap(fileName)
    pcap = scapy.rdpcap("pcap_files/eth-1.pcap")
    order = 1
    for pkt in pcap:
        frameInHex = scapy.raw(pkt).hex()
        print(order)
        print("Frame: ", frameInHex)
        destination_mac = _find_destination_mac(frameInHex)
        print("Destination MAC: ", destination_mac)
        source_mac = _find_source_mac(frameInHex)
        print("Source MAC: ", source_mac)
        ethernet_type = _find_ethernet_type(frameInHex)
        if ethernet_type == "ETHERNET II":
            print("Ethernet II")
        elif ethernet_type == "raw":
            print("IEE 802.3 - Raw")
        elif ethernet_type == "IEE 802.3 s LLC a SNAP":
            print("IEE 802.3 s LLC a SNAP")
        elif ethernet_type == "IEE 802.3 LLC":
            print("IEE 802.3 LLC")

        frames_dictionary = {'name': 'PKS2022/23',
                             'pcap_name': 'all.cap',
                             "packets": {
                                 "frame_number": order,
                                 "frame_type": ethernet_type,
                                 "src_mac": source_mac,
                                 "dst_mac": destination_mac,
                                 "hexa_frame": frameInHex,
                             }}


        # print(frames_dictionary)
        # with open(r'schema-task-1.yaml', 'w') as file:
        #   documents = yaml.dump(frames_dictionary, file)

        with open('frames.yaml', 'r+') as output_stream:
            documents = yaml.safe_load(output_stream)
            documents = yaml.dump(frames_dictionary, output_stream, default_flow_style=False, sort_keys=False)

        # print("Name: PKS2022/23\n"
            #     "pcap_name: all.pcap\n"
            # "packets: \n"
            # " - frame_number: ", order, "\n"
            #                             "   len_frame_pcap: ", "\n"
            #                                                    "   len_frame_medium: ", "\n"
            #                                                                             "   frame_type: ",
            # ethernet_type, "\n"
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
        order += 1
