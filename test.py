import os
import tkinter as tk
from tkinter import ttk
from threading import Thread
from scapy.all import sniff, Ether, ARP, IP, ICMP, TCP, UDP
import json

root = tk.Tk()
packet_text = tk.Text(root)

keep_sniffing = True
filename = tk.StringVar()
seen_packets = set()
packets = []

def packet_callback(packet):
    global root
    global packet_text
    global keep_sniffing
    global packets

    if not keep_sniffing:
        return 

    packet_identifier = packet.summary()

    if packet_identifier not in seen_packets:
        packet_dict = {}
        packet_dict["Packet Identifier"] = packet_identifier
        packet_dict["Timestamp"] = packet.time

        if packet.haslayer(Ether):
            packet_dict["Ethernet Layer"] = {
                "Type": "Ethernet",
                "Source MAC": packet[Ether].src,
                "Destination MAC": packet[Ether].dst
            }

        if packet.haslayer(ARP):
            packet_dict["ARP Layer"] = {
                "Type": "ARP",
                "Source IP": packet[ARP].psrc,
                "Destination IP": packet[ARP].pdst,
                "Source MAC": packet[ARP].hwsrc,
                "Destination MAC": packet[ARP].hwdst
            }

        elif packet.haslayer(IP):
            packet_dict["IP Layer"] = {
                "Type": "IP",
                "Source IP": packet[IP].src,
                "Destination IP": packet[IP].dst
            }

            if packet.haslayer(ICMP):
                packet_dict["ICMP Layer"] = {
                    "Type": packet[ICMP].type,
                    "Code": packet[ICMP].code
                }

            elif packet.haslayer(TCP):
                packet_dict["TCP Layer"] = {
                    "Source Port": packet[TCP].sport,
                    "Destination Port": packet[TCP].dport
                }

            elif packet.haslayer(UDP):
                packet_dict["UDP Layer"] = {
                    "Source Port": packet[UDP].sport,
                    "Destination Port": packet[UDP].dport
                }

        for layer in packet.layers():
            layer_dict = {}
            for field in layer.fields_desc:
                field_value = packet.getfieldval(field.name)
                if not isinstance(field_value, (dict, list, tuple, str, int, float, bool, type(None))):
                    field_value = str(field_value)
                layer_dict[field.name] = field_value
            packet_dict["{} Headers".format(layer.__name__)] = layer_dict

        packets.append(packet_dict)

        seen_packets.add(packet_identifier)
        packet_info = packet.summary()
        root.after(0, packet_text.insert, tk.END, packet_info + '\n')

def start_sniffing():
    global sniff_thread
    global keep_sniffing
    keep_sniffing = True
    sniff_thread = Thread(target=sniff, kwargs={'iface': iface.get(), 'prn': packet_callback, 'store': 0})
    sniff_thread.start()

def stop_sniffing():
    global keep_sniffing
    keep_sniffing = False

def save_packets():
    global packets
    global filename
    with open(filename.get(), "w") as log_file:
        for packet in packets:
            json.dump(packet, log_file, indent=4)
            log_file.write("\n")
    packets = []

def on_closing():
    stop_sniffing()
    os._exit(0)

iface = tk.StringVar()
iface.set('eth0')

iface_label = tk.Label(root, text="Select network interface:")
iface_label.pack()

iface_option = ttk.Combobox(root, textvariable=iface)
iface_option['values'] = ('eth0', 'wlan0')
iface_option.pack()

filename_entry = tk.Entry(root, textvariable=filename)
filename_entry.pack()

start_button = tk.Button(root, text="Start", command=start_sniffing)
start_button.pack()

stop_button = tk.Button(root, text="Stop", command=stop_sniffing)
stop_button.pack()

save_button = tk.Button(root, text="Save", command=save_packets)
save_button.pack()

root.protocol("WM_DELETE_WINDOW", on_closing)

packet_text.pack()

root.mainloop()

