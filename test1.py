import os
import tkinter as tk
from tkinter import ttk
from threading import Thread
from scapy.all import sniff

root = None
packet_text = None
keep_sniffing = True
save_packets = tk.BooleanVar()
filename = tk.StringVar()
seen_packets = set()

def packet_callback(packet):
    global root
    global packet_text
    global keep_sniffing
    global save_packets
    global filename

    if not keep_sniffing:
        return 

    packet_identifier = packet.summary()

    if packet_identifier not in seen_packets:
        if save_packets.get():
            with open(filename.get(), "a") as log_file:
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

                json.dump(packet_dict, log_file,indent=4)
                log_file.write("\n")

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

def on_closing():
    stop_sniffing()
    os._exit(0)

root = tk.Tk()
packet_text = tk.Text(root)

iface = tk.StringVar()
iface.set('eth0')

iface_label = tk.Label(root, text="Select network interface:")
iface_label.pack()

iface_option = ttk.Combobox(root, textvariable=iface)
iface_option['values'] = ('eth0', 'wlan0')
iface_option.pack()

save_packets_check = tk.Checkbutton(root, text="Save packets", variable=save_packets)
save_packets_check.pack()

filename_entry = tk.Entry(root, textvariable=filename)
filename_entry.pack()

start_button = tk.Button(root, text="Start", command=start_sniffing)
start_button.pack()

stop_button = tk.Button(root, text="Stop", command=stop_sniffing)
stop_button.pack()

root.protocol("WM_DELETE_WINDOW", on_closing)

packet_text.pack()

root.mainloop()
