import tkinter as tk
from tkinter import ttk, messagebox, font
from threading import Thread
from scapy.all import sniff, Ether, ARP, IP, ICMP, TCP, UDP
import json
from scapy.packet import Raw


keep_sniffing = True
seen_packets = set()
packets = []
filter_packets = False
is_reassembled = False
fragments = {}
reassembled_packets = []

def toggle_filter():
    global filter_packets
    global packets
    global tree
    filter_packets = not filter_packets

    # 清空 Treeview
    for i in tree.get_children():
        tree.delete(i)

    # 重新处理已经接收到的数据包
    for packet in packets:
        source_ip = packet["Source IP"]
        destination_ip = packet["Destination IP"]

        if filter_packets:
            if source_ip_filter.get() and source_ip != source_ip_filter.get():
                continue
            if destination_ip_filter.get() and destination_ip != destination_ip_filter.get():
                continue

        # 将符合条件的数据包添加到 Treeview
        tree.insert('', 'end', values=(packet["Timestamp"], source_ip, destination_ip, packet["Protocol"], packet["Function"]))


def packet_callback(packet):
    global root
    global tree
    global keep_sniffing
    global packets

    if not keep_sniffing:
        return 

    packet_identifier = packet.summary()

    packet_dict = {}
    packet_dict["Packet Identifier"] = packet_identifier
    packet_dict["Timestamp"] = packet.time
    packet_dict["Length"] = len(packet)
    packet_dict["Load"] = packet.load.decode('utf-8', 'ignore') if packet.haslayer(Raw) else None


    source_ip = ''
    destination_ip = ''
    protocol = ''
    function = packet_identifier
    source_port = None
    destination_port = None

    if packet.haslayer(Ether):
        source_mac = packet[Ether].src
        destination_mac = packet[Ether].dst

    if packet.haslayer(ARP):
        source_ip = packet[ARP].psrc
        destination_ip = packet[ARP].pdst
        protocol = "ARP"

    elif packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol = "IP"
        ip_id = packet[IP].id  # 获取IP数据包的ID

        if packet.haslayer(ICMP):
            protocol = "ICMP"

        elif packet.haslayer(TCP):
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif packet.haslayer(UDP):
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport
            
        ip_id = packet[IP].id
        ip_frag = packet[IP].frag
        if 'MF' in packet[IP].flags or packet[IP].frag > 0:
            if ip_id not in fragments:
                fragments[ip_id] = {}
            fragments[ip_id][ip_frag] = packet[IP].payload

    packet_dict["Source IP"] = source_ip
    packet_dict["Destination IP"] = destination_ip
    packet_dict["Protocol"] = protocol
    packet_dict["Function"] = function
    packet_dict["Source Port"] = source_port
    packet_dict["Destination Port"] = destination_port
    packet_dict["IP ID"] = ip_id  # 将IP ID添加到数据包字典中
    # 过滤逻辑
    if filter_packets:
        if source_ip_filter.get() and source_ip != source_ip_filter.get():
            return
        if destination_ip_filter.get() and destination_ip != destination_ip_filter.get():
            return

    packets.append(packet_dict)

    seen_packets.add(packet_identifier)
    root.after(0, lambda: tree.insert('', 'end', values=(packet.time, source_ip, destination_ip, protocol, function)))



def start_sniffing():
    global sniff_thread
    global keep_sniffing
    keep_sniffing = True
    sniff_thread = Thread(target=sniff, kwargs={'iface': iface.get(), 'prn': packet_callback, 'store': 0}, daemon=True)
    sniff_thread.start()

def stop_sniffing():
    global keep_sniffing
    keep_sniffing = False

def save_packets():
    global packets
    global filename
    if filename.get() == "":
        messagebox.showerror("Error", "Please enter a filename.")
        return
    with open(filename.get(), "w") as log_file:
        for packet in packets:
            json.dump(packet, log_file, indent=4)
            log_file.write("\n")
    packets = []

def on_closing():
    stop_sniffing()
    root.destroy()

def show_packet(event):
    global packet_text
    global packets
    global reassembled_packets
    global is_reassembled
    curselection = tree.focus()
    if curselection:  # 如果有选中的项
        index = tree.index(curselection)
        packet_text.delete(1.0, tk.END)
        if is_reassembled:
            packet_text.insert(tk.END, "IP Header: " + str(reassembled_packets[index][IP]) + "\n")  # 显示IP头
            packet_text.insert(tk.END, "IP ID: " + str(reassembled_packets[index][IP].id) + "\n")  # 显示IP头的标识字段
            packet_text.insert(tk.END, reassembled_packets[index].summary())
        else:
            packet_text.insert(tk.END, json.dumps(packets[index], indent=4))
            if "IP ID" in packets[index]:  # 如果数据包中有 "IP ID"，则显示它
                packet_text.insert(tk.END, "\nIP ID: " + str(packets[index]["IP ID"]))
            if "IP" in packets[index]:  # 如果数据包中有 "IP"，则显示它
                packet_text.insert(tk.END, "\nIP Flags: " + str(packets[index]["IP"]["flags"]))
    else:  # 如果没有选中的项
        packet_text.delete(1.0, tk.END)
        packet_text.insert(tk.END, "No packet selected.")




def reassemble_fragments():
    global fragments
    global reassembled_packets
    global is_reassembled
    global packets

    # 清空 Treeview
    for i in tree.get_children():
        tree.delete(i)

    if is_reassembled:
        # 如果已经进行了重组，那么就显示所有的数据报
        for packet in packets:
            tree.insert('', 'end', values=(packet["Timestamp"], packet["Source IP"], packet["Destination IP"], packet["Protocol"], packet["Function"]))
        is_reassembled = False
    else:
        # 否则，就显示重组后的数据报
        for ip_id in fragments:
            if len(fragments[ip_id]) == max(fragments[ip_id].keys()) + 1:  # 确保所有的分片都已经收到
                # 找到与当前数据包相对应的原始数据包
                original_packet = next(packet for packet in packets if packet["IP ID"] == ip_id)
                reassembled_packet = IP(id=ip_id)
                reassembled_packet.src = original_packet["Source IP"]
                reassembled_packet.dst = original_packet["Destination IP"]
                reassembled_packet.payload = IP(b''.join(bytes(fragments[ip_id][i]) for i in sorted(fragments[ip_id])))
                reassembled_packets.append(reassembled_packet)

        for packet in reassembled_packets:
            tree.insert('', 'end', values=(packet.time, packet.src, packet.dst, packet.proto, packet.summary()))
        is_reassembled = True


root = tk.Tk()
root.title("Packet Sniffer")
root.geometry("1400x800")
my_font = font.Font(family="Helvetica", size=14)
packet_text = tk.Text(root, width=80, height=10, font=my_font)
filename = tk.StringVar()

# 设置行和列的权重，使得它们可以随窗口尺寸变化
for i in range(6):
    root.grid_rowconfigure(i, weight=1, minsize=50)
for i in range(2):
    root.grid_columnconfigure(i, weight=1, minsize=100)

style = ttk.Style()
style.configure("Treeview", columnwidths=(100, 100, 100, 30, 170))
# 创建一个 Treeview
tree = ttk.Treeview(root, columns=('Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Function'), show='headings', style="Treeview")

# 创建一个垂直滚动条并将其与 Treeview 控件关联
v_scrollbar = ttk.Scrollbar(root, orient="vertical", command=tree.yview)
tree.configure(yscrollcommand=v_scrollbar.set)
v_scrollbar.grid(row=4, column=2, sticky='ns')

# 创建一个水平滚动条并将其与 Treeview 控件关联
#h_scrollbar = ttk.Scrollbar(root, orient="horizontal", command=tree.xview)
#tree.configure(xscrollcommand=h_scrollbar.set)
#h_scrollbar.grid(row=5, column=0, columnspan=2, sticky='ew')

tree.grid(row=4, column=0, columnspan=2, sticky="nsew")

source_ip_filter = tk.StringVar()
destination_ip_filter = tk.StringVar()

# 创建一个新的 Frame 来包含 Label 和 Entry
source_ip_frame = tk.Frame(root)
source_ip_frame.grid(row=3, column=0, sticky="ew")

source_ip_label = tk.Label(source_ip_frame, text="Filter by Source IP:", font=my_font)
source_ip_label.pack(side="left")

source_ip_entry = tk.Entry(source_ip_frame, textvariable=source_ip_filter, font=my_font)
source_ip_entry.pack(side="left", fill="x", expand=True)

# 创建一个新的 Frame 来包含 Label 和 Entry
destination_ip_frame = tk.Frame(root)
destination_ip_frame.grid(row=3, column=1, sticky="ew")

destination_ip_label = tk.Label(destination_ip_frame, text="Filter by Destination IP:", font=my_font)
destination_ip_label.pack(side="left")

destination_ip_entry = tk.Entry(destination_ip_frame, textvariable=destination_ip_filter, font=my_font)
destination_ip_entry.pack(side="left", fill="x", expand=True)
filter_frame = tk.Frame(root)
filter_frame.grid(row=3, column=2, sticky="ew")

# 新增的 Frame
reassemble_frame = tk.Frame(root)
reassemble_frame.grid(row=2, column=2, sticky="ew")

# 新增的按钮
reassemble_button = tk.Button(reassemble_frame, text="Reassemble", command=reassemble_fragments, bg="yellow", fg="black", font=my_font)
reassemble_button.pack(side="left", fill="x", expand=True)

# 新增的按钮
filter_button = tk.Button(filter_frame, text="Filter", command=toggle_filter, bg="yellow", fg="black", font=my_font)
filter_button.pack(side="left", fill="x", expand=True)

# 设置每列的标题
tree.heading('Timestamp', text='Timestamp')
tree.heading('Source IP', text='Source IP')
tree.heading('Destination IP', text='Destination IP')
tree.heading('Protocol', text='Protocol')
tree.heading('Function', text='Function')

# 设置每列的宽度
tree.column('Timestamp', width=100)
tree.column('Source IP', width=100)
tree.column('Destination IP', width=100)
tree.column('Protocol', width=100)
tree.column('Function', width=100)

iface = tk.StringVar()
iface.set('eth0')

iface_label = tk.Label(root, text="Select network interface:", font=my_font)
iface_label.grid(row=0, column=0, sticky="w")

iface_option = ttk.Combobox(root, textvariable=iface, font=my_font)
iface_option['values'] = ('eth0', 'wlan0')
iface_option.grid(row=0, column=1, sticky="we")

filename_label = tk.Label(root, text="Enter filename:", font=my_font)
filename_label.grid(row=1, column=0, sticky="w")

filename_entry = tk.Entry(root, textvariable=filename, font=my_font)
filename_entry.grid(row=1, column=1, sticky="we")

# 将 save_button 的位置从 (3, 0) 改为 (1, 2)
save_button = tk.Button(root, text="Save", command=save_packets, bg="blue", fg="white", font=my_font)
save_button.grid(row=1, column=2, sticky="w")

start_button = tk.Button(root, text="Start", command=start_sniffing, bg="green", fg="white", font=my_font)
start_button.grid(row=2, column=0, sticky="w")

stop_button = tk.Button(root, text="Stop", command=stop_sniffing, bg="red", fg="white", font=my_font)
stop_button.grid(row=2, column=1, sticky="w")

tree.grid(row=4, column=0, columnspan=2, sticky="nsew")
tree.bind('<<TreeviewSelect>>', show_packet)

packet_text.grid(row=5, column=0, columnspan=2, sticky="nsew")

root.protocol("WM_DELETE_WINDOW", on_closing)

root.mainloop()


