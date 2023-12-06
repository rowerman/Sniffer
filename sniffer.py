import tkinter as tk
from tkinter import ttk, messagebox, font
from threading import Thread
from scapy.all import sniff, Ether, ARP, IP, ICMP, TCP, UDP,IPv6
import json
from scapy.packet import Raw
import datetime
from ttkthemes import ThemedTk
import binascii

keep_sniffing = True
seen_packets = set()
packets = []
filter_packets = False
is_reassembled = False
is_filtered = False
fragments = {}
reassembled_packets = []
packet_id = 0
reassembled_packet_id = 0

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
        protocol = packet["Protocol"]

        if filter_packets:
            if source_ip_filter.get() and source_ip != source_ip_filter.get():
                continue
            if destination_ip_filter.get() and destination_ip != destination_ip_filter.get():
                continue
            if protocol_filter.get() != 'All' and protocol != protocol_filter.get():
            	continue

        # 将符合条件的数据包添加到 Treeview
        tree.insert('', 'end', values=(packet["ID"], packet["Timestamp"], source_ip, destination_ip, packet["Protocol"], packet["Function"]))


def packet_callback(packet):
    global root
    global tree
    global keep_sniffing
    global packets
    global packet_id
    ip_id = None

    if not keep_sniffing:
        return 
    packet_identifier = packet.summary()
    if packet_identifier not in seen_packets:
        packet_dict = {}
        packet_dict["Packet Identifier"] = packet_identifier
        packet_dict["Timestamp"] = packet.time
        packet_dict["Length"] = len(packet)
        if packet.haslayer(Raw):
            load = packet[Raw].load.decode('utf-8', 'ignore')
            if 'GET' in load or 'POST' in load:
                packet_dict["HTTP Method"] = load.split(' ')[0]
                packet_dict["HTTP Path"] = load.split(' ')[1]
            else:
                packet_dict["Load"] = binascii.hexlify(packet.load).decode()
        else:
            packet_dict["Load"] = None

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
            
        elif packet.haslayer(IPv6):
            source_ip = packet[IPv6].src
            destination_ip = packet[IPv6].dst
            protocol = "IPv6"


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
            if packet[IP].flags.DF == False:
                if ip_id not in fragments:
                    fragments[ip_id] = {}
                fragments[ip_id][ip_frag] = packet[IP].payload
                
        packet_id += 1
        packet_dict["ID"] = packet_id
        packet_dict["Source IP"] = source_ip
        packet_dict["Destination IP"] = destination_ip
        packet_dict["Protocol"] = protocol
        packet_dict["Function"] = function
        packet_dict["Source Port"] = source_port
        packet_dict["Destination Port"] = destination_port
        packet_dict["IP ID"] = ip_id  # 将IP ID添加到数据包字典中
        packet_dict["IP DF flag"] = packet[IP].flags.DF if packet.haslayer(IP) else None
        packet_dict["IP MF flag"] = packet[IP].flags.MF if packet.haslayer(IP) else None
        
        # 过滤逻辑
        if filter_packets:
            if source_ip_filter.get() and source_ip != source_ip_filter.get():
                return
            if destination_ip_filter.get() and destination_ip != destination_ip_filter.get():
                return
            if protocol_filter.get() != 'All' and protocol != protocol_filter.get():
            	return

        packets.append(packet_dict)

        seen_packets.add(packet_identifier)
        if not is_reassembled:  # Only add to tree if not in reassembled mode
            root.after(0, lambda: tree.insert('', 'end', values=(packet_id, packet.time, source_ip, destination_ip, protocol, function)))



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
        packet_text.delete(1.0, tk.END)
        selected_id = tree.item(curselection)['values'][0]  # 获取选中项的 'ID' 列的值
        if is_reassembled:
            # 使用 selected_id 查找 reassembled_packets 列表中的相应数据包
            packet = next((p for p in reassembled_packets if p.packet_id == selected_id), None)
            if packet is not None and packet.show() is not None:
                packet_text.insert(tk.END, packet.show().replace('\n', ' ')) # Use scapy's show method to display packet details
            else:
                packet_text.insert(tk.END, "No packet found.")
        else:
            # 使用 selected_id 查找 packets 列表中的相应数据包
            packet = next((p for p in packets if p["ID"] == selected_id), None)
            if packet is not None:
                # 将Unix时间戳转换为可读的日期和时间
                timestamp = packet["Timestamp"]

                # 检查timestamp的类型
                if isinstance(timestamp, str):
                    # 如果timestamp是字符串，那么我们假设它是一个日期时间字符串
                    dt_object = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                else:
                    # 否则，我们假设timestamp是一个Unix时间戳
                    dt_object = datetime.datetime.fromtimestamp(int(timestamp))

                formatted_time = dt_object.strftime("%Y-%m-%d %H:%M:%S")
                packet["Timestamp"] = formatted_time
                
                if "HTTP Method" in packet and "HTTP Path" in packet:
                    packet_text.insert(tk.END, "HTTP Method: " + packet["HTTP Method"] + "\n")
                    packet_text.insert(tk.END, "HTTP Path: " + packet["HTTP Path"] + "\n")

                packet_text.insert(tk.END, json.dumps(packet, indent=4))

    else:  # 如果没有选中的项
        packet_text.delete(1.0, tk.END)
        packet_text.insert(tk.END, "No packet selected.")

def filter_by_length():
    global is_filtered
    # 清空 Treeview
    for i in tree.get_children():
        tree.delete(i)

    # 根据 is_filtered 的值来决定显示哪些数据包
    if is_filtered:
        # 如果当前是过滤状态，那么显示所有数据包
        for packet in packets:
            tree.insert('', 'end', values=(packet["ID"], packet["Timestamp"], packet["Source IP"], packet["Destination IP"], packet["Protocol"], packet["Function"]))
    else:
        # 如果当前不是过滤状态，那么只显示长度超过1500的数据包
        for packet in packets:
            if packet["Length"] > 1500:
                tree.insert('', 'end', values=(packet["ID"], packet["Timestamp"], packet["Source IP"], packet["Destination IP"], packet["Protocol"], packet["Function"]))

    # 切换 is_filtered 的值
    is_filtered = not is_filtered


def reassemble_fragments():
    global fragments
    global reassembled_packets
    global is_reassembled
    global packets
    global reassembled_packet_id

    reassembled_packets = []  # 清空 reassembled_packets 列表
    # 清空 Treeview
    for i in tree.get_children():
        tree.delete(i)
    reassembled_packet_id = 0

    if is_reassembled:
        # 如果已经进行了重组，那么就显示所有的数据报
        packet_id = 0  # 重置 packet_id
        for packet in packets:
            tree.insert('', 'end', values=(packet_id, packet["Timestamp"], packet["Source IP"], packet["Destination IP"], packet["Protocol"], packet["Function"]))
            packet_id += 1  # 更新 packet_id
        is_reassembled = False
    else:
        # 否则，就显示重组后的数据报
        reassembled_packet_id = 0  # 重置 reassembled_packet_id
        for ip_id in fragments:
            if len(fragments[ip_id]) == max(fragments[ip_id].keys()) + 1:  # 确保所有的分片都已经收到
                # 找到与当前数据包相对应的原始数据包
                original_packet = next((packet for packet in packets if packet["IP ID"] == ip_id), None)
                if original_packet is not None:
                    reassembled_packet = IP(id=ip_id)
                    reassembled_packet.src = original_packet["Source IP"]
                    reassembled_packet.dst = original_packet["Destination IP"]
                    reassembled_packet.payload = IP(b''.join(bytes(fragments[ip_id][i]) for i in sorted(fragments[ip_id])))
                    reassembled_packet.packet_id = reassembled_packet_id  # Add an "packet_id" attribute to the packet 
                    reassembled_packets.append(reassembled_packet)
                    reassembled_packet_id += 1

        for packet in reassembled_packets:
            tree.insert('', 'end', values=(packet.packet_id, packet.time, packet.src, packet.dst, packet.proto, packet.summary()))
        is_reassembled = True


root = ThemedTk(theme="arc")
root.title("Packet Sniffer")
root.geometry("1400x900")


my_font = font.Font(family="Arial", size=14)
packet_text = tk.Text(root, width=80, height=10, font=my_font)
filename = tk.StringVar()

# 设置行和列的权重，使得它们可以随窗口尺寸变化
for i in range(6):
    root.grid_rowconfigure(i, weight=1, minsize=50)
for i in range(2):
    root.grid_columnconfigure(i, weight=1, minsize=100)

iface = tk.StringVar()
iface.set('ens33')

# 创建一个新的 Frame 来包含 Label 和 Combobox
iface_frame = tk.Frame(root)
iface_frame.grid(row=0, column=0, sticky="ew")
iface_label = tk.Label(iface_frame, text="Select network interface:", font=my_font)
iface_label.pack(side="left")
iface_option = ttk.Combobox(iface_frame, textvariable=iface, font=my_font)
iface_option['values'] = ('ens33', 'wlan0')
iface_option.pack(side="left", fill="x", expand=True)

# 创建一个新的 Frame 来包含 Label 和 Entry
filename_frame = tk.Frame(root)
filename_frame.grid(row=0, column=1, sticky="ew")
filename_label = tk.Label(filename_frame, text="Enter filename:", font=my_font)
filename_label.pack(side="left")
filename_entry = tk.Entry(filename_frame, textvariable=filename, font=my_font)
filename_entry.pack(side="left", fill="x", expand=True)

# 创建一个新的 Frame 来包含 Button
save_frame = tk.Frame(root)
save_frame.grid(row=0, column=2, sticky="ew")
save_button = tk.Button(save_frame, text="Save", command=save_packets, bg="blue", fg="white", font=my_font)
save_button.pack(side="left", fill="x", expand=True)

# 创建一个新的 Frame 来包含 Button
start_frame = tk.Frame(root)
start_frame.grid(row=1, column=0, sticky="ew")
start_button = tk.Button(start_frame, text="Start sniffering", command=start_sniffing, bg="green", fg="white", font=my_font)
start_button.pack(side="left", fill="x", expand=True)

# 创建一个新的 Frame 来包含 Button
stop_frame = tk.Frame(root)
stop_frame.grid(row=1, column=1, sticky="ew")
stop_button = tk.Button(stop_frame, text="Stop sniffering", command=stop_sniffing, bg="red", fg="white", font=my_font)
stop_button.pack(side="left", fill="x", expand=True)

# 新增的 Frame
reassemble_frame = tk.Frame(root)
reassemble_frame.grid(row=1, column=2, sticky="ew")
reassemble_button = tk.Button(reassemble_frame, text="Show combined pieces", command=filter_by_length, bg="yellow", fg="black", font=my_font)
reassemble_button.pack(side="left", fill="x", expand=True)

# 创建一个新的 Frame 来包含 Label 和 Entry
source_ip_filter = tk.StringVar()
source_ip_frame = tk.Frame(root)
source_ip_frame.grid(row=2, column=0, sticky="ew")
source_ip_label = tk.Label(source_ip_frame, text="Filter by Source IP:", font=my_font)
source_ip_label.pack(side="left")
source_ip_entry = tk.Entry(source_ip_frame, textvariable=source_ip_filter, font=my_font)
source_ip_entry.pack(side="left", fill="x", expand=True)

# 创建一个新的 Frame 来包含 Label 和 Entry
destination_ip_filter = tk.StringVar()
destination_ip_frame = tk.Frame(root)
destination_ip_frame.grid(row=2, column=1, sticky="ew")
destination_ip_label = tk.Label(destination_ip_frame, text="Filter by Destination IP:", font=my_font)
destination_ip_label.pack(side="left")
destination_ip_entry = tk.Entry(destination_ip_frame, textvariable=destination_ip_filter, font=my_font)
destination_ip_entry.pack(side="left", fill="x", expand=True)

#filter Button
filter_frame = tk.Frame(root)
filter_frame.grid(row=2, column=3, sticky="ew")
filter_button = tk.Button(filter_frame, text="Filter", command=toggle_filter, bg="yellow", fg="black", font=my_font)
filter_button.pack(side="left", fill="x", expand=True)

# Filter by protocol
protocol_frame = tk.Frame(root)
protocol_frame.grid(row=2,column=2,sticky="w")
protocol_label = tk.Label(protocol_frame,text="Filter by protocol:",font=my_font)
protocol_label.pack(side="left")
protocol_filter = tk.StringVar()
protocol_option = ttk.Combobox(protocol_frame, textvariable=protocol_filter, font=my_font)
protocol_option['values'] = ('All', 'ARP', 'IP', 'TCP', 'UDP', 'ICMP', 'IPv6')
protocol_option.current(0)  # 设置默认值为 'All'
protocol_option.pack(side="left")

# 创建一个新的 Frame 来包含 Treeview 和 Scrollbar
tree_frame = tk.Frame(root)
tree_frame.grid(row=3, column=0, columnspan=2, sticky="nsew")

# 创建一个 Treeview
tree = ttk.Treeview(tree_frame, columns=('ID', 'Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Function'), show='headings', style="Treeview")
tree.grid(row=0, column=0, sticky="nsew")
tree.bind('<<TreeviewSelect>>', show_packet)
# 设置每列的标题
tree.heading('ID',text='ID')
tree.heading('Timestamp', text='Timestamp')
tree.heading('Source IP', text='Source IP')
tree.heading('Destination IP', text='Destination IP')
tree.heading('Protocol', text='Protocol')
tree.heading('Function', text='Function')

# 设置每列的宽度
tree.column('ID',width=10)
tree.column('Timestamp', width=100)
tree.column('Source IP', width=100)
tree.column('Destination IP', width=100)
tree.column('Protocol', width=30)
tree.column('Function', width=170)


# 创建一个垂直滚动条并将其与 Treeview 控件关联
v_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
tree.configure(yscrollcommand=v_scrollbar.set)
v_scrollbar.grid(row=0, column=1, sticky='ns')

# 创建一个 Text 控件来显示数据报细节
packet_text = tk.Text(root)
packet_text.grid(row=4, column=0, columnspan=2, sticky="nsew")

# 配置 tree_frame 的网格权重，使得 Treeview 和 Scrollbar 可以随窗口大小变化
tree_frame.grid_columnconfigure(0, weight=1)
tree_frame.grid_rowconfigure(0, weight=1)

# 配置 root 的网格权重，使得 Treeview 和 Text 控件可以随窗口大小变化
root.grid_columnconfigure(0, weight=1)
root.grid_rowconfigure(3, weight=1)
root.grid_rowconfigure(4, weight=1)



root.protocol("WM_DELETE_WINDOW", on_closing)

root.mainloop()

