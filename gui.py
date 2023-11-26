import threading
import tkinter as tk
from tkinter import ttk, messagebox
import socket
import time
from sniffer import *
import queue


class PacketSniffer(threading.Thread):
    def __init__(self, queue, lock):
        super().__init__()
        self.queue = queue
        self.lock = lock
        self.running = False
        self.hex_data = None

    def run(self):
        # Establish a socket (OSI Layer 2, raw socket, all packets)
        connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        connection.settimeout(1)    # Set a timeout to prevent blocking
        packet_number = 0
        start_time = time.time()

        while self.running:
            try:
                # Read byte size of IP packet in raw data from socket
                raw_data, addr = connection.recvfrom(65535)
            except socket.timeout:
                # If recvfrom times out, just try again
                continue

            # Parse raw data from network frame into ethernet frame
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            proto = eth_proto   # default value
            self.hex_data = data 

            # Check the Ethernet protocol and unpack accordingly
            if eth_proto == "IPv4":
                version, header_length, ttl, proto, src, target, data = unpack_ipv4(data)

                # Check the IPv4 protocol and unpack accordingly
                if proto == 1:  # ICMP
                    icmp_type, code, checksum, data = unpack_icmp(data)
                    proto = "ICMP"
                    hex_data = data
                elif proto == 6:  # TCP
                    src_port, dst_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = unpack_tcp(data)
                    proto = "TCP"
                    hex_data = data
                    try:
                        data = "{} → {} [???] Seq={} Ack={}".format(
                            src_port, dst_port, seq, flag_ack
                        ).encode("utf-8").decode("utf-8")
                    except UnicodeDecodeError:
                        data = "Decoding error"

                elif proto == 17:  # UDP
                    src_port, dst_port, size, data = unpack_udp(data)
                    proto = "UDP"
                    hex_data = data
                    try:
                        data = "{} → {} Len={}".format(
                            src_port, dst_port, size
                        ).encode("utf-8").decode("utf-8")
                    except UnicodeDecodeError:
                        data = "Decoding error"
                else:  # IPv4 (other)
                    proto = "IPv4"
                    hex_data = data

            # Increment packet number and get current time
            packet_number += 1
            current_time = round(time.time() - start_time, 6)

            # Use a lock to prevent simultaneous access
            with self.lock:
                if not self.queue.full():
                    # Queue in next row
                    self.queue.put((packet_number, current_time, src_mac, dest_mac, proto, data))

    def stop(self):
        self.running = False
        self.join()  # Wait for the thread to finish before stopping


class SnifferGUI:
    def __init__(self, root, packet_queue, lock):
        self.root = root
        self.packet_queue = packet_queue
        self.lock = lock
        self.sniffer = None
        self.setup_ui()

    def setup_ui(self):
        # Set launch header and window dimensions
        self.root.title("Socketsloth")
        self.root.geometry("2650x1000")

        # Set data font style and row height
        style = ttk.Style()
        style.configure("Treeview", font=('Script', 11), rowheight=35)

        # Set heading titles
        self.tree = ttk.Treeview(self.root, columns=("No.", "Time", "Source", "Destination", "Protocol", "Data"), show="headings")
        self.tree.heading("No.", text="No.")
        self.tree.heading("Time", text="Time")
        self.tree.heading("Source", text="Source")
        self.tree.heading("Destination", text="Destination")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Data", text="Data")

        # Fetch screen dimensions
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        # Set data columns' titles and widths
        for col, ratio in [("No.", 0.05), ("Time", 0.10), ("Source", 0.15), ("Destination", 0.15), ("Protocol", 0.10), ("Data", 0.35)]:
            self.tree.column(col, anchor="center", width=int(screen_width*ratio))
            self.tree.heading(col, text=col, anchor="center")

        self.tree.pack(fill=tk.BOTH, expand=True)

        # Set buttons
        self.start_button = tk.Button(self.root, text="Start", command=self.start_sniffer, bg="green")
        self.start_button.pack()
        self.stop_button = tk.Button(self.root, text="Stop", command=self.stop_sniffer, state=tk.DISABLED, bg="red")
        self.stop_button.pack()
        self.clear_button = tk.Button(self.root, text="Clear", command=self.clear_table, state=tk.DISABLED, bg="blue")
        self.clear_button.pack()

        # Initialize right-click menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Show Raw Hex Data", command=self.show_raw_data)

        # Bind the right-click event to the Treeview
        self.tree.bind("<Button-3>", self.show_context_menu)

        self.update_gui()

    def start_sniffer(self):
        self.sniffer = PacketSniffer(self.packet_queue, self.lock)
        self.sniffer.running = True
        self.sniffer.start()
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.clear_button.config(state=tk.DISABLED)

    def stop_sniffer(self):
        self.sniffer.stop()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        if self.tree.get_children():
            self.clear_button.config(state=tk.NORMAL)

    def clear_table(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.clear_button.config(state=tk.DISABLED)

    def update_gui(self):
        while not self.packet_queue.empty():
            packet = self.packet_queue.get()
            new_item = self.tree.insert("", "end", values=packet)
            self.tree.see(new_item)
            if not self.sniffer.running:
                self.clear_button.config(state=tk.NORMAL)
        self.root.after(1000, self.update_gui)

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)  # Identify the item under the cursor
        if item:
            self.context_menu.post(event.x_root, event.y_root)

    def show_raw_data(self):
        selected_item = self.tree.selection()
        if selected_item:
            values = self.tree.item(selected_item, 'values')
            if values:
                packet_number, current_time, src_mac, dest_mac, proto, _ = values
                raw_data_str = format_multi_line("", self.sniffer.hex_data)

                # Create a Toplevel window for displaying raw data
                raw_data_window = tk.Toplevel(self.root)
                raw_data_window.title("Raw Hex Data")
                raw_data_window.geometry("1400x800")

                # Create a Text widget to display the raw data
                text_widget = tk.Text(raw_data_window, wrap=tk.WORD)
                text_widget.insert(tk.END, raw_data_str)
                text_widget.pack(expand=True, fill=tk.BOTH)

                # Allow copying text
                text_widget.config(state=tk.NORMAL)

                # Create a function to set the text widget back to read-only after copying
                def set_read_only(event):
                    text_widget.config(state=tk.DISABLED)

                # Bind the event to set the text widget to read-only after copying
                text_widget.bind("<Control-c>", set_read_only)


def main():
    root = tk.Tk()
    packet_queue = queue.Queue(maxsize=1000)    # Set a maximum size for the queue
    lock = threading.Lock()                     # Create a lock for thread safety
    gui = SnifferGUI(root, packet_queue, lock)
    root.mainloop()


if __name__ == "__main__":
    main()
