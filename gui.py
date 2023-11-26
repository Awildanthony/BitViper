import threading
import tkinter as tk
from tkinter import ttk, messagebox
import socket
import time
from sniffer import *
import queue


# Constants
MAX_PACKET_SIZE = 65535
MAX_PACKET_QUEUE_SIZE = 1000
SOCKET_TIMEOUT = 1


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

        # Set a timeout to prevent blocking
        connection.settimeout(SOCKET_TIMEOUT)

        # Start counters
        packet_number = 0
        start_time = time.time()

        while self.running:
            try:
                # Read byte size of IP packet in raw data from socket
                raw_data, addr = connection.recvfrom(MAX_PACKET_SIZE)
            except socket.timeout:
                # If recvfrom times out, just try again
                continue

            # Parse raw data from network frame into ethernet frame
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            eth_protocol = eth_proto    # (default value)
            self.hex_data = data        # (default value)

            # Check the Ethernet protocol and unpack accordingly
            if eth_proto == "IPv4":
                version, header_length, ttl, proto, src, target, data = unpack_ipv4(data)

                # Check the IPv4 protocol and unpack accordingly
                if proto == 1:  # ICMP
                    icmp_type, code, checksum, data = unpack_icmp(data)
                    eth_protocol = "ICMP"
                    hex_data = data
                elif proto == 6:  # TCP
                    src_port, dst_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = unpack_tcp(data)
                    eth_protocol = "TCP"
                    hex_data = data
                    try:
                        data = f"{src_port} → {dst_port} [???] Seq={seq} Ack={flag_ack}".encode("utf-8").decode("utf-8")
                    except UnicodeDecodeError:
                        data = "Decoding error"

                elif proto == 17:  # UDP
                    src_port, dst_port, size, data = unpack_udp(data)
                    eth_protocol = "UDP"
                    hex_data = data
                    try:
                        data = f"{src_port} → {dst_port} Len={size}".encode("utf-8").decode("utf-8")
                    except UnicodeDecodeError:
                        data = "Decoding error"
                else:  # IPv4 (other)
                    eth_protocol = "IPv4"
                    hex_data = data

            # Increment packet number and get current time
            packet_number += 1
            current_time = "{:.6f}".format(time.time() - start_time)
            current_time = current_time.ljust(8, '0')

            # Use a lock to prevent simultaneous access
            with self.lock:
                if not self.queue.full():
                    # Queue in next row
                    self.queue.put((packet_number, current_time, src_mac, dest_mac, eth_protocol, len(raw_data), data))

    def stop(self):
        self.running = False
        self.join()  # Wait for the thread to finish before stopping


class SnifferGUI:
    def __init__(self, root, packet_queue, lock):
        self.root = root
        self.packet_queue = packet_queue
        self.lock = lock
        self.sniffer = None
        self.sorting_column = None
        self.sorting_order = True   # Default sorting order is ascending
        self.setup_ui()

    def setup_ui(self):
        # Set launch header and window dimensions
        self.root.title("Socketsloth")
        self.root.geometry("2650x1000")

        # Set data font style and row height
        style = ttk.Style()
        style.configure("Treeview", font=('Script', 11), rowheight=35)

        # Set buttons
        button_frame = tk.Frame(self.root)
        button_frame.pack(side=tk.TOP, fill=tk.X)

        self.start_button = tk.Button(button_frame, text="Start", command=self.start_sniffer, bg="green")
        self.start_button.pack(side=tk.LEFT, padx=5)
        self.stop_button = tk.Button(button_frame, text="Stop", command=self.stop_sniffer, state=tk.DISABLED, bg="red")
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.clear_button = tk.Button(button_frame, text="Clear", command=self.clear_table, state=tk.DISABLED, bg="blue")
        self.clear_button.pack(side=tk.LEFT, padx=5)

        # Add a search bar
        search_frame = tk.Frame(self.root)
        search_frame.pack(side=tk.TOP, fill=tk.X)

        self.search_entry = tk.Entry(search_frame, width=30)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        search_button = tk.Button(search_frame, text="Search", command=self.apply_search)
        search_button.pack(side=tk.LEFT)

        # Set header titles
        self.tree = ttk.Treeview(self.root, columns=("No.", "Time", "Source", "Destination", "Protocol", "Length", "Data"), show="headings")
        self.tree.heading("No.", text="No.")
        self.tree.heading("Time", text="Time")
        self.tree.heading("Source", text="Source")
        self.tree.heading("Destination", text="Destination")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Length", text="Length")
        self.tree.heading("Data", text="Data")

        # Fetch screen dimensions
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        # Set header titles with binding to enable sorting
        for col, ratio in [("No.", 0.05), ("Time", 0.08), ("Source", 0.13), ("Destination", 0.13), ("Protocol", 0.08), ("Length", 0.08), ("Data", 0.35)]:
            self.tree.column(col, anchor="center", width=int(screen_width * ratio))
            self.tree.heading(col, text=col, anchor="center", command=lambda c=col: self.sort_treeview(c))

        self.tree.pack(fill=tk.BOTH, expand=True)

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
                packet_number, current_time, src_mac, dest_mac, proto, packet_length, _ = values

                try:
                    # Try to decode as UTF-8
                    hex_data = self.sniffer.hex_data.decode('utf-8')
                except UnicodeDecodeError:
                    # If decoding fails, display raw data as hexadecimal
                    hex_data = ' '.join(f'{byte:02X}' for byte in self.sniffer.hex_data)

                # Create a Toplevel window for displaying raw data
                raw_data_window = tk.Toplevel(self.root)
                raw_data_window.title("Raw Data Viewer")
                raw_data_window.geometry("1400x800")

                # Set the initial format to "Raw Hex Data"
                format_var = tk.StringVar(raw_data_window)
                format_var.set("Raw Hex Data")

                # Create a Text widget to display the raw data
                text_widget = tk.Text(raw_data_window, wrap=tk.WORD)
                text_widget.insert(tk.END, hex_data)
                text_widget.pack(expand=True, fill=tk.BOTH)

                # Set the text widget to read-only
                text_widget.config(state=tk.DISABLED)

                # Create a dropdown list for different viewing formats
                format_menu = tk.OptionMenu(raw_data_window, format_var, "Raw Hex Data", "ASCII", command=lambda x: self.update_format(x, text_widget))
                format_menu.pack()

    def update_format(self, format_type, text_widget):
        if format_type == "ASCII":
            try:
                # Try to decode as UTF-8, replacing non-printable characters
                ascii_data = ''.join(chr(byte) if 32 <= byte < 127 else '.' for byte in self.sniffer.hex_data)
            except UnicodeDecodeError:
                # If decoding fails, display raw data as hexadecimal
                ascii_data = ' '.join(f'{byte:02X}' for byte in self.sniffer.hex_data)

            # Display the ASCII data in the Text widget
            text_widget.config(state=tk.NORMAL)
            text_widget.delete(1.0, tk.END)
            text_widget.insert(tk.END, ascii_data)
            text_widget.config(state=tk.DISABLED)
        else:
            # Display the raw hex data
            text_widget.config(state=tk.NORMAL)
            text_widget.delete(1.0, tk.END)
            text_widget.insert(tk.END, ' '.join(f'{byte:02X}' for byte in self.sniffer.hex_data))
            text_widget.config(state=tk.DISABLED)

    def sort_treeview(self, col):
        # Check if we're sorting the same column
        if self.sorting_column == col:
            # Toggle sorting order
            self.sorting_order = not self.sorting_order
        else:
            # Set default sorting order to ascending for a new column
            self.sorting_order = True

        items = [(float(self.tree.set(k, col)) if col in ["Time", "No.", "Length"] else self.tree.set(k, col), k) for k in self.tree.get_children('')]
        items.sort(reverse=self.sorting_order)

        # Rearrange items in sorted positions
        for index, (val, k) in enumerate(items):
            self.tree.move(k, '', index)

        # Update sorting column
        self.sorting_column = col
    
    def apply_search(self):
        query = self.search_entry.get().lower()  # Convert the query to lowercase for case-insensitive search
        matching_items = []

        for item_id in self.tree.get_children():
            item = self.tree.item(item_id, 'values')
            if any(query in str(value).lower() for value in item):
                matching_items.append(item_id)

        # Clear current selection and select the matching items
        self.tree.selection_remove(self.tree.selection())
        self.tree.selection_add(*matching_items)
        self.tree.see(matching_items[0] if matching_items else "")  # Scroll to the first matching item if any


def main():
    root = tk.Tk()
    packet_queue = queue.Queue(maxsize=MAX_PACKET_QUEUE_SIZE)    # Set a maximum size for the queue
    lock = threading.Lock()                                      # Create a lock for thread safety
    gui = SnifferGUI(root, packet_queue, lock)
    root.mainloop()


if __name__ == "__main__":
    main()
