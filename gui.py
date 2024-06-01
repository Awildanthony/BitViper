from sniffer import *
from scapy.all import Ether, rdpcap, wrpcap
from queue import Queue
from tkinter import ttk, messagebox, filedialog
import tkinter as tk
import traceback
import threading
import socket
import queue
import time
import os


MAX_PACKET_SIZE = 65535
MAX_PACKET_QUEUE_SIZE = 1000
SOCKET_TIMEOUT = 1
UPDATES_PER_SECOND = 10


class PacketSniffer(threading.Thread):
    """
    A class that extends `threading.Thread` to sniff packets from 
    a network interface.

    Attributes: `queue`, `lock`, `running`, `outfile`, 
                `sesh_num`, `packet_num`.

    Methods: `fetch_sesh_num`, `run`, `stop`.
    """

    sesh_lock = threading.Lock()
    first_launch = True
    session_number = 1

    def __init__(self: 'PacketSniffer', 
                 packet_queue: queue.Queue, 
                 thread_lock: threading.Lock):
        super().__init__()
        self.queue = packet_queue
        self.lock = thread_lock
        self.running = False
        self.outfile = "captured_packets.pcap"
        self.sesh_num = self.fetch_sesh_num()
        self.packet_num = 0

    def fetch_sesh_num(self: 'PacketSniffer') -> int:
        """
        Returns the session number of the most recent packet.
        Grabs the sesh_lock to maintain thread safety.
        """
        with PacketSniffer.sesh_lock:
            try:
                session_number = PacketSniffer.session_number
            except Exception as e:
                print(f"Error loading session number: {e}")
                session_number = 1
            if PacketSniffer.first_launch:
                session_number = 1
                PacketSniffer.first_launch = False
            return session_number

    def run(self: 'PacketSniffer') -> None:
        """
        Starts a live packet capture session, listening on an
        open raw socket for all packets across the data link layer.
        """
        # Establish a socket.
        connection = socket.socket(socket.AF_PACKET,   # data link layer
                                   socket.SOCK_RAW,    # raw socket
                                   socket.ntohs(3))    # all packets

        # Set a timeout to prevent the thread from blocking.
        connection.settimeout(SOCKET_TIMEOUT)
        start_time = time.time()
        self.pkt_num = 0

        while self.running:
            try:
                # Read raw data of IP packet from socket, up to max size.
                net_frame, addr = connection.recvfrom(MAX_PACKET_SIZE)
                # addr = (NI name, eth_proto #, pkt type, hatype, src MAC addr)
            except socket.timeout:
                continue

            packet_data = (0, 0, '0.000000', 'N/A', 'N/A', 'N/A', 0, 'N/A')
            try:
                # Parse raw data from the network frame into an ethernet frame.
                dst_mac, src_mac, proto, eth_frame = parse_net_frame(net_frame)

                # Get the protocol to display and the payload as bytes.
                proto, display_data, pl = parse_eth_frame(proto, eth_frame)
                # TODO: fix bug where DNS packet has pl as display data. How?

                # Increment packet number; get and format current time.
                self.pkt_num += 1
                curr_t = "{:.6f}".format(time.time()-start_time).ljust(8, '0')

                # Grab lock to package and write/display packet information.
                with self.lock:
                    if not self.queue.full():
                        packet_data = (self.sesh_num,  # Session Number
                                       self.pkt_num,   # Packet Number
                                       curr_t,         # Time
                                       src_mac,        # Source MAC
                                       dst_mac,        # Destination MAC
                                       proto,          # Network Protocol
                                       len(pl),        # Length
                                       display_data,   # Display Data
                                       pl)             # Payload
                        try:
                            # Add the packet to the display queue.
                            self.queue.put(packet_data)
                            # Write the packet to the pcap file.
                            wrpcap(self.outfile, Ether(eth_frame), append=True)

                        except Exception as queue_err:
                            print(f"Error adding packet to queue: {queue_err}")

            except Exception as e:
                traceback.print_exc()
                print(f"Error processing packet: {e}")
                print(f"Packet data: {packet_data}\n")

    def stop(self: 'PacketSniffer') -> None:
        """
        Stops the live packet capture session. To avoid losing data, 
        waits until the current thread finishes processing first.
        """
        self.running = False
        # Block the calling thread until the current thread exits.
        self.join()
        self.pkt_num = 1
        self.sesh_num += 1
        with PacketSniffer.sesh_lock:
            PacketSniffer.session_number = self.sesh_num


class SnifferGUI:
    """
    A class representing the graphical user interface for the packet sniffer.

    Attributes: `root`, `queue`, `lock`, `sniffer`, `sorting_column`,
                `sorting_order`, `capture_running`.

    Methods: `setup_ui`, `start_sniffer`, `stop_sniffer`, `clear_table`,
             `on_closing`, `save_packets`, `load_packets`, `update_gui`,
             `show_context_menu`, `show_raw_data`, `update_format`,
             `sort_treeview`, `apply_search`.
    """
    def __init__(self: 'SnifferGUI', 
                 window_root: tk.Tk, 
                 packet_queue: queue.Queue, 
                 thread_lock: threading.Lock):
        self.root = window_root
        self.queue = packet_queue
        self.lock = thread_lock
        self.sniffer = None
        self.sorting_column = None  # Most recent column sorted.
        self.sorting_order = True   # Ascending by default.
        self.capture_running = False
        self.setup_ui()

        # Cannot save as .pcap file if empty datatable.
        self.save_button.config(state=tk.DISABLED)

    def setup_ui(self: 'SnifferGUI') -> None:
        """
        Set up the GUI elements to their base states.
        """
        # Set launch header and window dimensions.
        self.root.title('SocketSloth')
        self.root.geometry('2650x1000')

        # Set data font style and row height.
        style = ttk.Style()
        style.configure('Treeview', font=('Script', 11), rowheight=35)

        # Set buttons.
        button_frame = tk.Frame(self.root)
        button_frame.pack(side=tk.TOP, fill=tk.X)

        self.start_button = tk.Button(button_frame, 
                                      text="Start", 
                                      command=self.start_sniffer, 
                                      bg='green')
        self.start_button.pack(side=tk.LEFT, padx=5)
        self.stop_button = tk.Button(button_frame, 
                                     text="Stop", 
                                     command=self.stop_sniffer, 
                                     state=tk.DISABLED, 
                                     bg='red')
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.clear_button = tk.Button(button_frame, 
                                      text="Clear", 
                                      command=self.clear_table, 
                                      state=tk.DISABLED, 
                                      bg='blue')
        self.clear_button.pack(side=tk.LEFT, padx=5)
        self.save_button = tk.Button(button_frame, 
                                     text="Save", 
                                     command=self.save_packets)
        self.save_button.pack(side=tk.RIGHT, padx=5)
        self.load_button = tk.Button(button_frame, 
                                     text="Load", 
                                     command=self.load_packets)
        self.load_button.pack(side=tk.RIGHT, padx=5)

        # Set search bar.
        search_frame = tk.Frame(self.root)
        search_frame.pack(side=tk.TOP, fill=tk.X)

        self.search_entry = tk.Entry(search_frame, width=30)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        search_button = tk.Button(search_frame, 
                                  text="Search", 
                                  command=self.apply_search)
        search_button.pack(side=tk.LEFT)

        # Set header titles.
        self.tree = ttk.Treeview(self.root, columns=('Sesh', 'No.', 'Time', 
                                                     'Source', 'Destination', 
                                                     'Protocol', 'Length', 
                                                     'Data'), 
                                            show='headings')
        self.tree.heading('Sesh', text="Sesh")
        self.tree.heading('No.', text="No.")
        self.tree.heading('Time', text="Time")
        self.tree.heading('Source', text="Source")
        self.tree.heading('Destination', text="Destination")
        self.tree.heading('Protocol', text="Protocol")
        self.tree.heading('Length', text="Length")
        self.tree.heading('Data', text="Data")

        # Fetch screen dimensions.
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        # Set header titles with binding to enable sorting.
        # Width ratios should add up to 0.9 != 1.0, for some reason?
        for col, ratio in [('Sesh',         0.03),
                           ('No.',          0.05), 
                           ('Time',         0.08), 
                           ('Source',       0.12), 
                           ('Destination',  0.12), 
                           ('Protocol',     0.08), 
                           ('Length',       0.08), 
                           ('Data',         0.34)]:
            self.tree.column(col, anchor='c', width=int(screen_width * ratio))
            self.tree.heading(col, text=col, anchor='c', 
                              command=lambda c=col: self.sort_treeview(c))
        # Data column looks better left-aligned than centered.
        self.tree.column('Data', anchor='w')
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Initialize right-click menu.
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Inspect Payload", 
                                      command=self.show_raw_data)

        # Bind the right-click event to the Treeview.
        self.tree.bind('<Button-3>', self.show_context_menu)

        # Update GUI to base state.
        self.update_gui()

    def start_sniffer(self: 'SnifferGUI') -> None:
        """
        API to `run()` a PacketSniffer instance.
        """
        if not self.sniffer or not self.sniffer.running:
            # If an instance of `PacketSniffer` DNE, create one.
            self.sniffer = PacketSniffer(self.queue, self.lock)

            # Check whether class should pass `first_launch` to instance.
            if hasattr(PacketSniffer, 'first_launch'):
                self.sniffer.first_launch = PacketSniffer.first_launch

            self.sniffer.running = True
            self.sniffer.start()

        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.clear_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.DISABLED)
        self.load_button.config(state=tk.DISABLED)
        self.capture_running = True

    def stop_sniffer(self: 'SnifferGUI') -> None:
        """
        API to `stop()` the current PacketSniffer instance.
        """
        self.sniffer.stop()
        # vvv Creates a new instance upon the next start.
        self.sniffer = None
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.capture_running = False
        if self.tree.get_children():
            self.clear_button.config(state=tk.NORMAL)
            self.save_button.config(state=tk.NORMAL)
            self.load_button.config(state=tk.NORMAL)
        else:
            self.clear_button.config(state=tk.DISABLED)
            self.save_button.config(state=tk.DISABLED)
            self.load_button.config(state=tk.DISABLED)

    def clear_table(self: 'SnifferGUI') -> None:
        """
        Clear the table of captured packets in the GUI.
        Note this does not remove them from `self.outfile`.
        """
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.clear_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.DISABLED)
        with PacketSniffer.sesh_lock:
            PacketSniffer.session_number = 1

    def on_closing(self: 'SnifferGUI') -> None:
        """
        Should be called when the GUI's root window is closed. 
        Stops the sniffer, wipes any stored packets, and destroys root.
        """
        if self.sniffer:
            self.sniffer.stop()
        try:
            os.remove('captured_packets.pcap')
        except FileNotFoundError:
            pass
        self.root.destroy()

    def save_packets(self: 'SnifferGUI') -> None:
        """
        TODO: fix this. It's completely broken!

        Prompts user to name a `.pcap` outfile, to which any packets
        in `self.tree` will be saved. Should only be possible if 
        sniffer is stopped and there are packets in the table.
        """
        try:
            # Ask the user for the .pcap outfile's name and path.
            file_path = tk.filedialog.asksaveasfilename(
                defaultextension='.pcap', 
                filetypes=[("PCAP files", '*.pcap')]
            )
            if not file_path:
                return

            # Write the captured packets' data to said file.
            # pkt == (sesh #, pkt #, time, src MAC, dst MAC, proto, len, data)
            captured_packets = list(self.queue.queue)
            wrpcap(file_path, [Ether(pkt[-1]) for pkt in captured_packets])

        except Exception as e:
            traceback.print_exc()
            messagebox.showerror("Error", f"Error saving packets: {str(e)}")

    def load_packets(self: 'SnifferGUI') -> None:
        """
        TODO: fix this, IT'S COMPLETELY BROKEN!

        Prompts user to load a `.pcap` infile, which will display its
        packets in the table. Any .pcap files previously generated by
        SocketSloth will include a session number, packet number, and
        time, while others (e.g., from Wireshark) will not.
        """
        try:
            # Ask the user for a .pcap infile to load.
            file_path = tk.filedialog.askopenfilename(
                defaultextension='.pcap', 
                filetypes=[("PCAP files", '*.pcap')]
            )
            if not file_path:
                return

            # Read the selected .pcap file using Scapy library.
            # TODO: if I'm feeling ballsy, write my own rdpcap().
            packets = rdpcap(file_path)

            # Extract relevant information from the loaded packets.
            captured_packets = []
            for idx, packet in enumerate(packets, start=1):
                try:
                    dest_mac, src_mac, \
                        eth_proto, eth_data = parse_net_frame(bytes(packet))
                    # Set defaults.
                    eth_protocol = eth_proto
                    self.display_data = eth_data

                    # Check the Ethernet protocol and unpack accordingly.
                    if eth_proto == 'IPv4':
                        version, header_length, ttl, proto, \
                            src_ip, dst_ip, ipv4_data = unpack_ipv4(eth_data)

                        # Check the IPv4 protocol and unpack accordingly.
                        if proto == 1:
                            icmp_type, code, csum, data = unpack_icmp(ipv4_data)
                            eth_protocol = 'ICMP'
                            self.display_data = data

                        elif proto == 6:
                            src_port, dst_port, seq, ack, tcp_flags, \
                                http_method, http_url, status, data = unpack_tcp(data)
                            eth_protocol = 'TCP'
                            self.display_data = data

                            # Call to unpack_tcp() found HTTP(S) data.
                            if http_method and http_url:    
                                if dst_port == 80 or src_port == 80:
                                    eth_protocol = 'HTTP'
                                if dst_port == 443 or src_port == 443:
                                    eth_protocol = 'HTTPS'
                                else:
                                    # Non-conventional port (unknown).
                                    eth_protocol = 'HTTP(S)'
                            else:
                                try:
                                    non_http_data = (f'{src_port} → '
                                                     f'{dst_port} [???] Seq={seq} '
                                                     f'Ack={ack} {data}')
                                except UnicodeDecodeError as error:
                                    non_http_data = "Decoding error:\n{}".format(error)
                                data = non_http_data

                        elif proto == 17:
                            src_port, dst_port, size, data = unpack_udp(data)
                            eth_protocol = 'UDP'
                            self.display_data = data

                            # DNS.
                            if src_port in [53, 56710] or dst_port in [53, 56710]:
                                eth_protocol = 'DNS'
                                data = format_dns_data(data)

                            # UDP (other).
                            else:
                                try:
                                    data = f'{src_port} → {dst_port} Len={size}'
                                except UnicodeDecodeError as error:
                                    data = "Decoding error:\n{}".format(error)

                        # IPv4 (other).
                        else:
                            eth_protocol = 'IPv4'
                            self.display_data = data

                    # DNS (non-IPv4).
                    elif eth_proto == '56710':
                        try:
                            src_port, dst_port, size, data = unpack_udp(data)
                            eth_protocol = 'DNS'
                            self.display_data = data
                            data = format_dns_data(data)
                        # TODO: fix this!
                        except Exception as buffer_error: 
                            eth_protocol = 'DNS'

                    # ARP.
                    # TODO: implement this!
                    elif eth_proto == '1544':
                        eth_protocol = 'ARP'

                    # .pcap files typically do not store session_number.
                    if hasattr(self.sniffer, 'session_number'):
                        session_number = self.sniffer.sesh_num
                    else:
                        session_number = "#"

                    # .pcap files typically do not store packet_number.
                    if hasattr(self.sniffer, 'pkt_num'):
                        index = self.sniffer.pkt_num
                    else:
                        index = idx

                    # .pcap files might not have a start_time attribute.
                    start_time = getattr(self.sniffer, 'start_time', 0.0)

                    # (Un)package and write/display packet information.
                    packet_info = (session_number,
                                   index,
                                   "{:.6f}".format(time.time() - start_time),
                                   src_mac,
                                   dest_mac,
                                   eth_protocol,
                                   len(bytes(packet)),
                                   data)
                    captured_packets.append(packet_info)

                except Exception as e:
                    print(f"Error extracting packet information: {str(e)}")

            # Populate the data table with the extracted information.
            for packet_info in captured_packets:
                new_item = self.tree.insert("", 'end', values=packet_info)
                self.tree.see(new_item)

            # Packets are now in the data table; enable the Save and Clear buttons.
            self.save_button.config(state=tk.NORMAL)
            self.clear_button.config(state=tk.NORMAL)

        except Exception as e:
            messagebox.showerror("Error", f"Error loading packets: {str(e)}")

    def update_gui(self: 'SnifferGUI') -> None:
        """
        Update the GUI to reflect changes in the packet queue.
        Happens every `UPDATES_PER_SECOND` times per second.
        """
        if self.sniffer:
            while not self.queue.empty():
                packet = self.queue.get()
                try:
                    packet_info = tuple(str(value) for value in packet)
                    new_item = self.tree.insert("", 'end', values=packet_info)
                    self.tree.see(new_item)
                except Exception as e:
                    print(f"Error updating GUI: {e}")
                    print(f"Packet values: {packet}")

            if not self.sniffer.running:
                self.clear_button.config(state=tk.NORMAL)
                self.load_button.config(state=tk.NORMAL)
                if self.tree.get_children():
                    # Table must have packet(s) and sniffer must be off.
                    self.save_button.config(state=tk.NORMAL)

        self.root.after(1000 // UPDATES_PER_SECOND, self.update_gui)

    def show_context_menu(self: 'SnifferGUI', event: tk.Event) -> None:
        """
        Upon right-clicking on a packet in the GUI, displays
        the menu of options for interacting with that packet.
        """
        # Identify the item (packet as a row in the table) under the cursor.
        item = self.tree.identify_row(event.y)
        if item:
            self.context_menu.post(event.x_root, event.y_root)

    def show_raw_data(self: 'SnifferGUI') -> None:
        """
        Offers the user a selection menu to further examine a
        packet by right-clicking it. Currently supports only
        examining the payload in either raw hex or ASCII format.
        """
        selected_item = self.tree.selection()
        if selected_item:
            # values = (sesh, pkt #, time, src MAC, dst MAC, proto, len, data)
            values = self.tree.item(selected_item, 'values')
            if values:
                payload = values[-1]
                hex_data = payload

                # Create a Toplevel window for displaying raw data.
                raw_data_window = tk.Toplevel(self.root)
                raw_data_window.title("Raw Data Viewer")
                raw_data_window.geometry('1400x800')

                # Set the initial format to "Raw Hex Data".
                format_var = tk.StringVar(raw_data_window)
                format_var.set("Raw Hex Data")

                # Create a Text widget to display the raw data.
                text_widget = tk.Text(raw_data_window, wrap=tk.WORD)
                text_widget.insert(tk.END, hex_data)
                text_widget.pack(expand=True, fill=tk.BOTH)

                # Set the text widget to read-only.
                text_widget.config(state=tk.DISABLED)

                # Create a dropdown list for different viewing formats.
                format_menu = tk.OptionMenu(
                    raw_data_window, 
                    format_var, 
                    "Raw Hex Data", 
                    "ASCII", 
                    command=lambda x: self.update_format(x, text_widget))
                format_menu.pack()

    def update_format(self: 'SnifferGUI', 
                      format_type: str, 
                      text_widget: tk.Text) -> None:
        """
        Update the display format of the payload data (e.g., hex -> ASCII).
        """
        if format_type == 'ASCII':
            # Get the raw hex data string from the text widget.
            raw_hex_data_str = text_widget.get('1.0', tk.END).strip()
            if self.sniffer:
                hex_data = self.sniffer.hex_data
            else:
                # Convert the raw hex data string to bytes
                try:
                    hex_data = bytes.fromhex(raw_hex_data_str)
                except ValueError:
                    return

            # Decode the raw hex data to ASCII.
            ascii_data = ''.join(
                chr(byte) if 32 <= byte < 127 else '.'
                for byte in hex_data
            )

            # Update the text widget with the ASCII data.
            text_widget.config(state=tk.NORMAL)
            text_widget.delete('1.0', tk.END)
            text_widget.insert(tk.END, ascii_data)
            text_widget.config(state=tk.DISABLED)
        else:
            # Display the raw hex data.
            text_widget.config(state=tk.NORMAL)
            text_widget.delete(1.0, tk.END)
            text_widget.insert(
                tk.END, 
                ' '.join(f'{byte:02X}' for byte in self.sniffer.hex_data))
            text_widget.config(state=tk.DISABLED)

    def sort_treeview(self: 'SnifferGUI', col: str) -> None:
        """
        Sort the data table in the GUI based on the selected column.
        Toggles between ASC (default) and DESC alphanumerical order.
        """
        # Check if we're sorting the same column.
        if self.sorting_column == col:
            # Toggle sorting order.
            self.sorting_order = not self.sorting_order
        else:
            # Set default sorting order to ascending for a new column.
            self.sorting_order = True

        # Create a list of tuples with the sort value and item's ID.
        items = [(float(self.tree.set(k, col)) 
                  if col in ['Time', 'No.', 'Length']
                  else self.tree.set(k, col),
                  k)
                for k in self.tree.get_children('')]
        items.sort(reverse=self.sorting_order)

        # Rearrange items in sorted positions.
        for index, (val, k) in enumerate(items):
            self.tree.move(k, '', index)

        # Update sorting column.
        self.sorting_column = col
    
    def apply_search(self: 'SnifferGUI') -> None:
        """
        Apply a search query to highlight packets in the data table.
        """
        # Convert the query to lowercase for case-insensitive search.
        query = self.search_entry.get().lower()
        matching_items = []

        for item_id in self.tree.get_children():
            item = self.tree.item(item_id, 'values')
            if any(query in str(value).lower() for value in item):
                matching_items.append(item_id)

        # Clear current selection and select the matching items.
        self.tree.selection_remove(self.tree.selection())
        self.tree.selection_add(*matching_items)
        self.tree.see(matching_items[0] if matching_items else "")  # Go to 1st


def main():
    window_root = tk.Tk()
    packet_queue = Queue(maxsize=MAX_PACKET_QUEUE_SIZE)
    thread_lock = threading.Lock()
    gui = SnifferGUI(window_root, packet_queue, thread_lock)

    # Bind the on_closing method to the closing event.
    window_root.protocol('WM_DELETE_WINDOW', gui.on_closing)

    window_root.mainloop()


if __name__ == '__main__':
    main()
