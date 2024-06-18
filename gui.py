import os
import queue
import shutil
import socket
import threading
import time
import traceback
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from queue import Queue
from scapy.all import Ether, rdpcap, wrpcap
from sniffer import *


MAX_PACKET_SIZE = 65535
MAX_PACKET_QUEUE_SIZE = 1000
SOCKET_TIMEOUT = 1
UPDATES_PER_SECOND = 100


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
        self.pkt_num = 0

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

            packet_data = (0, 0, '---', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 0, b'')
            try:
                # Parse raw data from the network frame into an ethernet frame.
                dst_mac, src_mac, proto, eth_frame = parse_net_frame(net_frame)

                # Get the protocol to display and the payload as bytes.
                src_ip, dst_ip, proto, info, pl = parse_eth_frame(proto, eth_frame)

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
                                       src_mac,        # Source MAC Address
                                       dst_mac,        # Destination MAC Address
                                       src_ip,         # Source IP Address
                                       dst_ip,         # Destination IP Address
                                       proto,          # Network Protocol
                                       len(pl),        # Length
                                       info,           # Display Data
                                       pl)             # Payload
                        try:
                            # Add the packet to the display queue.
                            self.queue.put(packet_data)
                            # Write the packet (`net_frame`) to the pcap file.
                            wrpcap(self.outfile, net_frame, append=True)

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
        self.sorting_col = None  # Most recent column sorted.
        self.asc_order = True    # Ascending by default.
        self.capture_running = False
        self.outfile = "captured_packets.pcap"  # TODO: make this dynamically set.
        self.setup_ui()

        # Cannot save as .pcap file if empty datatable.
        self.save_button.config(state=tk.DISABLED)

    def setup_ui(self: 'SnifferGUI') -> None:
        """
        Set up the GUI elements to their base states.
        """
        def on_resize(event) -> None:
            """
            Function to handle window resize event.
            """
            total_width = self.tree.winfo_width()
            for col, ratio in col_configs:
                new_width = int(total_width * ratio)
                self.tree.column(col, width=new_width, minwidth=min_col_widths[col])

            # Calculate/define current GUI window dimensions.
            current_width = self.root.winfo_width()
            current_height = self.root.winfo_height()
            min_gui_height = 400    # <-- Should be universal.
            
            # Enforce minimum dimensions.
            if current_width < min_gui_width:
                self.root.geometry(f'{min_gui_width}x{current_height}')
            if current_height < min_gui_height:
                self.root.geometry(f'{current_width}x{min_gui_height}')

        # Fetch screen dimensions; define GUI size.
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        gui_width = 1850 if screen_width >= 1920 else int(screen_width * 0.9)
        gui_height = int(screen_height * 0.65)

        # Set launch header and window dimensions.
        self.root.title('Bit Viper')
        self.root.geometry(f'{gui_width}x{gui_height}')

        # Set data font style, row height, and (left) padding for column headers.
        style = ttk.Style()
        style.configure('Treeview', font=('Script', 11), 
                        rowheight=30, padding=(5, 0, 0, 0))
        style.layout('Treeview', [('Treeview.treearea', {'sticky': 'nswe'})])
        style.configure('Treeview.Heading', padding=(5, 0, 0, 0))

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

        self.search_entry = tk.Entry(search_frame, width=54)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        search_button = tk.Button(search_frame, 
                                  text="Search", 
                                  command=self.apply_search,)
        search_button.pack(side=tk.LEFT, pady=5)

        # Define default width column ratios.
        col_configs = [
            ('Sesh',             0.01),
            ('No.',              0.02),
            ('Time',             0.06),
            ('Source MAC',       0.08),
            ('Destination MAC',  0.08),
            ('Source IP',        0.07),
            ('Destination IP',   0.07),
            ('Protocol',         0.04),
            ('Length',           0.03),
            ('Info',             0.29)
        ]

        # Calculate column widths based on ratios and screen width.
        default_col_config = {
            col: int(gui_width * ratio) 
            for col, ratio in col_configs
        }
        min_col_widths = {
            'Sesh':             50,
            'No.':              65,
            'Time':             120,
            'Source MAC':       155,
            'Destination MAC':  155,
            'Source IP':        130,
            'Destination IP':   130,
            'Protocol':         80,
            'Length':           70,
            'Info':             400  # This one is enforced by on_resize().
        }
        min_gui_width = sum(min_col_widths.values())

        # Create the treeview.
        self.tree = ttk.Treeview(self.root, 
                                 columns=[col for col, _ in col_configs], 
                                 show="headings")
        # Configure columns.
        for col, width in default_col_config.items():
            self.tree.column(col, anchor='w', 
                             width=width, 
                             minwidth=min_col_widths[col])
            self.tree.heading(col, text=col, 
                              anchor='w', 
                              command=lambda c=col: self.sort_treeview(c))
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Initialize right-click menu.
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Inspect Payload", 
                                      command=self.show_raw_data)

        # Bind the right-click event to the Treeview.
        self.tree.bind('<Button-3>', self.show_context_menu)

        # Bind resize event to the Treeview.
        self.tree.bind('<Configure>', on_resize)

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
        Prompts user to name a `.pcap` outfile, to which captured
        packets will be saved. Should only be possible if sniffer 
        is stopped and there are packets to save.
        """
        try:
            # Ask the user for the .pcap outfile's name and path.
            file_path = tk.filedialog.asksaveasfilename(
                defaultextension='.pcap',
                filetypes=[("PCAP files", '*.pcap')]
            )
            if not file_path:
                return

            # Copy the contents of self.outfile to the new file.
            # NOTE: this means one cannot save loaded files' contents this way.
            shutil.copyfile(self.outfile, file_path)

        except Exception as e:
            traceback.print_exc()
            messagebox.showerror("Error", f"Error saving packets: {str(e)}")

    def load_packets(self: 'SnifferGUI') -> None:
        """
        TODO: fix bug with loading DNS packets.

        Prompts user to load a `.pcap` infile, which will display its
        packets in the table. Any .pcap files previously generated by
        Bit Viper will include a session number, packet number, and
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
            loaded_packets = []
            for idx, packet in enumerate(packets, start=1):
                try:
                    # Extract Ethernet frame from the packet.
                    # TODO: this fails for DNS packets
                    if Ether in packet:
                        eth_frame = bytes(packet[Ether])
                    else:
                        print(f"Could not load packet {idx}:\n{packet}\n")
                        continue

                    # Parse data from the network frame into an ethernet frame.
                    dst_mac, src_mac, proto, eth_pl = parse_net_frame(eth_frame)

                    # Extract displayable info from the ethernet frame.
                    src_ip, dst_ip, proto, info, net_pl = parse_eth_frame(proto, eth_pl)

                    # NOTE: length of net_pl is consistently ...
                    # - 34 bytes short for TCP
                    # - 14 bytes short for ARP
                    # ...

                    # Only our .pcap files store session/packet #s.
                    sesh_num = getattr(self.sniffer, 'sesh_num', "#")
                    pkt_num = getattr(self.sniffer, 'pkt_num', idx)

                    # .pcap files might not store packets' capture time.
                    capture_time = getattr(self.sniffer, 'cap_time', 0.0)

                    # (Un)package and write/display packet information.
                    packet_data = (sesh_num,      # Session Number
                                   pkt_num,       # Packet Number
                                   capture_time,  # Time
                                   src_mac,       # Source MAC Address
                                   dst_mac,       # Destination MAC Address
                                   src_ip,        # Source IP Address
                                   dst_ip,        # Destination IP Address
                                   proto,         # Network Protocol
                                   len(net_pl),   # Length
                                   info,          # Display Data
                                   net_pl)        # Payload
                    loaded_packets.append(packet_data)

                except Exception as e:
                    print(f"Error extracting packet information: {str(e)}")

            # Populate the data table with the extracted information.
            for packet in loaded_packets:
                new_item = self.tree.insert("", 'end', values=packet)
                self.tree.see(new_item)

            # Packets now in data table; enable the Save and Clear buttons.
            self.save_button.config(state=tk.NORMAL)
            self.clear_button.config(state=tk.NORMAL)

        except Exception as e:
            messagebox.showerror("Error", f"Error loading packets: {str(e)}")

    def update_gui(self: 'SnifferGUI') -> None:
        """
        Updates the GUI to reflect changes in `self.tree` brought 
        about by incoming packets processed from `self.queue`. 
        `UPDATES_PER_SECOND` refresh rate.
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
        packet by right-clicking it. Dumps the payload in either 
        raw bytestring, hexadecimal, or ASCII format.
        """
        selected_item = self.tree.selection()
        if selected_item:
            values = self.tree.item(selected_item, 'values')
            if values:
                # values = (sesh #, pkt #, time, src MAC, dst MAC, 
                #           src IP, dst IP, proto, len, info, payload)
                payload = values[-1]

                # Create a Toplevel window for displaying raw data.
                raw_data_window = tk.Toplevel(self.root)
                raw_data_window.title("Raw Data Viewer")
                raw_data_window.geometry('1400x800')

                # Set the initial format to "Raw Byte String".
                format_var = tk.StringVar(raw_data_window)
                format_var.set("Raw Byte String")

                # Create a Text widget to display the raw data.
                text_widget = tk.Text(raw_data_window, wrap=tk.WORD)
                text_widget.insert(tk.END, payload)
                text_widget.pack(expand=True, fill=tk.BOTH)

                # Set the text widget to read-only.
                text_widget.config(state=tk.DISABLED)

                # Create a dropdown list for different viewing formats.
                format_menu = tk.OptionMenu(
                    raw_data_window, 
                    format_var, 
                    "Raw Bytestring", 
                    "ASCII", 
                    "Hexadecimal",
                    command=lambda x: self.update_format(x, text_widget, payload))
                format_menu.pack()

    def update_format(self: 'SnifferGUI', format_type: str, 
                      text_widget: tk.Text, payload: str) -> None:
        """
        Update the display format of the payload data in:
            - Raw Bytestring
            - ASCII
            - Hexadecimal
        """
        # NOTE: because I can't figure out a way to both simultaneously store
        # `payload` in self.Treeview and prevent it from being displayed AND
        # from being turned into a string, we need a way to convert the string
        # representation of a bytestring into ASCII; we trust the input as valid,
        # i.e., accurately depicting the actual payload of the packet we care about.

        # Convert payload to desired format.
        temp_pl = payload
        if format_type == 'ASCII':
            # Immediately replace all '\x??' sequences with fromhex(??).
            def replace_hex_escapes(match):
                hex_value = match.group(1)
                byte_value = bytes.fromhex(hex_value)
                return chr(byte_value[0])
            temp_pl = re.sub(r'\\x([0-9A-Fa-f]{2})', replace_hex_escapes, payload)
            
            # Replace any remaining non-printable chars with "."; trim "b'" and "'".
            data_to_display = ''.join(
                chr(ord(char)) if 0x20 <= ord(char) <= 0x7E else '.' 
                for char in temp_pl
            )[2:-1]
        elif format_type == 'Hexadecimal':
            # Convert the payload to Hexadecimal.
            tmp_pl = temp_pl.encode('utf-8', errors='replace')
            hex_data = ' '.join(f'{byte:02X}' for byte in tmp_pl)
            data_to_display = hex_data
        else:
            # Display the Raw Bytestring, with replacement for non-decodable bytes.
            data_to_display = temp_pl.encode('utf-8', errors='replace')

        # Update the text widget with the chosen format.
        text_widget.config(state=tk.NORMAL)
        text_widget.delete('1.0', tk.END)
        text_widget.insert(tk.END, data_to_display)
        text_widget.config(state=tk.DISABLED)

    def sort_treeview(self: 'SnifferGUI', col: str) -> None:
        """
        Sort the data table in the GUI based on the selected column.
        Toggles between ASC (default) and DESC alphanumerical order.
        """
        # Toggle sorting order if we're sorting the same column; else asc order.
        self.asc_order = not self.asc_order if self.sorting_col == col else True

        # Create a list of tuples with the sort value and item's ID.
        items = [(float(self.tree.set(k, col)) 
                  if col in ['Time', 'No.', 'Length']
                  else self.tree.set(k, col),
                  k)
                for k in self.tree.get_children('')]
        items.sort(reverse=self.asc_order)

        # Rearrange items in sorted positions.
        for index, (val, k) in enumerate(items):
            self.tree.move(k, '', index)

        # Update sorting column.
        self.sorting_col = col
    
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
