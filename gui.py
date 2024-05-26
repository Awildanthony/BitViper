from sniffer import *
from scapy.all import Ether, rdpcap, wrpcap
from queue import Queue
from tkinter import ttk, messagebox
import tkinter as tk
import threading
import socket
import time
import os


MAX_PACKET_SIZE = 65535
MAX_PACKET_QUEUE_SIZE = 1000
SOCKET_TIMEOUT = 1
UPDATES_PER_SECOND = 10


class PacketSniffer(threading.Thread):
    """
    TODO
    """
    session_number_lock = threading.Lock()
    first_launch = True

    def __init__(self, queue, lock):
        super().__init__()
        self.queue = queue
        self.lock = lock
        self.running = False
        self.hex_data = None
        self.file_name = "captured_packets.pcap"
        self.sesh_num, self.pkt_num = self.fetch_recent_row()

    # TODO: add precise function signature.
    def fetch_recent_row(self):
        """
        Return the session number and packet number of the last packet received.
        """
        # Get the current session while sniffer runs in parallel.
        with PacketSniffer.session_number_lock:
            try:
                # Separate file used as IPC for session number.
                with open('sesh_num.txt', 'r') as f:
                    session_number = int(f.read().strip())
            except FileNotFoundError:
                session_number = 1
                with open('sesh_num.txt', 'w') as f:
                    f.write(str(session_number))
            except Exception as e:
                print(f"Error loading session number: {e}")
                session_number = 1
            if PacketSniffer.first_launch:
                # Reset session number to 1 only on the first launch
                session_number = 1
                PacketSniffer.first_launch = False
            return session_number, 0

    # TODO: add precise function signature.
    def run(self):
        """
        Begin a live packet capture session.
        """
        # Establish a socket.
        connection = socket.socket(socket.AF_PACKET,   # data link layer
                                   socket.SOCK_RAW,    # raw socket
                                   socket.ntohs(3))    # all packets

        # Set a timeout to prevent blocking.
        connection.settimeout(SOCKET_TIMEOUT)
        start_time = time.time()
        self.pkt_num = 0

        while self.running:
            try:
                # Read raw data of IP packet from socket, up to max size.
                raw_data, addr = connection.recvfrom(MAX_PACKET_SIZE)
            except socket.timeout:
                continue

            packet_data = (0, 0, '0.000000', 'N/A', 'N/A', 'N/A', 0, 'N/A')
            try:
                # Parse raw data from the network frame into an ethernet frame,
                # obtaining raw 'Protocol' and 'Data' columns.
                dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
                eth_protocol = eth_proto
                self.hex_data = data

                # Check the Ethernet protocol and unpack accordingly
                if eth_proto == 'IPv4':
                    version, header_length, ttl, \
                        proto, src, target, data = unpack_ipv4(data)
                    proto = get_proto_name(proto)

                    # Check the IPv4 protocol and unpack accordingly
                    if proto == 'ICMP':
                        icmp_type, code, checksum, data = unpack_icmp(data)
                        eth_protocol = 'ICMP'
                        self.hex_data = data

                    elif proto == 'TCP':
                        # Omitted flags: urg, ack, psh, rst, syn, fin.
                        src_port, dst_port, seq, ack, _, _, _, _, _, _, \
                            http_method, http_url, \
                            status_code, data = unpack_tcp(data)
                        eth_protocol = 'TCP'
                        self.hex_data = data

                        # Call to `unpack_tcp()` found HTTP(S) data.
                        if http_method and http_url:
                            dst_port = get_proto_name(dst_port) 
                            if digits_in(dst_port):
                                # This is a non-conventional port (unknown).
                                eth_protocol = 'HTTP(S)'
                            else:
                                eth_protocol = dst_port
                        else:
                            try:
                                non_http_data = (f'{src_port} → '
                                                 f'{dst_port} [???] Seq={seq} '
                                                 f'Ack={ack} {data}'
                                                ).encode('utf-8').decode('utf-8')
                            except UnicodeDecodeError as error:
                                non_http_data = "Decoding error:\n{}".format(error)
                            data = non_http_data

                    elif proto == 'UDP':
                        src_port, dst_port, size, data = unpack_udp(data)
                        eth_protocol = 'UDP'
                        self.hex_data = data

                        # DNS
                        if src_port in [53, 56710] or dst_port in [53, 56710]:
                            eth_protocol = 'DNS'
                            data = format_dns_data(data)

                        else: # UDP (other)
                            try:
                                data = (f'{src_port} → {dst_port} Len={size}'
                                        ).encode('utf-8').decode('utf-8')
                            except UnicodeDecodeError as error:
                                data = "Decoding error:\n{}".format(error)

                    else:  # IPv4 (other)
                        eth_protocol = 'IPv4'
                        self.hex_data = data

                # DNS (non-IPv4)
                elif eth_proto == '56710':
                    try:
                        src_port, dst_port, size, data = unpack_udp(data)
                        self.hex_data = data
                        data = format_dns_data(data)
                    # TODO: fix this
                    except Exception as buffer_error:
                        eth_protocol = 'DNS'
                
                # ARP
                # TODO: implement this
                elif eth_proto == '1544':
                    eth_protocol = 'ARP'

                # Increment packet number and get current time
                self.pkt_num += 1
                current_time = '{:.6f}'.format(time.time() - start_time)
                current_time = current_time.ljust(8, '0')

                # Use a lock to prevent simultaneous access
                with self.lock:
                    if not self.queue.full():
                        packet_data = (self.sesh_num, 
                                       self.pkt_num, 
                                       current_time,
                                       src_mac,
                                       dest_mac,
                                       eth_protocol,
                                       len(raw_data), data)

                        try:
                            self.queue.put(packet_data)
                            # Write the packet to the pcap file.
                            wrpcap(self.file_name, Ether(raw_data), append=True)

                        except Exception as queue_error:
                            print(f"Error adding packet to queue: {queue_error}")

            except Exception as e:
                print(f"Error processing packet: {e}")
                print(f"Packet data: {packet_data}")

    def get_captured_packets(self):
        # Retrieve all captured packets from the queue
        with self.lock:
            captured_packets = list(self.captured_packets.queue)
            self.captured_packets = Queue()     # Clear the queue after retrieval
        return captured_packets

    def stop(self):
        self.running = False
        self.join()  # Wait for the thread to finish before stopping
        self.sesh_num += 1
        self.pkt_num = 1

        # Save the session number to a file
        with open('sesh_num.txt', 'w') as f:
            f.write(str(self.sesh_num))

    def get_packet_info(self):
        return (
            str(self.sesh_num),
            str(self.pkt_num),
            '{:.6f}'.format(time.time() - self.start_time),
            str(self.src_mac),
            str(self.dest_mac),
            str(self.eth_protocol),
            str(len(self.hex_data)),
            self.hex_data,
        )



class SnifferGUI:
    def __init__(self, root, packet_queue, lock):
        self.root = root
        self.packet_queue = packet_queue
        self.lock = lock
        self.sniffer = None
        self.sorting_column = None
        self.sorting_order = True   # Default sorting order is ascending
        self.capture_running = False
        self.setup_ui()

        # Cannot save as .pcap file if empty datatable
        self.save_button.config(state=tk.DISABLED)

    def setup_ui(self):
        # Set launch header and window dimensions
        self.root.title('SocketSloth')
        self.root.geometry('2650x1000')

        # Set data font style and row height
        style = ttk.Style()
        style.configure('Treeview', font=('Script', 11), rowheight=35)

        # Set buttons
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

        # Add a search bar
        search_frame = tk.Frame(self.root)
        search_frame.pack(side=tk.TOP, fill=tk.X)

        self.search_entry = tk.Entry(search_frame, width=30)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        search_button = tk.Button(search_frame, 
                                  text="Search", 
                                  command=self.apply_search)
        search_button.pack(side=tk.LEFT)

        # Set header titles
        self.tree = ttk.Treeview(self.root, columns=(
            'Sesh', 'No.', 'Time', 'Source', 
            'Destination', 'Protocol', 'Length', 'Data'
            ), show='headings')
        self.tree.heading('Sesh', text="Sesh")
        self.tree.heading('No.', text="No.")
        self.tree.heading('Time', text="Time")
        self.tree.heading('Source', text="Source")
        self.tree.heading('Destination', text="Destination")
        self.tree.heading('Protocol', text="Protocol")
        self.tree.heading('Length', text="Length")
        self.tree.heading('Data', text="Data")

        # Fetch screen dimensions
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        # Set header titles with binding to enable sorting.
        # Width ratios should add up to 0.9 != 1.0, for some reason
        for col, ratio in [('Sesh', 0.03),
                           ('No.', 0.05), 
                           ('Time', 0.08), 
                           ('Source', 0.12), 
                           ('Destination', 0.12), 
                           ('Protocol', 0.08), 
                           ('Length', 0.08), 
                           ('Data', 0.34)]:
            self.tree.column(col, anchor='center', width=int(screen_width * ratio))
            self.tree.heading(col, text=col, anchor='center', 
                              command=lambda c=col: self.sort_treeview(c))

        self.tree.pack(fill=tk.BOTH, expand=True)

        # Initialize right-click menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Inspect Payload", 
                                      command=self.show_raw_data)

        # Bind the right-click event to the Treeview
        self.tree.bind('<Button-3>', self.show_context_menu)

        self.update_gui()

    def start_sniffer(self):
        if not self.sniffer or not self.sniffer.running:
            # If the sniffer is not created or not running, create a new sniffer
            self.sniffer = PacketSniffer(self.packet_queue, self.lock)

            # Check if the 'first_launch' attribute exists in the sniffer class
            if hasattr(PacketSniffer, 'first_launch'):
                  # Pass the 'first_launch' value.
                self.sniffer.first_launch = PacketSniffer.first_launch

            self.sniffer.running = True
            self.sniffer.start()

        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.clear_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.DISABLED)
        self.load_button.config(state=tk.DISABLED)
        self.capture_running = True

    def stop_sniffer(self):
        self.sniffer.stop()
        self.sniffer = None  # Set to None to create a new instance on start
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

    def clear_table(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None  # Set to None to create a new instance on start
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.capture_running = False
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.clear_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.DISABLED)

        # Reset the session number to 1
        with PacketSniffer.session_number_lock:
            self.sesh_num, self.pkt_num = 1, 0
            with open('sesh_num.txt', 'w') as f:
                f.write("1")
    
    def on_closing(self):
        if self.sniffer:
            self.sniffer.stop()
        # Delete the ICP files
        try:
            os.remove('sesh_num.txt')
            os.remove('captured_packets.pcap')
        except FileNotFoundError:
            pass  # If the file doesn't exist, there's no need to delete it
        self.root.destroy()

    def save_packets(self):
        if self.tree.get_children():  # Check if there are packets in the datatable
            try:
                # Ask the user for the file name and location
                file_path = tk.filedialog.asksaveasfilename(defaultextension='.pcap', 
                                                            filetypes=[("PCAP files", 
                                                                        '*.pcap')])
                if not file_path:
                    return

                # Write the captured packets to the specified file
                captured_packets = list(self.packet_queue.queue)
                wrpcap(file_path, 
                       [Ether(data) for _, _, _, _, _, data in captured_packets])

                # Clear the packet_queue
                while not self.packet_queue.empty():
                    self.packet_queue.get()

            except Exception as e:
                messagebox.showerror("Error", f"Error saving packets: {str(e)}")
        else:
            # If the datatable is empty, show an info message
            messagebox.showinfo('Info', "No packets to save.")

    def load_packets(self):
        try:
            # Prompt the user to select a .pcap file
            file_path = tk.filedialog.askopenfilename(defaultextension='.pcap', 
                                                      filetypes=[("PCAP files", 
                                                                  '*.pcap')])
            if not file_path:
                return

            # Read the selected .pcap file using Scapy
            packets = rdpcap(file_path)

            # Extract relevant information from the loaded packets
            captured_packets = []
            for idx, packet in enumerate(packets, start=1):
                try:
                    dest_mac, src_mac, eth_proto, data = ethernet_frame(bytes(packet))
                    eth_protocol = eth_proto  # (default value)
                    self.hex_data = data  # (default value)

                    # Check the Ethernet protocol and unpack accordingly
                    if eth_proto == 'IPv4':
                        version, header_length, ttl, \
                            proto, src, target, data = unpack_ipv4(data)

                        # Check the IPv4 protocol and unpack accordingly
                        if proto == 1:  # ICMP
                            icmp_type, code, checksum, data = unpack_icmp(data)
                            eth_protocol = 'ICMP'
                            self.hex_data = data

                        elif proto == 6:  # TCP
                            # Omitted flags: urg, ack, psh, rst, syn, fin.
                            src_port, dst_port, seq, ack, _, _, _, _, _, _, \
                                http_method, http_url, \
                                status_code, data = unpack_tcp(data)
                            eth_protocol = 'TCP'
                            self.hex_data = data

                            # call to unpack_tcp() found HTTP(S) data
                            if http_method and http_url:    
                                if dst_port == 80 or src_port == 80:
                                    eth_protocol = 'HTTP'
                                if dst_port == 443 or src_port == 443:
                                    eth_protocol = 'HTTPS'
                                else:
                                    # non-conventional port (unknown)
                                    eth_protocol = 'HTTP(S)'
                            else:
                                try:
                                    non_http_data = (f'{src_port} → '
                                                     f'{dst_port} [???] Seq={seq} '
                                                     f'Ack={ack} {data}'
                                                    ).encode('utf-8').decode('utf-8')
                                except UnicodeDecodeError as error:
                                    non_http_data = "Decoding error:\n{}".format(error)
                                data = non_http_data

                        elif proto == 17:  # UDP
                            src_port, dst_port, size, data = unpack_udp(data)
                            eth_protocol = 'UDP'
                            self.hex_data = data

                            # DNS
                            if src_port in [53, 56710] or dst_port in [53, 56710]:
                                eth_protocol = 'DNS'
                                data = format_dns_data(data)

                            else: # UDP (other)
                                try:
                                    data = (f'{src_port} → {dst_port} Len={size}'
                                            ).encode('utf-8').decode('utf-8')
                                except UnicodeDecodeError as error:
                                    data = "Decoding error:\n{}".format(error)

                        else:  # IPv4 (other)
                            eth_protocol = 'IPv4'
                            self.hex_data = data

                    # DNS (non-IPv4)
                    elif eth_proto == '56710':
                        try:
                            src_port, dst_port, size, data = unpack_udp(data)
                            eth_protocol = 'DNS'
                            self.hex_data = data
                            data = format_dns_data(data)
                        # TODO: fix this
                        except Exception as buffer_error: 
                            eth_protocol = 'DNS'

                    # ARP
                    # TODO: implement this
                    elif eth_proto == '1544':
                        eth_protocol = 'ARP'

                    # .pcap files typically do not store session_number
                    if hasattr(self.sniffer, 'session_number'):
                        session_number = self.sniffer.sesh_num
                    else:
                        session_number = "#"

                    # .pcap files typically do not store packet_number
                    if hasattr(self.sniffer, 'pkt_num'):
                        index = self.sniffer.pkt_num
                    else:
                        index = idx

                    # .pcap files might not have a start_time attribute
                    start_time = getattr(self.sniffer, 'start_time', 0.0)

                    # Customize the extraction based on your packet structure
                    packet_info = (
                        session_number,
                        index,
                        '{:.6f}'.format(time.time() - start_time),
                        src_mac,
                        dest_mac,
                        eth_protocol,
                        len(bytes(packet)),
                        data
                    )

                    captured_packets.append(packet_info)

                except Exception as e:
                    print(f"Error extracting packet information: {str(e)}")

            # Populate the data table with the extracted information
            for packet_info in captured_packets:
                new_item = self.tree.insert("", 'end', values=packet_info)
                self.tree.see(new_item)

            # Packets are now in the data table; enable the Save and Clear buttons.
            self.save_button.config(state=tk.NORMAL)
            self.clear_button.config(state=tk.NORMAL)

        except Exception as e:
            messagebox.showerror('Error', f"Error loading packets: {str(e)}")


    def update_gui(self):
        if self.sniffer:
            while not self.packet_queue.empty():
                packet = self.packet_queue.get()
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
                    # Enable Save iff table has packet(s) and live capture is off.
                    self.save_button.config(state=tk.NORMAL)

        self.root.after(1000 // UPDATES_PER_SECOND, self.update_gui)

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)  # Identify the item under the cursor
        if item:
            self.context_menu.post(event.x_root, event.y_root)

    def show_raw_data(self):
        selected_item = self.tree.selection()
        if selected_item:
            values = self.tree.item(selected_item, 'values')
            if values:
                payload = values[-1]  # Assuming payload is the last item in values
                if self.sniffer:  # Sniffer is running
                    hex_data = self.sniffer.hex_data
                else:  # Sniffer is stopped or data is imported
                    # Extract the payload data from the displayed string
                    start_index = payload.find("b'") + 2
                    end_index = payload.find("'", start_index)
                    hex_data_str = payload[start_index:end_index]
                    # Filter out non-hexadecimal characters
                    hex_data_str = filter_non_hex(hex_data_str)
                    # Convert the payload data back to raw hex
                    hex_data = bytes.fromhex(hex_data_str)

                try:
                    # Try to decode as UTF-8
                    decoded_data = hex_data.decode('utf-8')
                except UnicodeDecodeError:
                    # If decoding fails, display raw data as hexadecimal
                    decoded_data = ' '.join(f'{byte:02X}' for byte in hex_data)

                # Create a Toplevel window for displaying raw data
                raw_data_window = tk.Toplevel(self.root)
                raw_data_window.title("Raw Data Viewer")
                raw_data_window.geometry('1400x800')

                # Set the initial format to "Raw Hex Data"
                format_var = tk.StringVar(raw_data_window)
                format_var.set("Raw Hex Data")

                # Create a Text widget to display the raw data
                text_widget = tk.Text(raw_data_window, wrap=tk.WORD)
                text_widget.insert(tk.END, decoded_data)
                text_widget.pack(expand=True, fill=tk.BOTH)

                # Set the text widget to read-only
                text_widget.config(state=tk.DISABLED)

                # Create a dropdown list for different viewing formats
                format_menu = tk.OptionMenu(raw_data_window, 
                                            format_var, 
                                            "Raw Hex Data", 
                                            "ASCII", 
                                            command=lambda x: 
                                                self.update_format(x, text_widget))
                format_menu.pack()

    def update_format(self, format_type, text_widget):
        if format_type == 'ASCII':
            # Get the raw hex data string from the text widget
            raw_hex_data_str = text_widget.get('1.0', tk.END).strip()
            # Sniffer is running
            if self.sniffer:
                hex_data = self.sniffer.hex_data
            # Sniffer is stopped or data is imported
            else:
                # Convert the raw hex data string to bytes
                try:
                    hex_data = bytes.fromhex(raw_hex_data_str)
                except ValueError:
                    # If the string is not valid hexadecimal, return
                    return

            # Decode the raw hex data to ASCII
            ascii_data = ''.join(chr(byte) if 32 <= byte < 127 else '.' for byte in hex_data)

            # Update the text widget with the ASCII data
            text_widget.config(state=tk.NORMAL)
            text_widget.delete('1.0', tk.END)
            text_widget.insert(tk.END, ascii_data)
            text_widget.config(state=tk.DISABLED)
        else:
            # Display the raw hex data
            text_widget.config(state=tk.NORMAL)
            text_widget.delete(1.0, tk.END)
            text_widget.insert(tk.END, 
                               ' '.join(f'{byte:02X}' for byte in self.sniffer.hex_data))
            text_widget.config(state=tk.DISABLED)

    def sort_treeview(self, col):
        # Check if we're sorting the same column
        if self.sorting_column == col:
            # Toggle sorting order
            self.sorting_order = not self.sorting_order
        else:
            # Set default sorting order to ascending for a new column
            self.sorting_order = True

        items = [(float(self.tree.set(k, col)) if col in ['Time', 'No.', 'Length'] else self.tree.set(k, col), k) for k in self.tree.get_children('')]
        items.sort(reverse=self.sorting_order)

        # Rearrange items in sorted positions
        for index, (val, k) in enumerate(items):
            self.tree.move(k, '', index)

        # Update sorting column
        self.sorting_column = col
    
    def apply_search(self):
        # Convert the query to lowercase for case-insensitive search.
        query = self.search_entry.get().lower()
        matching_items = []

        for item_id in self.tree.get_children():
            item = self.tree.item(item_id, 'values')
            if any(query in str(value).lower() for value in item):
                matching_items.append(item_id)

        # Clear current selection and select the matching items
        self.tree.selection_remove(self.tree.selection())
        self.tree.selection_add(*matching_items)
        self.tree.see(matching_items[0] if matching_items else "") # Jump to first one


def main():
    root = tk.Tk()
    packet_queue = Queue(maxsize=MAX_PACKET_QUEUE_SIZE)  # Set a max size for queue
    lock = threading.Lock()                              # Create a lock for threads
    gui = SnifferGUI(root, packet_queue, lock)

    # Bind the on_closing method to the closing event
    root.protocol('WM_DELETE_WINDOW', gui.on_closing)

    root.mainloop()


if __name__ == '__main__':
    main()
