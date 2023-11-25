import threading
import tkinter as tk
from tkinter import ttk
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

            # Increment packet number and get current time
            packet_number += 1
            current_time = round(time.time() - start_time, 6)

            # Use a lock to prevent simultaneous access
            with self.lock:
                if not self.queue.full():
                    self.queue.put((packet_number, current_time, src_mac, dest_mac, eth_proto, data))

    def stop(self):
        self.running = False
        self.join()     # Wait for the thread to finish before stopping


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


def main():
    root = tk.Tk()
    packet_queue = queue.Queue(maxsize=1000)    # Set a maximum size for the queue
    lock = threading.Lock()                     # Create a lock for thread safety
    gui = SnifferGUI(root, packet_queue, lock)
    root.mainloop()


if __name__ == "__main__":
    main()
