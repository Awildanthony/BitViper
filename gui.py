import threading
import tkinter as tk
from tkinter import ttk
import socket
import time
from sniffer import *
import queue


class PacketSniffer(threading.Thread):
    def __init__(self, queue):
        super().__init__()
        self.queue = queue
        self.running = False

    def run(self):
        connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        packet_number = 0
        start_time = time.time()

        while self.running:
            raw_data, addr = connection.recvfrom(65535)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

            # Increment packet number and get current time
            packet_number += 1
            current_time = round(time.time() - start_time, 6)

            # Add the packet data to the queue instead of the treeview
            self.queue.put((packet_number, current_time, src_mac, dest_mac, eth_proto, data))

    def stop(self):
        self.running = False
        self.join()  # Wait for the thread to finish


def main():
    # Create a Tkinter window
    root = tk.Tk()
    root.title("Packet Sniffer")

    # Set launch dimensions
    root.geometry("2650x1000")

    # Create a queue for communication between threads
    packet_queue = queue.Queue()

    # Set text font, text size, row height, etc.
    style = ttk.Style()
    style.configure("Treeview", font=('Script', 11), rowheight=35)

    # Create a treeview for the packet data
    tree = ttk.Treeview(root, columns=("No.", "Time", "Source", "Destination", "Protocol", "Data"), show="headings")
    tree.heading("No.", text="No.")
    tree.heading("Time", text="Time")
    tree.heading("Source", text="Source")
    tree.heading("Destination", text="Destination")
    tree.heading("Protocol", text="Protocol")
    tree.heading("Data", text="Data")

    # Get screen dimensions (2880 x 1800)
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    for col, ratio in [("No.", 0.05), ("Time", 0.10), ("Source", 0.15), ("Destination", 0.15), ("Protocol", 0.10), ("Data", 0.35)]:
        tree.column(col, anchor="center", width=int(screen_width*ratio))    # Manually set each column's width
        tree.heading(col, text=col, anchor="center")                        # Configure columns to stretch with the window

    tree.pack(fill=tk.BOTH, expand=True)

    def start_sniffer(packet_queue):
        global sniffer
        sniffer = PacketSniffer(packet_queue)
        sniffer.running = True
        sniffer.start()
        start_button.config(state=tk.DISABLED)  # Disable the start button when it's clicked
        stop_button.config(state=tk.NORMAL)     # Enable the stop button when the start button is clicked

    def stop_sniffer():
        sniffer.stop()
        start_button.config(state=tk.NORMAL)    # Enable the start button when the stop button is clicked
        stop_button.config(state=tk.DISABLED)   # Disable the stop button when it's clicked

    # Create start and stop buttons
    start_button = tk.Button(root, text="Start", command=lambda: start_sniffer(packet_queue), bg="green")
    start_button.pack()
    stop_button = tk.Button(root, text="Stop", command=stop_sniffer, state=tk.DISABLED, bg="red")  # Disable the stop button initially
    stop_button.pack()

    # Periodically check the queue (every second) and update the GUI
    def update_gui():
        while not packet_queue.empty():
            packet = packet_queue.get()
            new_item = tree.insert("", "end", values=packet)     # Insert the new item
            tree.see(new_item)                                   # Automatically scroll to the new item
        root.after(1000, update_gui)

    update_gui()
    root.mainloop()


if __name__ == "__main__":
    main()
