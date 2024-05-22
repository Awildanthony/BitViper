# "SocketSloth" Packet Sniffer

### What is a packet sniffer?
A packet sniffer is a computer program, such as Wireshark, or specialized piece of hardware, such as a packet capture appliance, that logs and can analyze traffic passing over a computer network. It is a masssively helpful and popular tool in network forensics.

### Why this choice in project?
I am interested in cyber security. As a current student, I don't yet have the wherewithal knowledge to build an offensive or defensive security tool. A network analyzer is more of a forensic and debugging tool (aside from spying on people), which is more in line with my experience.

### How is the codebase structured?
The codebase is spread across two files: `gui.py` and `sniffer.py`. The latter can be thought of as a custom library equipped with functions I've written, used to manipulate the incoming packets and the data within them. The former is how the user sees and interacts with the data from a UX/UI experience inside of a graphical user interface (GUI), which makes use of the `tkinter` library.

### How does the user launch the program?
The GUI is launched with

Linux: `sudo python3 ./gui.py`
Windows: `py ./gui.py`

That's it. I purposely wanted the UX to be simple: no running scripts across multiple consoles here. Within the GUI, things are very intuitive: you start the packet capture process with "Start", and you end it with "Stop". You can choose to start a new capture session by clicking "Start" again, which will increment the Sesh count, and restart the time and packet counters. You can wipe the table with "Clear", which resets everything. Clicking any column header toggles alpha-numeric sorting of its data. Additionally, you can save and load your own `.pcap` files. At any point, you can analyze individual packets with the "Inspect Payload" feature: right-click on any packet (row), and toggle between the raw hex data and ASCII decodings.

### What precisely happens when the user clicks "Start"?

1.) **User Interaction:** \
Upon clicking "Start" in the GUI, the associated callback function `startButtonClicked()` is triggered.

2.) **Callback Execution:** \
`startButtonClicked()` initializes the packet sniffing process by calling the `initializePacketSniffing()` function.

3.) **Initialization:** \
Within `initializePacketSniffing()`, necessary data structures are set up, network interfaces are configured using functions like `setupNetworkInterfaces()`, and the packet capture library (e.g., `libpcap`) is initialized.

4.) **Start Packet Capture Loop:** \
After initialization, `initializePacketSniffing()` enters a loop where it continuously captures packets using the `capturePackets()` function.
`capturePackets()` utilizes the packet capture library's functions (e.g., `pcap_loop()`) to capture packets from the network interface(s).

5.) **Packet Filtering:** \
Captured packets are filtered based on user-defined criteria using functions like `applyPacketFilters()`. `applyPacketFilters()` examines each packet and determines whether it matches the specified filters, such as protocol type or IP addresses.

6.) **Packet Parsing:** \
Filtered packets are parsed to extract relevant information using functions like `parsePacket()`. `parsePacket()` examines the packet's header fields to extract details such as source/destination IP addresses, MAC addresses, and protocol-specific data.

7.) **Data Processing:** \
Extracted packet data is processed according to application requirements using functions like `processPacketData()`. `processPacketData()` formats the extracted information for display in the GUI or performs real-time analysis, depending on user preferences.

8.) **GUI Update:** \
As new packets are captured and processed, the GUI is updated to reflect the latest information using functions like `updateGUI()`.`updateGUI()` modifies GUI components such as tables, graphs, or text fields to display packet details in real-time.

9.) **User Interaction (Optional):** \
While packet capture is ongoing, the user may interact with the GUI to pause, resume, or stop the packet capture process, facilitated by functions like `pausePacketCapture()` or `stopPacketCapture()`.

10.) **Packet Capture Termination:** \
Packet capture continues until the user explicitly stops it or a termination condition is met. Upon termination, cleanup tasks are performed using functions like `cleanup()` to close network interfaces and release resources acquired during packet capture.

11.) **Finalization:** \
After packet capture stops, finalization tasks may be executed using functions like `finalizePacketCapture()`. `finalizePacketCapture()` summarizes captured data, generates reports, or presents analysis results to the user, depending on application requirements.

### What protocols are currently supported?
The following is a complete list of all the protocols that this program supports, meaning that the "Protocol" and "Data" columns for the respective packet should actually present human-readable text that gives useful information about that packet, at a glance. Example: (ARP) "Who has 123.132.34? Tell 456.654.45". I chose this list becauase it seemed natural and comprehensive. Any unsupported protocol will simply have its protocol number shown in "Protocol" and raw payload bytestring in "Data".

1.) **ARP: Address Resolution Protocol** (Layer 2): \
Resolves IP addresses to MAC addresses on a local network segment. [IN-PROGRESS]

2.) **IPv4: Internet Protocol Version 4** (Layer 3): \
Provides identification and location addressing for devices on a network and route packets across multiple networks.

3.) **ICMP: Internet Control Message Protocol** (Layer 3): \
Used for diagnostic and control purposes for IP networks, such as ping.

4.) **TCP: Transmission Control Protocol** (Layer 4): \
Provides reliable, ordered, and error-checked delivery of data between applications.

5.) **UDP: User Datagram Protocol** (Layer 4): \
A lightweight, connectionless protocol used for datagram-oriented network communication.

6.) **HTTP: Hypertext Transfer Protocol** (Layer 7): \
A protocol for transmitting hypermedia documents, such as HTML files, over the internet.

7.) **HTTPS: Hypertext Transfer Protocol Secure** (Layer 7): \
An extension of HTTP with added security features like encryption and authentication.

8.) **DNS: Domain Name System** (Layer 7): \
Translates domain names to IP addresses and vice-versa, enabling devices to locate resources on a network using human-readable names.

### How can I test this code?
The way I did it, which I believed was best, was to save a packet capture file from Wireshark (or any other reliable packet analyzer). I included such a file, called `example1.pcap`, for reference. After you import it into the Ubuntu VM using the designated spice client folder, you can cross-reference it with this program to ensure it follows intended design and behavior. The biggest challenge in debugging this tool is to naturally-enduce certain network behavior, which is very difficult. Certain features of Wireshark also served as motivation and inspiration for subsequent additional features of this project, such as which protocols to support or changes made to the GUI.

### Were there any encountered difficulties?
Yes. I'll include a list of persistent bugs that I'm aware of, below. Ironically, some of the more difficult parts were not necessary supporting the packet capture; but rather, they were supporting a friendly, intuitive, and useful UX design. Specifically, the choice to support a session number --- thereby allowing multiple different packet captures to coalesce into one --- was a very pesky and questionable one. Things like ensuring certain conditions are met for the state of the capture function, including when to wipe/discard information, made it a hard balancing act to engineer. On the more network-intensive side of things, unwrapping each of the packets just required some reasearch into packet header architecture (specific to which protocol(s) I want to support, as well). After that, if you have the knowledge of what each packet's payload looks like for a particular protocol that you want to support, you can just continually support new protocols. With this being a somewhat large and complex program, organizing the code likewise required a lot of thought and care, and can be improved still.

### List of (known) persistent bugs:
- In order to inspect packets taken from a live capture session, the capture session needs to still be running (i.e., you can't press "Stop" first). This bug is pesky, and comes from wanting to include a session number as a data column.
- Inspecting packets from a loaded `.pcap` file generally doesn't work, but this is just due to some confusion between translating between byte strings and hexadecimal, so it should be a relatively simple fix.
- The support between capturing, loading, and saving packets is not 100% streamlined; that is, you currently cannot take a capture session saved from this program, and then try to load it into Wireshark.
- ...

### What would I add to this project moving forward?
Initially, the motivation for creating this tool was not just to create a clone of Wireshark, albeit in Python. The goal was to do things that Wireshark *doesn't* do, with the ultimate goal of producing a tool that allows users to splice and edit their own custom `.pcap` files. Returning to the difficulty of naturally-encountering certain network traffic flow for testing purposes, that is very hard; as a possible solution, custom `.pcap` files could perhaps in the future be read and those packets artificially re-transmitted across a network for enriched network testing capabilities. In the past, I did a project on a Network Policy-as-Code solution: a piece of software that semi-automatizes any network security policy into a sort of IDS. Coalescing that project with this one would involve more deep-packet inspection capabilities.
