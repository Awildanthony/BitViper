1.) Some warnings while sniffer is running:
```
WARNING: PcapWriter: unknown LL type for bytes. Using type 1 (Ethernet)
WARNING: more PcapWriter: unknown LL type for bytes. Using type 1 (Ethernet)
```

2.) Cannot load DNS packets (might have to do with #1).
    - On that note, DNS packets sometimes still bypass parsing (their display data remains in bytes form)?

3.) ARP not implemented yet.

4.) Color-coding for packets of different protocols not implemented yet.

5.) Dynamic column/window contents shifting not implemented yet.

6.) Support for MAC & Windows not tested/implemented yet.
