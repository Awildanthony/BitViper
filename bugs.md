1.) Some warnings while sniffer is running (only on Virtual Machines?):
```
WARNING: PcapWriter: unknown LL type for bytes. Using type 1 (Ethernet)
WARNING: more PcapWriter: unknown LL type for bytes. Using type 1 (Ethernet)
```

2.) Cannot load DNS packets (might have to do with #1).
    - On that note, DNS packets sometimes still bypass parsing (their display data remains in bytes form)?

3.) Color-coding for packets of different protocols not implemented yet.

4.) GUI window "spasms" while enforcing minimum window dimensions during resizing by user.

5.) Support for MAC & Windows not tested/implemented yet.
