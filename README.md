### High-Level Architecture

```text
Packets
   ↓
Load Balancer
   ↓
Detection Server <--- Where the magic happens
   ↓
Group traffic / maintain statistics
   ↓
Apply detection rule
   ↓
NORMAL or DDoS
```

Open sourcing this: [NSDI 2026 paper](https://www.usenix.org/system/files/nsdi26-xiao.pdf)

