# Network Traffic Monitor with Rule-Based Intrusion Detection System (NTM-IDS)

> **A C++ Data Structures & Algorithms project that inspects network traffic in real time and raises prioritized alerts using rule-based detection.**

---

## Project Overview

**NTM-IDS** is a console-based application that simulates the core pipeline of a network Intrusion Detection System. Packets flow into a fixed-size buffer, are tracked per source IP, and are checked against a set of detection rules. Anything suspicious triggers an alert, and the most severe alerts are always reported first.

Unlike a typical "use the STL for everything" project, NTM-IDS is built around **choosing the right data structure and algorithm for each job**. Every component maps to a DSA concept, with its time complexity analysed and justified.

> Traffic is **simulated** (packet generator or CSV dataset). No real network sniffing is performed.

---

## Key Features

### 1. **Traffic Buffering**
* **Circular Queue (FIFO):** Fixed-size array buffer that absorbs bursts of incoming packets with `O(1)` insert and delete.
* **Overflow Policy:** When the buffer is full, the oldest packet is dropped and the drop is counted.

### 2. **Flow Tracking**
* **Hash Map Flow Table:** Keeps a live summary per source IP (packet count, timestamps, ports touched, SYN count, last seen).
* **Collision Handling:** Separate chaining with linked lists.
* **Auto-Resize:** Table doubles and rehashes when the load factor exceeds 0.75, giving `O(1)` amortized insertion.
* **Flow Expiry:** Inactive entries are removed so spoofed-IP floods cannot exhaust memory.

### 3. **Rule-Based Detection**

| Rule | Detects | Technique |
| :--- | :--- | :--- |
| **IP Blacklist** | Traffic from banned hosts or whole subnets (`10.0.0.*`) | IP Trie |
| **Signature Match** | Malicious payload strings (`DROP TABLE`, `/etc/passwd`) | Aho-Corasick |
| **Flood / DoS** | Too many packets from one IP in T seconds | Sliding Window (deque) |
| **Port Scan** | One IP touching many distinct ports | Hash Map + Set |
| **SYN Flood** | Many SYN packets without matching ACKs | Flow Table counters |
| **Port Rules** | Blocked port ranges | Sorted array + Binary Search |

### 4. **Alert Management**
* **Max-Heap Priority Queue:** Alerts are ordered by severity (1-3), so the most critical is always handled first.
* **Alert Log:** Every alert is appended to a linked list and written to `data/alerts.log` with timestamp, source IP, rule name, and severity.

### 5. **Reporting**
* **Top-K Talkers:** Busiest source IPs using a min-heap of size K in `O(n log K)`.
* **Summary Statistics:** Packets processed, dropped, alerts by severity, and unique IPs seen.

---

## Data Structures & Algorithms Used

| Component | Data Structure / Algorithm | Time Complexity |
| :--- | :--- | :--- |
| Packet buffer | Circular Queue | `O(1)` enqueue / dequeue |
| Flow table | Hash Map (chaining + rehashing) | `O(1)` average lookup |
| Rate limiting | Sliding Window (deque) | `O(1)` amortized |
| IP blacklist | Trie (prefix match) | `O(k)`, k = octets (max 4) |
| Payload signatures | Aho-Corasick automaton | `O(N + z)` scan, N = payload length, z = matches |
| Aho-Corasick build | Trie + BFS fail links | `O(total pattern length)` |
| Port-range rules | Sorted array + Binary Search | `O(log M)` |
| Alert ordering | Max-Heap | `O(log n)` push / pop |
| Top-K talkers | Min-Heap of size K | `O(n log K)` |
| Alert history | Linked List | `O(1)` append |

---

## How It Works

```
Packet Source (generator / CSV)
        |
        v
 [ Circular Queue ]  <- buffers bursts
        |
        v  (dequeue one packet)
 [ Flow Table (Hash Map) ]  <- update per-IP counters
        |
        v
 [ Rule Engine ]
   |-- IP Trie            -> blacklisted?
   |-- Sliding Window     -> too fast?
   |-- Port / SYN checks  -> scan or flood?
   '-- Aho-Corasick       -> malicious payload?
        |
        v  (rule fired)
 [ Alert Max-Heap ]  -> most severe first
        |
        v
 [ Alert Log (Linked List + file) ]
```

**Static vs dynamic structures**
* **Built once at startup (read-only):** IP Trie and Aho-Corasick automaton, loaded from `rules/`.
* **Change with every packet:** Circular Queue, Flow Table, Alert Heap, Alert Log.

---

## Packet Structure

```cpp
struct Packet {
    string srcIP;
    string dstIP;
    int    srcPort;
    int    dstPort;
    string protocol;   // TCP / UDP / ICMP
    string flags;      // SYN, ACK, ...
    string payload;
    int    timestamp;  // seconds
};
```

---

## Project Directory Structure

```
NTM-IDS/
├── src/
│   ├── main.cpp             # Entry point & monitor loop
│   ├── Packet.h             # Packet struct & parser
│   ├── CircularQueue.h      # Fixed-size packet buffer
│   ├── FlowTable.h          # Hash map with chaining & resize
│   ├── IPTrie.h             # Blacklist trie
│   ├── AhoCorasick.h        # Signature matching automaton
│   ├── RuleEngine.h         # Combines all detection rules
│   ├── AlertHeap.h          # Severity-ordered priority queue
│   └── Logger.h             # Alert log (linked list + file)
├── rules/
│   ├── blacklist.txt        # Banned IPs / subnets
│   └── signatures.txt       # Malicious payload strings
├── data/
│   ├── packets.csv          # Simulated traffic
│   └── alerts.log           # Output alerts
├── .gitignore
└── README.md
```

---

## Sample Rule Files

**`rules/blacklist.txt`**
```
6.6.6.6
192.168.1.5
10.0.0.*
```

**`rules/signatures.txt`**
```
DROP TABLE
/etc/passwd
<script>
```

---

## Sample Output

```
[SEVERITY 3] 12:00:02  Blacklisted IP 6.6.6.6
[SEVERITY 3] 12:00:05  Flood detected from 10.0.0.5 (50 packets / 2s)
[SEVERITY 2] 12:00:03  Signature 'DROP TABLE' from 1.1.1.1
[SEVERITY 2] 12:00:07  Port scan from 172.16.0.9 (23 ports / 5s)

--- SUMMARY ---
Packets processed : 10000
Packets dropped   : 0
Unique IPs        : 214
Alerts            : 4
Top talkers       : 10.0.0.5 (312), 172.16.0.9 (188), ...
```

---

## Technical Stack

* **Language:** C++ (C++11 or later)
* **Paradigm:** Data Structures & Algorithms, with custom implementations of the core structures
* **Data Input:** Simulated packets (`.csv`) and rule files (`.txt`)
* **Interface:** Console-Based CLI
* **Build:** `g++ -std=c++11 src/main.cpp -o ntm_ids`

---

## Key Design Decisions

✓ **Circular queue over `std::queue`**: fixed memory and `O(1)` operations, implemented from scratch  
✓ **Aho-Corasick over naive search**: one pass over the payload regardless of signature count  
✓ **Trie over a list scan**: lookup cost depends on IP length, not on the number of rules  
✓ **Rehashing + flow expiry**: keeps the flow table fast and memory-bounded under spoofed-IP floods  
✓ **Heap for alerts**: critical threats surface first, not in arrival order  

---

## Limitations

* Traffic is simulated; no live packet capture
* Signature matching is exact-string (no regex)
* Detection thresholds (e.g. flood limit, scan limit) are fixed constants
* Single-threaded processing

---

## Future Enhancements

- [ ] Live packet capture using libpcap / Npcap
- [ ] Bit-level trie for exact CIDR subnet masks (`/24`, `/16`)
- [ ] Regex-based signatures
- [ ] Configurable thresholds from a config file
- [ ] Multi-threaded producer-consumer pipeline
- [ ] Graph analysis of host connections for lateral-movement detection
- [ ] GUI dashboard for live alerts
- [ ] Export reports as PDF / CSV

---

## License

This project is provided as-is for educational purposes in demonstrating Data Structures and Algorithms in C++.

---

## Author

**Nabeel Abid**  
GitHub:[@NabeelAbid1](https://github.com/NabeelAbid1)

**Sheraz Ali**  
GitHub: [@Sheraz-Ali403](https://github.com/Sheraz-Ali403)


---

## Notes

- All timestamps follow the format: `YYYY-MM-DD HH:MM:SS`
- Detection thresholds are constants defined in `RuleEngine.h`
- File paths are relative to the working directory where the executable is run
-
