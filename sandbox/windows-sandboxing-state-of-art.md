# Windows malware sandboxing state-of-art



### [Zenbox](https://virustotal.readme.io/docs/in-house-sandboxes#zenbox) : 

The Zenbox is one [VirusTotal In-house Sandboxes](https://virustotal.readme.io/docs/in-house-sandboxes)

#### features:
- Windows 10 sandbox.
- MITRE matrix[^1]
- Signature detection
- Memory dumps
- Runs on GC VmwareEngine[^2].

#### lacks:

- Doesn't allow self hosting
- Closed Source
- Lacks or could not be found how it does it's tracking

### [CAPEv2](https://github.com/kevoreilly/CAPEv2)

CAPEv2 is a open source successor to the cuckoo sandbox
#### features:

- Behavioral tracking based on API hooking(uses [cuckoo modified api hooking engine](https://github.com/spender-sandbox/cuckoomon-modified))
- Captures files that the malware interacted with
- Network traffic capture in PCAP[^3] format
- Memory Dumps
- Classification based on the retrieved data
- Automated Dynamic Malware Unpacking[^4]
- Malware classification based on YARA[^5] signatures of unpacked payloads
- Dynamic anti-sandbox countermeasures
- Instruction traces
- Can be self hosted and it's very well documented


### any.run sandbox

### joe sandbox

### Tria.ge

### Falcon Sandbox

### Hybrid Anlisys 


# Virtualization detection

### Patfish

Pafish is a testing tool that uses different techniques to detect virtual machines and malware analysis environments in the same way that malware families do 

[repo](https://github.com/a0rtega/pafish) e [demo](https://www.youtube.com/watch?v=MaLz3B5rcYM&t=1s)

## RDTSC

[Vm Spoofing tutorial](https://www.reddit.com/r/VFIO/comments/i071qx/spoof_and_make_your_vm_undetectable_no_more/)

## Hypervisor cpu flag

[How to deactivate hypervisor flag](https://www.reddit.com/r/VFIO/comments/jpvf2c/disable_the_hypervisor_flag_at_runtime_vm/)

## Hypervisor vendor 


## Referências

https://virustotal.readme.io/docs/in-house-sandboxes

## Notas

[^1]: The MITRE ATT&CK Matrix, on the other hand, is a visualization of the tactics and techniques in the ATT&CK framework. [more info](https://www.paloaltonetworks.com/cyberpedia/what-is-mitre-attack-matrix)

[^2]: Google Cloud based Vmwareengine

[^3]: PCAP refers to packet capture, a technique of capturing data packets as they travel across the network in order to analyze them

[^4]: Packing consist of a obfuscation tecnique used to avoid common signature matching, a packer can be used to basically compress a file and create a unpacking stub that will contain the instructions on how to unpack and run the malware using tecniques like process hollowing to run it, [more info on this process](https://medium.com/@dbragetti/unpacking-malware-685de7093e5). A dynamic unpacker will unpack the program by analyzing the process while its running, and capturing a copy of the uncompressed program, that was uncompressed by the stub. more on [dynamic unpacking](http://ulsrl.org/project/dynamic-unpacking/)

[^5]:YARA is a very popular open-source and multi-platform tool(it works with most hosts running Windows, Linux, or Mac operating systems) that provides a mechanism to exploit code similarities between malware samples within a family
