# NetNTLMv2-Sniffer
Small WinPcap-Based NetNTLMv2 Hash Sniffer

Basic little thing that sniffs SMB2 datagrams and harvests any NetNTLMv2 hashes into a text/XML file, which can then be directly fed into hashcat. Has a bit of code to prevent duplicate collection on a single account, and requires WinPcap (and the WinPcap lib).

#### XML_to_Hashcat.ps1
A couple lines of PowerShell to turn the XML output into a list of hashes Hashcat likes.
