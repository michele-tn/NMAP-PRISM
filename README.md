# Nmap Host Name Discovery

A PowerShell 7 script that discovers the **host names** on a subnet with Nmap and merges every result into
**one standard Nmap XML file** (`<nmaprun>`), readable by Zenmap, `nmap-parse-output`, python-nmap / libnmap,
Metasploit and any other tool that understands Nmap XML.

A plain `nmap -sV -O` often returns no names: reverse DNS may be empty, NetBIOS may be disabled, SMB may be
hardened. This script asks every available source, verifies which DNS servers are really usable, and records
the chosen name, its source and the alternatives.

> **Use only on networks you own or are explicitly authorized to test.**

## Requirements

- Windows with **PowerShell 7.0+**, started **as Administrator**
- [Nmap](https://nmap.org/download.html) 7.9x with Npcap (standard install folder preferred)

## Usage

```powershell
# Auto-detects the local subnet and the DNS servers
pwsh -ExecutionPolicy Bypass -File .\Invoke-HostNameDiscovery.ps1

# Explicit subnet and DNS server
pwsh -ExecutionPolicy Bypass -File .\Invoke-HostNameDiscovery.ps1 -Subnet 192.168.1.0/24 -DnsServer 192.168.1.10

# Add an authenticated SMB pass for hosts that still have no name (see the security notes)
pwsh -ExecutionPolicy Bypass -File .\Invoke-HostNameDiscovery.ps1 -Subnet 10.0.0.0/24 -Credential (Get-Credential)
```

| Parameter     | Description |
|---------------|-------------|
| `-Subnet`     | CIDR range. If omitted, the subnet of the default-route adapter is used (must be /22 or smaller). |
| `-DnsServer`  | Extra DNS server IPv4 addresses to test (servers are detected automatically anyway). |
| `-Credential` | Enables phase 5 (authenticated `smb-os-discovery`). |
| `-OutDir`     | Output folder (default `.\scan_yyyyMMdd_HHmmss`). |
| `-OutFile`    | Final XML path (default `<OutDir>\scan_complete.xml`). |
| `-SkipUdp`    | Skip phase 4. |
| `-Force`      | Skip the confirmation prompt before phase 5. |

## Phases

1. **Discovery** – ARP host discovery, no DNS.
2. **DNS verification** – candidates from the parameter, adapter settings, domain controllers (SRV records) and
   the default gateway. Each is checked for TCP/53, reverse zone (SOA) and PTR answers on every live host.
   Servers returning PTR records are passed to Nmap with `--dns-servers`.
3. **TCP** – top 100 ports, `-sV`, `-O` and name-revealing scripts: `smb-os-discovery`, `nbstat`, `*-ntlm-info`
   (RDP, HTTP, MSSQL, Telnet, SMTP), `ssl-cert`, `http-title`.
4. **UDP** – ports 137, 161, 1900, 5353 with `nbstat`, `snmp-*`, `dns-service-discovery`, `upnp-info`.
5. **Authenticated SMB** *(optional)* – only for hosts with 445 open and still unnamed.

## Output

`scan_complete.xml` is a standard `<nmaprun>` document. The intermediate XML files of each phase are kept in
`phases/`.

- `<hostname type="PTR">` – real DNS records.
- `<hostname type="user">` – best name derived from NetBIOS / SMB / NTLM / SSL when no PTR exists (the Nmap
  DTD only allows `user` and `PTR`).
- `<script id="discovered-hostname">` in `<hostscript>` – chosen name, source of every candidate, domain.
- A comment near the top summarizes the DNS verification.

Name priority: local machine → DNS → SMB FQDN → NTLM DNS name → SMB computer name → NTLM NetBIOS name →
NetBIOS (`nbstat`) → SSL certificate CN.

## Troubleshooting

- **"running scripts is disabled"** – run with `pwsh -ExecutionPolicy Bypass -File ...` or `Unblock-File`.
- **"No candidate DNS server returns PTR records"** – the reverse zone (for example `16.168.192.in-addr.arpa`)
  is missing or unpopulated on your DNS servers. The verification table shows *Reverse zone = no* and
  *PTR found = 0*. Create the reverse lookup zone and enable PTR registration (DHCP / dynamic updates).
- **Hosts with only port 135 open** usually sit behind the Windows firewall and cannot be named by any
  network probe; use DNS/DHCP/Active Directory records instead.

## Security notes

- **Phase 5 sends NTLM authentication to every unnamed host with port 445 open**, including unknown or rogue
  devices, which could capture the hash. Use a dedicated low-privilege account; the script asks for
  confirmation unless `-Force` is given.
- Credentials are passed to Nmap through a temporary `--script-args-file` restricted to the current user and
  deleted afterwards, so they never appear on the command line or in the XML output.
- The script must run elevated; it prefers `nmap.exe` from the standard install folder and warns when the
  binary is resolved through `PATH` or has an invalid Authenticode signature.
- Nmap XML is parsed with external entity resolution disabled. Text coming from the network is sanitized
  before being printed or written to XML.
- Output folders contain a full inventory of the scanned network: treat them as sensitive.