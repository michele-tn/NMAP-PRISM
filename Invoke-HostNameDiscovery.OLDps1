#Requires -Version 7.0
<#
.SYNOPSIS
    Discovers host names on a subnet with Nmap and merges everything into ONE standard Nmap XML file.

.DESCRIPTION
    Runs a multi-phase Nmap scan, verifies the DNS servers that are really in use on the network, and
    produces a single Nmap-format XML report (<nmaprun>) that works with Zenmap, nmap-parse-output,
    python-nmap / libnmap, Metasploit, etc. Host names are filled in from every source available.

    Phase 1  Host discovery (ARP, no DNS).
    Phase 2  DNS discovery and verification. Candidates come from the -DnsServer parameter, the DNS
             servers of the network adapters (those on the scanned subnet first), the domain controllers
             (SRV records _ldap._tcp.dc._msdcs) and the default gateway. Every candidate is checked for
             TCP/53, for the existence of the reverse zone (SOA) and for PTR answers on all live hosts.
             Servers returning at least one PTR record are passed to Nmap (--dns-servers).
    Phase 3  TCP top-100 scan with -sV, -O and scripts that expose the host name (SMB, NetBIOS, NTLM over
             RDP/HTTP/MSSQL/Telnet/SMTP, SSL certificates, HTTP titles).
    Phase 4  Targeted UDP scan (137, 161, 1900, 5353) with NetBIOS, SNMP, UPnP and mDNS scripts.
    Phase 5  Optional (needs -Credential): authenticated smb-os-discovery against hosts with port 445
             open that still have no name.
    Merge    The XML files of all phases are merged into one <nmaprun>:
             - UDP / SMB ports and scripts are added to the matching <host>
             - names are added to <hostnames>: type="PTR" for real DNS records, type="user" for names
               derived from NetBIOS / SMB / NTLM / SSL when no PTR exists (the Nmap DTD only allows
               "user" and "PTR")
             - a synthetic script "discovered-hostname" in <hostscript> records the chosen name, its
               source and the alternatives
             - <scaninfo>, <runstats> and the host counters are updated
    The intermediate XML files are kept in the "phases" sub-folder.

    Must run in PowerShell 7 started AS ADMINISTRATOR (Nmap needs Npcap / raw sockets for -O and -sU).
    Only scan networks you own or are explicitly authorized to test.

.PARAMETER Subnet
    Network to scan in CIDR notation. If omitted, the subnet of the adapter that holds the default route
    is used (only when it is /22 or smaller; otherwise specify it explicitly).

.PARAMETER DnsServer
    One or more DNS server IPs to add to the candidates (optional: DNS servers are detected automatically).

.PARAMETER Credential
    Account for phase 5. The password must not contain commas, spaces, quotes or '='
    (a limitation of Nmap's --script-args syntax).

.PARAMETER OutDir
    Output folder. Default: .\scan_yyyyMMdd_HHmmss

.PARAMETER OutFile
    Path of the final XML file. Default: <OutDir>\scan_complete.xml

.PARAMETER SkipUdp
    Skips phase 4 (UDP scan).

.EXAMPLE
    .\Invoke-HostNameDiscovery.ps1

.EXAMPLE
    .\Invoke-HostNameDiscovery.ps1 -Subnet 192.168.1.0/24 -DnsServer 192.168.1.10

.EXAMPLE
    .\Invoke-HostNameDiscovery.ps1 -Subnet 10.0.0.0/24 -Credential (Get-Credential)
#>
[CmdletBinding()]
param(
    [string]$Subnet,
    [string[]]$DnsServer,
    [pscredential]$Credential,
    [string]$OutDir = (Join-Path (Get-Location).Path ('scan_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))),
    [string]$OutFile,
    [switch]$SkipUdp
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.0.0'

# =====================================================================================
# Generic helpers (network maths, table output)
# =====================================================================================
function ConvertTo-UInt32Ip([string]$Ip) {
    $b = [ipaddress]::Parse($Ip).GetAddressBytes()
    [array]::Reverse($b)
    return [BitConverter]::ToUInt32($b, 0)
}

function ConvertFrom-UInt32Ip([uint32]$Value) {
    $b = [BitConverter]::GetBytes($Value)
    [array]::Reverse($b)
    return ([ipaddress]::new($b)).ToString()
}

function Get-PrefixMask([int]$Length) {
    if ($Length -le 0) { return [uint32]0 }
    return [uint32](([uint64]4294967295 -shl (32 - $Length)) -band 4294967295)
}

function Test-IpInCidr([string]$Ip, [string]$Cidr) {
    $parts = $Cidr -split '/'
    $len = if ($parts.Count -gt 1) { [int]$parts[1] } else { 32 }
    $mask = Get-PrefixMask $len
    return (((ConvertTo-UInt32Ip $Ip) -band $mask) -eq ((ConvertTo-UInt32Ip $parts[0]) -band $mask))
}

function Get-ReverseZone([string]$Cidr) {
    $parts = $Cidr -split '/'
    $o = $parts[0].Split('.')
    $len = if ($parts.Count -gt 1) { [int]$parts[1] } else { 32 }
    if ($len -ge 24)     { return "$($o[2]).$($o[1]).$($o[0]).in-addr.arpa" }
    elseif ($len -ge 16) { return "$($o[1]).$($o[0]).in-addr.arpa" }
    else                 { return "$($o[0]).in-addr.arpa" }
}

function Get-DefaultSubnet {
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
        Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
    $addr = Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { $_.PrefixOrigin -ne 'WellKnown' } | Select-Object -First 1
    $len = [int]$addr.PrefixLength
    $net = (ConvertTo-UInt32Ip $addr.IPAddress) -band (Get-PrefixMask $len)
    return ('{0}/{1}' -f (ConvertFrom-UInt32Ip ([uint32]$net)), $len)
}

# Word-wraps a text to a maximum width and returns the resulting lines.
function Split-Wrapped {
    param([string]$Text, [int]$Width)
    if ($Width -lt 1) { $Width = 1 }
    $lines = [System.Collections.Generic.List[string]]::new()
    $cur = ''
    foreach ($word in @($Text -split '\s+' | Where-Object { $_ -ne '' })) {
        $w = $word
        while ($w.Length -gt $Width) {
            if ($cur) { $lines.Add($cur); $cur = '' }
            $lines.Add($w.Substring(0, $Width))
            $w = $w.Substring($Width)
        }
        if (-not $cur) { $cur = $w }
        elseif (($cur.Length + 1 + $w.Length) -le $Width) { $cur += ' ' + $w }
        else { $lines.Add($cur); $cur = $w }
    }
    if ($cur -or $lines.Count -eq 0) { $lines.Add($cur) }
    return , $lines.ToArray()
}

# Prints an aligned table. Column widths are computed from the content and, when the table is wider
# than the console, the columns flagged Wrap=$true are shrunk and their text is word-wrapped.
#   Columns: @{ Header = 'Name'; Property = 'Prop'; Type = 'Text'|'Number'|'Bool'; Wrap = $true|$false }
function Write-AlignedTable {
    param(
        [object[]]$Rows,
        [hashtable[]]$Columns,
        [int]$MinWrapWidth = 12
    )
    if (-not $Rows -or @($Rows).Count -eq 0) { return }

    try { $total = [Console]::WindowWidth - 1 } catch { $total = 0 }
    if ($total -lt 60) { $total = 119 }
    $gap = 2
    $n = $Columns.Count

    # cell texts
    $cells = @(foreach ($r in $Rows) {
        $row = New-Object 'string[]' $n
        for ($i = 0; $i -lt $n; $i++) {
            $v = $r.($Columns[$i].Property)
            if ($Columns[$i].Type -eq 'Bool') { $t = if ($v) { 'yes' } else { 'no' } }
            elseif ($null -eq $v) { $t = '' }
            else { $t = [string]$v }
            $row[$i] = $t
        }
        , $row
    })

    # natural widths
    $widths = New-Object 'int[]' $n
    for ($i = 0; $i -lt $n; $i++) {
        $w = $Columns[$i].Header.Length
        foreach ($row in $cells) { if ($row[$i].Length -gt $w) { $w = $row[$i].Length } }
        $widths[$i] = $w
    }

    # shrink the widest wrappable column until the table fits the console
    while ((($widths | Measure-Object -Sum).Sum + $gap * ($n - 1)) -gt $total) {
        $pick = -1
        for ($i = 0; $i -lt $n; $i++) {
            if ($Columns[$i].Wrap -and $widths[$i] -gt $MinWrapWidth -and ($pick -lt 0 -or $widths[$i] -gt $widths[$pick])) { $pick = $i }
        }
        if ($pick -lt 0) { break }
        $widths[$pick]--
    }

    # header + separator
    for ($i = 0; $i -lt $n; $i++) {
        $h = $Columns[$i].Header
        $txt = if ($Columns[$i].Type -eq 'Number') { $h.PadLeft($widths[$i]) } else { $h.PadRight($widths[$i]) }
        Write-Host $txt -NoNewline -ForegroundColor Cyan
        if ($i -lt $n - 1) { Write-Host (' ' * $gap) -NoNewline }
    }
    Write-Host ''
    for ($i = 0; $i -lt $n; $i++) {
        Write-Host ('-' * $widths[$i]) -NoNewline -ForegroundColor DarkGray
        if ($i -lt $n - 1) { Write-Host (' ' * $gap) -NoNewline }
    }
    Write-Host ''

    # rows
    foreach ($row in $cells) {
        $colLines = @()
        $maxLines = 1
        for ($i = 0; $i -lt $n; $i++) {
            if ($Columns[$i].Wrap) { $l = @(Split-Wrapped $row[$i] $widths[$i]) } else { $l = @($row[$i]) }
            $colLines += , $l
            if ($l.Count -gt $maxLines) { $maxLines = $l.Count }
        }
        for ($k = 0; $k -lt $maxLines; $k++) {
            for ($i = 0; $i -lt $n; $i++) {
                $text = if ($k -lt $colLines[$i].Count) { [string]$colLines[$i][$k] } else { '' }
                $cell = if ($Columns[$i].Type -eq 'Number') { $text.PadLeft($widths[$i]) } else { $text.PadRight($widths[$i]) }
                if ($Columns[$i].Type -eq 'Bool' -and $text -eq 'yes')    { Write-Host $cell -NoNewline -ForegroundColor Green }
                elseif ($Columns[$i].Type -eq 'Bool' -and $text -eq 'no') { Write-Host $cell -NoNewline -ForegroundColor Yellow }
                else { Write-Host $cell -NoNewline }
                if ($i -lt $n - 1) { Write-Host (' ' * $gap) -NoNewline }
            }
            Write-Host ''
        }
    }
}

# =====================================================================================
# Pre-flight checks
# =====================================================================================
Write-Host ("Host name discovery v{0} - only scan networks you are authorized to test." -f $ScriptVersion) -ForegroundColor DarkGray

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw 'Run PowerShell (or your terminal) as Administrator: -O and -sU require elevated privileges.'
}

foreach ($d in @($DnsServer | Where-Object { $_ })) {
    if (-not [ipaddress]::TryParse($d, [ref]$null)) {
        throw "DnsServer '$d' is not a valid IP address. Pass a real address, for example -DnsServer 192.168.1.10"
    }
}

if ($Subnet) {
    $ok = $Subnet -match '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$' -and
          [ipaddress]::TryParse($Matches[1], [ref]$null) -and [int]$Matches[2] -le 32
    if (-not $ok) { throw "Subnet '$Subnet' is not valid CIDR notation (example: 192.168.1.0/24)." }
    if ([int](($Subnet -split '/')[1]) -lt 20) {
        Write-Warning "Subnet $Subnet is very large: -sV / -O scans may take a long time."
    }
}
else {
    try { $Subnet = Get-DefaultSubnet }
    catch { throw "Could not detect the local subnet ($($_.Exception.Message)). Specify it with -Subnet." }
    if ([int](($Subnet -split '/')[1]) -lt 22) {
        throw "The detected subnet $Subnet is larger than /22. Specify the range to scan explicitly with -Subnet."
    }
    Write-Host "Subnet auto-detected: $Subnet" -ForegroundColor DarkGray
}

$nmap = (Get-Command nmap -ErrorAction SilentlyContinue).Source
if (-not $nmap) {
    foreach ($p in @("$env:ProgramFiles\Nmap\nmap.exe", "${env:ProgramFiles(x86)}\Nmap\nmap.exe")) {
        if (Test-Path -LiteralPath $p) { $nmap = $p; break }
    }
}
if (-not $nmap) { throw 'nmap.exe not found: install Nmap (with Npcap) or add it to PATH.' }

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$OutDir = (Resolve-Path -LiteralPath $OutDir).Path
$StageDir = Join-Path $OutDir 'phases'
New-Item -ItemType Directory -Path $StageDir -Force | Out-Null
if (-not $OutFile) { $OutFile = Join-Path $OutDir 'scan_complete.xml' }
$OutFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)

Start-Transcript -Path (Join-Path $OutDir 'log.txt') | Out-Null

try {
    # ------------------------------------------------------------------------ Nmap runner
    $cmdLog = [System.Collections.Generic.List[string]]::new()
    $stageFiles = [System.Collections.Generic.List[string]]::new()

    function Invoke-Nmap {
        param([string]$Title, [string[]]$Arguments, [string]$XmlFile)
        Write-Host "`n=== $Title ===" -ForegroundColor Cyan
        $all = @($Arguments) + @('-oX', $XmlFile)
        $shown = ($all -join ' ') -replace 'smbpassword=[^,\s]*', 'smbpassword=***'
        Write-Host "nmap $shown" -ForegroundColor DarkGray
        & $nmap @all
        if ($LASTEXITCODE -ne 0) { throw "nmap exited with code $LASTEXITCODE ($Title)" }
        $cmdLog.Add("nmap $shown")
        $stageFiles.Add($XmlFile)
    }

    function Get-XmlSafe([string]$Text) {
        if ($null -eq $Text) { return '' }
        return ($Text -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', '')
    }

    function Test-Tcp53([string]$Ip) {
        $c = [System.Net.Sockets.TcpClient]::new()
        try {
            $t = $c.ConnectAsync($Ip, 53)
            return ($t.Wait(1500) -and $c.Connected)
        }
        catch { return $false }
        finally { $c.Dispose() }
    }

    # ------------------------------------------------------------------------ name database
    # Priority of the name sources (lower index = more reliable)
    $Prio = @(
        'local',
        'DNS-*',
        'smb-os-discovery FQDN',
        '*ntlm-info DNS',
        'smb-os-discovery*',
        '*ntlm-info NetBIOS',
        'nbstat',
        'ssl-cert*'
    )
    function Get-Prio([string]$Source) {
        for ($i = 0; $i -lt $Prio.Count; $i++) { if ($Source -like $Prio[$i]) { return $i } }
        return 99
    }

    $db = @{}
    function Get-Rec([string]$Ip) {
        if (-not $db.ContainsKey($Ip)) {
            $db[$Ip] = [pscustomobject]@{
                Ip     = $Ip
                Domain = ''
                Ports  = [System.Collections.Generic.List[string]]::new()
                Names  = [System.Collections.Generic.List[object]]::new()
            }
        }
        $db[$Ip]
    }

    function Add-Name {
        param($Rec, [string]$Source, [string]$Name)
        if ([string]::IsNullOrWhiteSpace($Name)) { return }
        $Name = (Get-XmlSafe ($Name -replace '\\x00', '')).Trim().TrimEnd('.')
        if ($Name -in @('', '<unknown>')) { return }
        if ($Rec.Names | Where-Object { $_.Name -ieq $Name -and $_.Source -eq $Source }) { return }
        $Rec.Names.Add([pscustomobject]@{ Source = $Source; Name = $Name })
    }

    # Reads an Nmap XML file and extracts names, domain and open ports into the database
    function Import-NmapNames {
        param([string]$File)
        $doc = [System.Xml.XmlDocument]::new()
        $doc.Load((Resolve-Path -LiteralPath $File).Path)

        foreach ($h in $doc.SelectNodes('//host')) {
            $st = $h.SelectSingleNode('status')
            if ($st -and $st.GetAttribute('state') -ne 'up') { continue }
            $ipNode = $h.SelectSingleNode("address[@addrtype='ipv4']")
            if (-not $ipNode) { continue }
            $rec = Get-Rec $ipNode.GetAttribute('addr')

            foreach ($hn in $h.SelectNodes('hostnames/hostname')) {
                Add-Name $rec ('DNS-' + $hn.GetAttribute('type')) $hn.GetAttribute('name')
            }

            foreach ($p in $h.SelectNodes("ports/port[state/@state='open']")) {
                $pp = '{0}/{1}' -f $p.GetAttribute('portid'), $p.GetAttribute('protocol')
                if (-not $rec.Ports.Contains($pp)) { $rec.Ports.Add($pp) }
            }

            foreach ($s in $h.SelectNodes('.//script')) {
                $id = $s.GetAttribute('id')
                $out = $s.GetAttribute('output')
                $port = ''
                if ($s.ParentNode.Name -eq 'port') { $port = $s.ParentNode.GetAttribute('portid') }

                switch -Wildcard ($id) {
                    'smb-os-discovery' {
                        if ($out -match '(?m)^\s*FQDN:\s*(.+?)\s*$')                 { Add-Name $rec 'smb-os-discovery FQDN' $Matches[1] }
                        if ($out -match '(?m)^\s*Computer name:\s*(.+?)\s*$')        { Add-Name $rec 'smb-os-discovery' $Matches[1] }
                        if ($out -match '(?m)NetBIOS computer name:\s*([^\\\r\n]+)') { Add-Name $rec 'smb-os-discovery NetBIOS' $Matches[1] }
                        if ($out -match '(?m)^\s*Domain name:\s*(.+?)\s*$')          { $rec.Domain = $Matches[1] }
                        elseif ($out -match '(?m)^\s*Workgroup:\s*([^\\\r\n]+)')     { if (-not $rec.Domain) { $rec.Domain = $Matches[1].Trim() } }
                    }
                    'nbstat' {
                        if ($out -match 'NetBIOS name:\s*([^,\r\n]+),') { Add-Name $rec 'nbstat' $Matches[1] }
                        if ($out -match '(?m)^\s*(\S+)<00>\s+Flags:\s*<group>') { if (-not $rec.Domain) { $rec.Domain = $Matches[1] } }
                    }
                    '*-ntlm-info' {
                        if ($out -match '(?m)^\s*DNS_Computer_Name:\s*(\S+)')     { Add-Name $rec "$id DNS" $Matches[1] }
                        if ($out -match '(?m)^\s*NetBIOS_Computer_Name:\s*(\S+)') { Add-Name $rec "$id NetBIOS" $Matches[1] }
                        if ($out -match '(?m)^\s*DNS_Domain_Name:\s*(\S+)')       { if (-not $rec.Domain) { $rec.Domain = $Matches[1] } }
                    }
                    'ssl-cert' {
                        if ($out -match 'commonName=([^/\r\n]+)') { Add-Name $rec "ssl-cert CN[$port]" $Matches[1] }
                    }
                    'snmp-info' {
                        if ($out -match '(?m)^\s*sysName:\s*(.+?)\s*$') { Add-Name $rec 'snmp-info sysName' $Matches[1] }
                    }
                }
            }
        }
    }

    # ---------------------------------------------------------------------- PHASE 1
    $x1 = Join-Path $StageDir '1_discovery.xml'
    Invoke-Nmap 'PHASE 1 - live host discovery' @('-sn', '-n', '-T4', $Subnet) $x1
    Import-NmapNames $x1

    $live = Join-Path $StageDir 'live_hosts.txt'
    $liveIps = @($db.Keys | Sort-Object { [version]$_ })
    if ($liveIps.Count -eq 0) { throw 'No live hosts found in phase 1.' }
    $liveIps | Set-Content -LiteralPath $live -Encoding ascii
    Write-Host ("Live hosts found: {0}" -f $liveIps.Count) -ForegroundColor Green

    # ---------------------------------------------------------------------- PHASE 2 - DNS
    Write-Host "`n=== PHASE 2 - DNS discovery and verification ===" -ForegroundColor Cyan

    $cand = [ordered]@{}
    function Add-Cand([string]$Ip, [string]$Origin) {
        $addr = $null
        if (-not [ipaddress]::TryParse($Ip, [ref]$addr)) { return }
        if ($addr.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return }
        if ($Ip -like '127.*' -or $Ip -like '169.254.*' -or $Ip -eq '0.0.0.0') { return }
        if (-not $cand.Contains($Ip)) { $cand[$Ip] = [System.Collections.Generic.List[string]]::new() }
        if (-not $cand[$Ip].Contains($Origin)) { $cand[$Ip].Add($Origin) }
    }

    # 1) parameter
    foreach ($d in @($DnsServer | Where-Object { $_ })) { Add-Cand $d 'parameter' }

    # 2) DNS servers configured on the network adapters (adapters on the scanned subnet first)
    try {
        $ifOnSubnet = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { Test-IpInCidr $_.IPAddress $Subnet } |
            ForEach-Object { $_.InterfaceIndex })
        $entries = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop)
        $entries = @($entries | Sort-Object { if ($ifOnSubnet -contains $_.InterfaceIndex) { 0 } else { 1 } })
        foreach ($e in $entries) {
            $o = if ($ifOnSubnet -contains $e.InterfaceIndex) { 'adapter on subnet' } else { 'other adapter' }
            foreach ($sa in $e.ServerAddresses) { Add-Cand $sa "$o ($($e.InterfaceAlias))" }
        }
    }
    catch { Write-Warning "Could not read the adapters' DNS settings: $($_.Exception.Message)" }

    # 3) domain controllers (SRV records)
    $domains = @()
    if ($env:USERDNSDOMAIN) { $domains += $env:USERDNSDOMAIN }
    try { $domains += @(Get-DnsClient -ErrorAction Stop | Where-Object { $_.ConnectionSpecificSuffix } | ForEach-Object { $_.ConnectionSpecificSuffix }) } catch { }
    try { $domains += @((Get-DnsClientGlobalSetting -ErrorAction Stop).SuffixSearchList) } catch { }
    $domains = @($domains | Where-Object { $_ } | ForEach-Object { $_.ToLower() } | Sort-Object -Unique)
    foreach ($dom in $domains) {
        $srvRecs = @(Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$dom" -Type SRV -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue |
            Where-Object { $_.Type -eq 'SRV' })
        foreach ($sr in $srvRecs) {
            $arecs = @(Resolve-DnsName -Name $sr.NameTarget -Type A -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue |
                Where-Object { $_.Type -eq 'A' })
            foreach ($ar in $arecs) { Add-Cand $ar.IPAddress "domain controller $dom ($($sr.NameTarget))" }
        }
    }
    if ($domains.Count) { Write-Host ("DNS domains / suffixes considered: {0}" -f ($domains -join ', ')) -ForegroundColor DarkGray }

    # 4) default gateway
    try {
        Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | ForEach-Object { Add-Cand $_.NextHop 'default gateway' }
    }
    catch { }

    if ($cand.Count -eq 0) {
        Write-Warning 'No candidate DNS server found: Nmap will use the system resolver.'
    }

    # verify every candidate
    $zone = Get-ReverseZone $Subnet
    Write-Host ("Expected reverse zone: {0}" -f $zone) -ForegroundColor DarkGray

    $dnsReport = @()
    foreach ($ip in @($cand.Keys)) {
        Write-Host ("  checking {0} ..." -f $ip)
        $tcp = Test-Tcp53 $ip
        $soa = Resolve-DnsName -Name $zone -Type SOA -Server $ip -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue |
            Where-Object { $_.Type -eq 'SOA' } | Select-Object -First 1

        # an unreachable server only gets a small sample
        $sample = if ($tcp -or $soa) { $liveIps } else { @($liveIps | Select-Object -First 3) }

        $srvIp = $ip
        $res = @($sample | ForEach-Object -Parallel {
            $ipx = $_
            $r = Resolve-DnsName -Name $ipx -Server $using:srvIp -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue
            $nm = @($r | Where-Object { $_.NameHost } | ForEach-Object { $_.NameHost }) | Select-Object -First 1
            [pscustomobject]@{ Ip = $ipx; Name = $nm }
        } -ThrottleLimit 20)
        $hits = @($res | Where-Object { $_.Name })

        $dnsReport += [pscustomobject]@{
            Ip          = $ip
            Origin      = ($cand[$ip] -join '; ')
            Tcp53       = [bool]$tcp
            ReverseZone = [bool]$soa
            PrimaryNs   = [string]$soa.PrimaryServer
            Tested      = @($sample).Count
            PtrFound    = $hits.Count
            Responding  = [bool]($tcp -or $soa -or $hits.Count -gt 0)
            Used        = $false
            Ptr         = $hits
        }
    }

    # choose the DNS servers to use: those returning PTR records, otherwise the reachable ones
    $good = @($dnsReport | Where-Object { $_.PtrFound -gt 0 } | Sort-Object PtrFound -Descending)
    if ($good.Count -eq 0) {
        $good = @($dnsReport | Where-Object { $_.Responding })
        Write-Warning 'No candidate DNS server returns PTR records for the live hosts: reverse DNS is empty or not populated.'
    }
    foreach ($g in $good) { $g.Used = $true }
    $dnsUsed = @($good | ForEach-Object { $_.Ip })

    # PTR names found feed the name database
    foreach ($rep in $dnsReport) {
        foreach ($p in $rep.Ptr) {
            if ($db.ContainsKey($p.Ip)) { Add-Name $db[$p.Ip] ("DNS-PTR {0}" -f $rep.Ip) $p.Name }
        }
    }

    Write-Host "`nDNS verification result:" -ForegroundColor Green
    Write-AlignedTable -Rows $dnsReport -Columns @(
        @{ Header = 'DNS server';   Property = 'Ip';          Type = 'Text' },
        @{ Header = 'TCP/53';       Property = 'Tcp53';       Type = 'Bool' },
        @{ Header = 'Reverse zone'; Property = 'ReverseZone'; Type = 'Bool' },
        @{ Header = 'Primary NS';   Property = 'PrimaryNs';   Type = 'Text'; Wrap = $true },
        @{ Header = 'Tested';       Property = 'Tested';      Type = 'Number' },
        @{ Header = 'PTR found';    Property = 'PtrFound';    Type = 'Number' },
        @{ Header = 'Responding';   Property = 'Responding';  Type = 'Bool' },
        @{ Header = 'Used';         Property = 'Used';        Type = 'Bool' },
        @{ Header = 'Origin';       Property = 'Origin';      Type = 'Text'; Wrap = $true }
    )

    $dnsArgs = @()
    if ($dnsUsed.Count) {
        $dnsArgs = @('--dns-servers', ($dnsUsed -join ','))
        Write-Host ("`nDNS servers used for Nmap: {0}" -f ($dnsUsed -join ', ')) -ForegroundColor Green
    }

    # ---------------------------------------------------------------------- PHASE 3
    $x3 = Join-Path $StageDir '3_tcp_names.xml'
    $tcpScripts = 'smb-os-discovery,nbstat,rdp-ntlm-info,http-ntlm-info,ms-sql-ntlm-info,telnet-ntlm-info,smtp-ntlm-info,ssl-cert,http-title'
    $a3 = @('-Pn', '-sV', '-O', '--top-ports', '100', '-T4', '-R', '--host-timeout', '10m') + $dnsArgs +
          @('--script', $tcpScripts, '-iL', $live)
    Invoke-Nmap 'PHASE 3 - TCP top 100 + name-revealing scripts' $a3 $x3
    Import-NmapNames $x3

    # ---------------------------------------------------------------------- PHASE 4
    $x4 = $null
    if (-not $SkipUdp) {
        $x4 = Join-Path $StageDir '4_udp_names.xml'
        $a4 = @('-Pn', '-sU', '-p', '137,161,1900,5353', '-T4', '--max-retries', '1', '--host-timeout', '5m',
                '--script', 'nbstat,snmp-sysdescr,snmp-info,dns-service-discovery,upnp-info', '-iL', $live)
        Invoke-Nmap 'PHASE 4 - targeted UDP (NetBIOS, SNMP, UPnP, mDNS)' $a4 $x4
        Import-NmapNames $x4
    }

    # ---------------------------------------------------------------------- PHASE 5 (optional)
    $x5 = $null
    if ($Credential) {
        $targets = $db.Values | Where-Object {
            $_.Ports.Contains('445/tcp') -and -not ($_.Names | Where-Object { $_.Source -like 'smb-os-discovery*' })
        } | ForEach-Object { $_.Ip }

        if ($targets) {
            $tFile = Join-Path $StageDir 'smb_auth_targets.txt'
            $targets | Set-Content -LiteralPath $tFile -Encoding ascii

            $u = $Credential.UserName
            $dm = ''
            if ($u -match '^(.+)\\(.+)$')    { $dm = $Matches[1]; $u = $Matches[2] }
            elseif ($u -match '^(.+)@(.+)$') { $u = $Matches[1]; $dm = $Matches[2] }
            $pw = $Credential.GetNetworkCredential().Password

            $sa = "smbusername=$u,smbpassword=$pw"
            if ($dm) { $sa += ",smbdomain=$dm" }

            $x5 = Join-Path $StageDir '5_smb_auth.xml'
            Invoke-Nmap 'PHASE 5 - authenticated smb-os-discovery' @('-Pn', '-p445', '--script', 'smb-os-discovery', '--script-args', $sa, '-iL', $tFile) $x5
            Import-NmapNames $x5
        }
        else {
            Write-Host 'PHASE 5 - no host with port 445 open and no name: skipped.' -ForegroundColor Yellow
        }
    }

    # name of the local machine (the scanner cannot query itself with nbstat)
    try {
        foreach ($lip in (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop).IPAddress) {
            if ($db.ContainsKey($lip)) { Add-Name $db[$lip] 'local' $env:COMPUTERNAME }
        }
    } catch { }

    # =====================================================================================
    # MERGE INTO ONE STANDARD NMAP XML
    # =====================================================================================
    Write-Host "`n=== MERGE - building a single Nmap XML ===" -ForegroundColor Cyan

    function Read-Xml([string]$File) {
        $d = [System.Xml.XmlDocument]::new()
        $d.Load((Resolve-Path -LiteralPath $File).Path)
        return $d
    }

    # base document: the TCP scan (ports, services, OS, scripts)
    $merged = Read-Xml $x3
    $root = $merged.DocumentElement

    function Get-HostIp($n) {
        $a = $n.SelectSingleNode("address[@addrtype='ipv4']")
        if ($a) { return $a.GetAttribute('addr') }
        return $null
    }

    function Get-HostnamesNode($hostNode) {
        $hn = $hostNode.SelectSingleNode('hostnames')
        if ($hn) { return $hn }
        $hn = $merged.CreateElement('hostnames')
        $addrs = $hostNode.SelectNodes('address')
        if ($addrs.Count -gt 0) { $null = $hostNode.InsertAfter($hn, $addrs[$addrs.Count - 1]) }
        else { $null = $hostNode.AppendChild($hn) }
        return $hn
    }

    function Get-PortsNode($hostNode) {
        $p = $hostNode.SelectSingleNode('ports')
        if ($p) { return $p }
        $p = $merged.CreateElement('ports')
        $null = $hostNode.InsertAfter($p, (Get-HostnamesNode $hostNode))
        return $p
    }

    function Get-HostScriptNode($hostNode) {
        $hs = $hostNode.SelectSingleNode('hostscript')
        if ($hs) { return $hs }
        $hs = $merged.CreateElement('hostscript')
        $ref = $hostNode.SelectSingleNode('trace')
        if (-not $ref) { $ref = $hostNode.SelectSingleNode('times') }
        if ($ref) { $null = $hostNode.InsertBefore($hs, $ref) } else { $null = $hostNode.AppendChild($hs) }
        return $hs
    }

    $baseHosts = @{}
    foreach ($h in $root.SelectNodes('host')) {
        $hip = Get-HostIp $h
        if ($hip) { $baseHosts[$hip] = $h }
    }

    function Add-HostNode($srcHost) {
        $n = $merged.ImportNode($srcHost, $true)
        $null = $root.InsertBefore($n, $root.SelectSingleNode('runstats'))
        return $n
    }

    function Merge-ExtraXml([string]$File) {
        $ex = Read-Xml $File

        foreach ($eh in $ex.SelectNodes('//host')) {
            $hip = Get-HostIp $eh
            if (-not $hip) { continue }
            if (-not $baseHosts.ContainsKey($hip)) {
                $baseHosts[$hip] = Add-HostNode $eh
                continue
            }
            $bh = $baseHosts[$hip]

            # ports (and their scripts)
            foreach ($ep in $eh.SelectNodes('ports/port')) {
                $portId = $ep.GetAttribute('portid')
                $proto = $ep.GetAttribute('protocol')
                $ports = Get-PortsNode $bh
                $bp = $ports.SelectSingleNode("port[@portid='$portId' and @protocol='$proto']")
                if (-not $bp) {
                    $null = $ports.AppendChild($merged.ImportNode($ep, $true))
                }
                else {
                    foreach ($sc in $ep.SelectNodes('script')) {
                        $sid = $sc.GetAttribute('id')
                        if (-not $bp.SelectSingleNode("script[@id='$sid']")) {
                            $null = $bp.AppendChild($merged.ImportNode($sc, $true))
                        }
                    }
                }
            }

            # host-level scripts
            $ehs = $eh.SelectSingleNode('hostscript')
            if ($ehs) {
                $bhs = Get-HostScriptNode $bh
                foreach ($sc in $ehs.SelectNodes('script')) {
                    $sid = $sc.GetAttribute('id')
                    if (-not $bhs.SelectSingleNode("script[@id='$sid']")) {
                        $null = $bhs.AppendChild($merged.ImportNode($sc, $true))
                    }
                }
            }

            # host names, if any
            $bhn = Get-HostnamesNode $bh
            foreach ($en in $eh.SelectNodes('hostnames/hostname')) {
                $nm = $en.GetAttribute('name')
                if (-not $bhn.SelectSingleNode("hostname[@name='$nm']")) {
                    $null = $bhn.AppendChild($merged.ImportNode($en, $true))
                }
            }
        }

        # <scaninfo> of the additional scans (e.g. udp)
        foreach ($si in $ex.SelectNodes('/nmaprun/scaninfo')) {
            $t = $si.GetAttribute('type'); $pr = $si.GetAttribute('protocol')
            if (-not $root.SelectSingleNode("scaninfo[@type='$t' and @protocol='$pr']")) {
                $all = $root.SelectNodes('scaninfo')
                $imp = $merged.ImportNode($si, $true)
                if ($all.Count -gt 0) { $null = $root.InsertAfter($imp, $all[$all.Count - 1]) }
                else { $null = $root.PrependChild($imp) }
            }
        }
    }

    # hosts seen only by the discovery phase, plus ports/scripts of the additional scans
    Merge-ExtraXml $x1
    if ($x4) { Merge-ExtraXml $x4 }
    if ($x5) { Merge-ExtraXml $x5 }

    # discovered names -> <hostnames> + synthetic "discovered-hostname" script
    foreach ($bh in $root.SelectNodes('host')) {
        $hip = Get-HostIp $bh
        if (-not $hip -or -not $db.ContainsKey($hip)) { continue }
        $rec = $db[$hip]
        if ($rec.Names.Count -eq 0) { continue }

        $ordered = @($rec.Names | Sort-Object { Get-Prio $_.Source })
        $best = $ordered | Select-Object -First 1
        $hnNode = Get-HostnamesNode $bh

        # real DNS records -> type="PTR"
        foreach ($n in ($ordered | Where-Object { $_.Source -like 'DNS-*' })) {
            $nm = $n.Name
            $dup = $false
            foreach ($ex1 in $hnNode.SelectNodes('hostname')) {
                if ($ex1.GetAttribute('name') -ieq $nm) { $dup = $true; break }
            }
            if (-not $dup) {
                $e = $merged.CreateElement('hostname')
                $e.SetAttribute('name', $nm)
                $e.SetAttribute('type', 'PTR')
                $null = $hnNode.AppendChild($e)
            }
        }
        # no PTR: best script-derived name (the Nmap DTD only allows user|PTR)
        if ($hnNode.SelectNodes('hostname').Count -eq 0) {
            $e = $merged.CreateElement('hostname')
            $e.SetAttribute('name', $best.Name)
            $e.SetAttribute('type', 'user')
            $null = $hnNode.AppendChild($e)
        }

        # synthetic script with name, source and alternatives
        $hs = Get-HostScriptNode $bh
        if (-not $hs.SelectSingleNode("script[@id='discovered-hostname']")) {
            $sc = $merged.CreateElement('script')
            $sc.SetAttribute('id', 'discovered-hostname')
            $lines = @($ordered | ForEach-Object { '  {0} (source: {1})' -f $_.Name, $_.Source })
            if ($rec.Domain) { $lines += ('  domain/workgroup: {0}' -f $rec.Domain) }
            $sc.SetAttribute('output', "`n" + ($lines -join "`n"))
            foreach ($n in $ordered) {
                $el = $merged.CreateElement('elem')
                $el.SetAttribute('key', (Get-XmlSafe $n.Source))
                $el.InnerText = $n.Name
                $null = $sc.AppendChild($el)
            }
            if ($rec.Domain) {
                $el = $merged.CreateElement('elem')
                $el.SetAttribute('key', 'domain')
                $el.InnerText = (Get-XmlSafe $rec.Domain)
                $null = $sc.AppendChild($el)
            }
            $null = $hs.AppendChild($sc)
        }
    }

    # hosts sorted by IP address
    $hostNodes = @($root.SelectNodes('host'))
    $sorted = @($hostNodes | Sort-Object {
        $i = Get-HostIp $_
        if ($i) { [version]$i } else { [version]'255.255.255.255' }
    })
    foreach ($n in $hostNodes) { $null = $root.RemoveChild($n) }
    $runNode = $root.SelectSingleNode('runstats')
    foreach ($n in $sorted) { $null = $root.InsertBefore($n, $runNode) }

    # general metadata: start, end, counters, command line
    $starts = @(); $ends = @()
    foreach ($f in $stageFiles) {
        $d = Read-Xml $f
        $starts += [int64]$d.DocumentElement.GetAttribute('start')
        $fin = $d.SelectSingleNode('/nmaprun/runstats/finished')
        if ($fin) { $ends += [int64]$fin.GetAttribute('time') }
    }
    $t0 = ($starts | Measure-Object -Minimum).Minimum
    $t1 = ($ends | Measure-Object -Maximum).Maximum
    $inv = [cultureinfo]::InvariantCulture
    $fmt = 'ddd MMM d HH:mm:ss yyyy'
    $t0s = [DateTimeOffset]::FromUnixTimeSeconds($t0).ToLocalTime().ToString($fmt, $inv)
    $t1s = [DateTimeOffset]::FromUnixTimeSeconds($t1).ToLocalTime().ToString($fmt, $inv)

    $censusHosts = (Read-Xml $x1).SelectSingleNode('/nmaprun/runstats/hosts')
    $totalAddr = [int]$censusHosts.GetAttribute('total')
    $upCount = @($root.SelectNodes("host[status/@state='up']")).Count
    $elapsed = [int]($t1 - $t0)

    $root.SetAttribute('start', [string]$t0)
    $root.SetAttribute('startstr', $t0s)
    $root.SetAttribute('args', 'merged scan from multiple phases: ' + ($cmdLog -join ' || '))

    $fin = $root.SelectSingleNode('runstats/finished')
    $fin.SetAttribute('time', [string]$t1)
    $fin.SetAttribute('timestr', $t1s)
    $fin.SetAttribute('elapsed', [string]$elapsed)
    $fin.SetAttribute('summary', ('Nmap done at {0}; {1} IP addresses ({2} hosts up) scanned in {3} seconds' -f $t1s, $totalAddr, $upCount, $elapsed))
    $fin.SetAttribute('exit', 'success')

    $hostsEl = $root.SelectSingleNode('runstats/hosts')
    $hostsEl.SetAttribute('up', [string]$upCount)
    $hostsEl.SetAttribute('down', [string][math]::Max(0, $totalAddr - $upCount))
    $hostsEl.SetAttribute('total', [string]$totalAddr)

    # comment with the DNS verification result (comments do not alter the standard format)
    $dnsTxt = ($dnsReport | ForEach-Object {
        '{0}: {1}, reverse zone {2}, PTR {3}/{4}, origin [{5}]' -f $_.Ip, $(if ($_.Used) { 'used' } else { 'not used' }), $(if ($_.ReverseZone) { 'present' } else { 'absent' }), $_.PtrFound, $_.Tested, $_.Origin
    }) -join '; '
    if (-not $dnsTxt) { $dnsTxt = 'no candidate DNS server' }
    $cmtText = ' DNS verification: ' + ($dnsTxt -replace '--', '- -') + ' '
    $firstChild = $root.SelectSingleNode('scaninfo')
    $cmt = $merged.CreateComment((Get-XmlSafe $cmtText))
    if ($firstChild) { $null = $root.InsertBefore($cmt, $firstChild) } else { $null = $root.PrependChild($cmt) }

    # save (UTF-8 without BOM, indented)
    $ws = [System.Xml.XmlWriterSettings]::new()
    $ws.Indent = $true
    $ws.IndentChars = '  '
    $ws.Encoding = [System.Text.UTF8Encoding]::new($false)
    $xw = [System.Xml.XmlWriter]::Create($OutFile, $ws)
    try { $merged.Save($xw) } finally { $xw.Close() }

    # sanity check: the file must load again
    $check = Read-Xml $OutFile
    $chkHosts = @($check.SelectNodes('/nmaprun/host'))
    $chkNamed = @($chkHosts | Where-Object { $_.SelectNodes('hostnames/hostname').Count -gt 0 })

    Write-Host "`n=== RESULT ===" -ForegroundColor Green
    Write-Host ("Hosts in the final file: {0} | with a name in <hostnames>: {1} | without a name: {2}" -f $chkHosts.Count, $chkNamed.Count, ($chkHosts.Count - $chkNamed.Count))
    Write-Host "Final XML (standard Nmap format): $OutFile"
    Write-Host "Per-phase XML files             : $StageDir"

    $missing = @($chkHosts | Where-Object { $_.SelectNodes('hostnames/hostname').Count -eq 0 })
    if ($missing.Count) {
        Write-Host "`nHosts still without a name:" -ForegroundColor Yellow
        $missRows = $missing | ForEach-Object {
            $osm = $_.SelectSingleNode('os/osmatch')
            $mac = $_.SelectSingleNode("address[@addrtype='mac']")
            [pscustomobject]@{
                IP     = Get-HostIp $_
                MAC    = if ($mac) { $mac.GetAttribute('addr') } else { '' }
                Vendor = if ($mac) { $mac.GetAttribute('vendor') } else { '' }
                OS     = if ($osm) { $osm.GetAttribute('name') } else { '' }
                Ports  = (@($_.SelectNodes("ports/port[state/@state='open']") | ForEach-Object { $_.GetAttribute('portid') }) -join ' ')
            }
        }
        Write-AlignedTable -Rows $missRows -Columns @(
            @{ Header = 'IP';         Property = 'IP';     Type = 'Text' },
            @{ Header = 'MAC';        Property = 'MAC';    Type = 'Text' },
            @{ Header = 'Vendor';     Property = 'Vendor'; Type = 'Text'; Wrap = $true },
            @{ Header = 'OS';         Property = 'OS';     Type = 'Text'; Wrap = $true },
            @{ Header = 'Open ports'; Property = 'Ports';  Type = 'Text'; Wrap = $true }
        )
    }
}
finally {
    Stop-Transcript | Out-Null
}
