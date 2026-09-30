#Requires -Version 5.1
<#
.SYNOPSIS
    IPv4 inventory and WPF desktop GUI for authorized networks.
.DESCRIPTION
    Native Windows/.NET discovery using runspace pools, cancellation, DNS,
    NBNS, LLMNR/mDNS PTR, ARP, TCP, banners, TLS and authenticated CIM.
    With no parameters, opens the GUI. Dot-source to load functions only.
    Quick discovers presence and names; Standard adds ports; Deep adds services.
    Exports HTML, CSV, JSON and Nmap-compatible XML without requiring Nmap.
.PARAMETER Subnet
    IPv4 CIDR, address or range. Can be combined with Target and TargetFile.
.PARAMETER Target
    IPv4 addresses, CIDR blocks or ranges, including 192.168.1.10-50.
.PARAMETER TargetFile
    One target per line. Lines may include comments starting with #.
.PARAMETER DnsServer
    Explicit IPv4 DNS resolvers. Defaults to active interface settings.
.PARAMETER Credential
    Credentials for CIM in Deep mode. Never exported or passed to processes.
.PARAMETER OutDir
    Report directory. Defaults to scan_yyyyMMdd_HHmmss in the current directory.
.PARAMETER OutFile
    XML output path. Defaults to OutDir/scan_complete.xml.
.PARAMETER SkipUdp
    Disable NBNS, mDNS and LLMNR. Unicast DNS remains enabled.
.PARAMETER Gui
    Open the WPF GUI in STA mode.
.PARAMETER Cli
    Run in command-line mode, including automatic subnet detection.
.PARAMETER ScanProfile
    Quick, Standard (CLI default), or Deep. Deep sends application probes.
.PARAMETER Ports
    Custom TCP ports, for example 22,80,443,8000-8010.
.PARAMETER TopPorts
    Use the first 100 or 1000 ports from the embedded Nmap port ranking.
.PARAMETER TimeoutMs
    Per-operation timeout in milliseconds.
.PARAMETER Retry
    TCP retries after timeout or failure, excluding explicit connection refusal.
.PARAMETER PingCount
    ICMP samples per host. Packet loss does not prove a host is offline.
.PARAMETER ThrottleLimit
    Maximum number of concurrent host workers.
.PARAMETER RateLimit
    Maximum probes started per second, shared by all workers.
.PARAMETER Baseline
    Previous JSON report. Compares matching targets and compatible coverage.
.PARAMETER OuiFile
    Local CSV with Prefix,Vendor columns and 6, 7 or 9 hexadecimal prefix digits.
.PARAMETER Force
    Allow more than 1024 targets or Deep mode without interactive confirmation.
.PARAMETER ShowVersion
    Display version and build date without opening the GUI or probing the network.
.EXAMPLE
    .\Invoke-HostNameDiscovery.ps1 -Gui
.EXAMPLE
    .\Invoke-HostNameDiscovery.ps1 -Cli -Target 127.0.0.1 -Profile Quick -SkipUdp
.EXAMPLE
    .\Invoke-HostNameDiscovery.ps1 -Subnet 192.168.1.0/24 -WhatIf
.NOTES
    Version: 2.1.5
    Build: 2026-09-29
    Changed: English UI, help, validation, logs and generated report labels.
    Added: visible, accessible search label.
    Added: explicit MAC source and routed-subnet explanation.
    Fixed: background tasks in packaged EXE no longer reload a missing script path.
    Use only on networks you own or are authorized to test.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Subnet, [string[]]$Target, [string]$TargetFile,
    [string[]]$DnsServer, [pscredential]$Credential,
    [string]$OutDir = (Join-Path (Get-Location).Path ('scan_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))),
    [string]$OutFile, [switch]$SkipUdp, [switch]$Gui, [switch]$Cli,
    [Alias('Profile')][ValidateSet('Quick','Standard','Deep')][string]$ScanProfile = 'Standard',
    [string]$Ports, [ValidateSet(100,1000)][int]$TopPorts = 100,
    [ValidateRange(100,30000)][int]$TimeoutMs = 800,
    [ValidateRange(0,3)][int]$Retry = 0,
    [ValidateRange(1,10)][int]$PingCount = 2,
    [ValidateRange(1,128)][int]$ThrottleLimit = 24,
    [ValidateRange(1,5000)][int]$RateLimit = 100,
    [string]$Baseline, [string]$OuiFile, [switch]$Force, [Alias('Version')][switch]$ShowVersion,
    [ValidateSet('Scan','Light','Dark')][string]$SelfTest, [string]$SelfTestReport, [string]$CapturePath
)
$script:Version = '2.1.5'
$script:BuildDate = '2026-09-29'
$script:DiscoveryPath = $PSCommandPath
[Threading.Thread]::CurrentThread.CurrentUICulture = [cultureinfo]'en-US'

function ConvertTo-DiscoveryIpNumber {
    param([string]$Address)
    $parsed = $null
    if ($Address -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -or
        -not [ipaddress]::TryParse($Address,[ref]$parsed) -or
        $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw "Invalid IPv4: $Address" }
    $bytes=$parsed.GetAddressBytes()
    return [uint64]$bytes[0]*16777216+[uint64]$bytes[1]*65536+[uint64]$bytes[2]*256+$bytes[3]
}
function ConvertFrom-DiscoveryIpNumber {
    param([uint64]$Number)
    if ($Number -gt 4294967295) { throw 'IPv4 out of range.' }
    return '{0}.{1}.{2}.{3}' -f (($Number -shr 24) -band 255),(($Number -shr 16) -band 255),(($Number -shr 8) -band 255),($Number -band 255)
}
function Get-DiscoveryTarget {
    param([string[]]$InputTarget, [string]$File, [int]$MaxTargets=65536)
    $items=@($InputTarget)
    if ($File) { $items+=@(Get-Content -LiteralPath $File -ErrorAction Stop) }
    $set=New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($line in $items) {
        foreach ($token in (($line -replace '#.*$','') -split '[,;\s]+' | Where-Object { $_ })) {
            $first=[uint64]0; $last=[uint64]0
            if ($token -match '^([^/]+)/(\d{1,2})$') {
                $address=ConvertTo-DiscoveryIpNumber $Matches[1]; $prefix=[int]$Matches[2]
                if ($prefix -gt 32) { throw "Invalid CIDR prefix: $token" }
                $size=[uint64][math]::Pow(2,32-$prefix)
                $first=[uint64]([math]::Floor($address/$size)*$size); $last=$first+$size-1
                if ($prefix -lt 31) { $first++; $last-- }
            } elseif ($token -match '^([^-]+)-([^-]+)$') {
                $left=$Matches[1]; $right=$Matches[2]; $first=ConvertTo-DiscoveryIpNumber $left
                if ($right -match '^\d{1,3}$') { $right=$left.Substring(0,$left.LastIndexOf('.')+1)+$right }
                $last=ConvertTo-DiscoveryIpNumber $right
                if ($last -lt $first) { throw "Reversed range: $token" }
            } else { $first=ConvertTo-DiscoveryIpNumber $token; $last=$first }
            if (($last-$first+1) -gt $MaxTargets) { throw "Range too large: maximum $MaxTargets addresses." }
            for ($n=$first; $n -le $last; $n++) {
                $null=$set.Add((ConvertFrom-DiscoveryIpNumber $n))
                if ($set.Count -gt $MaxTargets) { throw "Maximum $MaxTargets targets." }
            }
        }
    }
    if ($set.Count -eq 0) { throw 'Specify at least one IPv4 address, range or CIDR.' }
    $set | Sort-Object { ConvertTo-DiscoveryIpNumber $_ }
}
function Get-DiscoverySubnet {
    $active=@(Get-NetAdapter -ErrorAction Stop | Where-Object Status -eq 'Up' | Select-Object -ExpandProperty ifIndex)
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { $_.InterfaceIndex -in $active -and $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
        ForEach-Object {
            $number=ConvertTo-DiscoveryIpNumber $_.IPAddress
            $size=[uint64][math]::Pow(2,32-$_.PrefixLength)
            '{0}/{1}' -f (ConvertFrom-DiscoveryIpNumber ([uint64]([math]::Floor($number/$size)*$size))),$_.PrefixLength
        } | Sort-Object -Unique
}
function Get-DiscoveryPort {
    param([string]$Specification, [int]$Count=100)
    if (-not $Specification) { return @($script:RankedTcpPorts | Select-Object -First $Count) }
    $result=New-Object 'System.Collections.Generic.HashSet[int]'
    foreach ($part in ($Specification -split '[,;\s]+' | Where-Object { $_ })) {
        if ($part -notmatch '^(\d{1,5})(?:-(\d{1,5}))?$') { throw "Invalid port: $part" }
        $start=[int]$Matches[1]; $end=$start
        if ($Matches[2]) { $end=[int]$Matches[2] }
        if ($start -lt 1 -or $end -gt 65535 -or $end -lt $start) { throw "Ports out of range: $part" }
        for ($i=$start; $i -le $end; $i++) { $null=$result.Add($i) }
    }
    if (-not $result.Count) { throw 'Empty port list.' }
    $result | Sort-Object
}
function Write-DiscoveryLog {
    param([string]$Path,[ValidateSet('Info','Warning','Error','Debug')][string]$Level,[string]$Message)
    $entry='{0} [{1}] {2}' -f ([datetime]::UtcNow.ToString('o')),$Level,($Message -replace '[\r\n]+',' ')
    if ($Path) { Add-Content -LiteralPath $Path -Value $entry -Encoding UTF8 -ErrorAction Stop }
    Write-Verbose $entry
}
function Initialize-DiscoveryNative {
    if ('Discovery.Native' -as [type]) { return }
    Add-Type -TypeDefinition @"
using System;
using System.Net;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
namespace Discovery {
 public static class Native {
  [DllImport("iphlpapi.dll", ExactSpelling=true)]
  private static extern int SendARP(uint dest, uint src, byte[] mac, ref uint len);
  public static string Arp(string ip) {
   byte[] mac=new byte[6]; uint len=6;
   int rc=SendARP(BitConverter.ToUInt32(IPAddress.Parse(ip).GetAddressBytes(),0),0,mac,ref len);
   return rc==0 && len==6 ? BitConverter.ToString(mac) : null;
  }
 }
 public class TlsProbe : IDisposable {
  public SslStream Stream;
  public string PolicyErrors;
  public TlsProbe(System.IO.Stream stream) { Stream=new SslStream(stream,false,Validate); }
  private bool Validate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) {
   PolicyErrors=errors.ToString(); return true;
  }
  public void Dispose() { if(Stream!=null) Stream.Dispose(); }
 }
}
"@ -ErrorAction Stop
}
function Get-DiscoveryOui {
    param([string]$File)
    $map=@{'000C29'='VMware';'005056'='VMware';'00155D'='Microsoft Hyper-V';'080027'='VirtualBox'}
    if ($File) {
        foreach ($row in (Import-Csv -LiteralPath $File -ErrorAction Stop)) {
            $prefix=($row.Prefix -replace '[:-]','').ToUpperInvariant()
            if ($prefix -notmatch '^(?:[0-9A-F]{6}|[0-9A-F]{7}|[0-9A-F]{9})$' -or -not $row.Vendor) { throw 'OUI CSV: Prefix,Vendor columns; prefixes require 6, 7 or 9 hex digits.' }
            $map[$prefix]=[string]$row.Vendor
        }
    }
    return $map
}
function Get-DiscoveryVendor {
    param([string]$Mac,[hashtable]$Map)
    $hex=$Mac -replace '[:-]',''
    if ($hex.Length -ne 12) { return '' }
    if (([Convert]::ToInt32($hex.Substring(0,2),16) -band 2) -ne 0) { return 'Locally administered MAC' }
    foreach ($length in @(9,7,6)) {
        $prefix=$hex.Substring(0,$length).ToUpperInvariant()
        if ($Map.ContainsKey($prefix)) { return $Map[$prefix] }
    }
    return 'OUI unavailable'
}
function Wait-DiscoveryRate {
    param($Options,$Control)
    if ($Control.Cancel) { throw [OperationCanceledException]::new('Scan cancelled.') }
    [Threading.Monitor]::Enter($Control.Gate)
    try {
        $at=[math]::Max([datetime]::UtcNow.Ticks,[long]$Control.NextProbe)
        $Control.NextProbe=[long]($at+(10000000/$Options.RateLimit))
    } finally { [Threading.Monitor]::Exit($Control.Gate) }
    while ([datetime]::UtcNow.Ticks -lt $at) {
        if ($Control.Cancel) { throw [OperationCanceledException]::new('Scan cancelled.') }
        Start-Sleep -Milliseconds 10
    }
}
function Test-DiscoveryTcp {
    param([string]$Address,[int]$Port,$Options,$Control)
    for ($attempt=0; $attempt -le $Options.Retry; $attempt++) {
        Wait-DiscoveryRate $Options $Control
        $client=New-Object Net.Sockets.TcpClient
        try {
            $clock=[Diagnostics.Stopwatch]::StartNew(); $task=$client.ConnectAsync($Address,$Port)
            if (-not $task.Wait($Options.TimeoutMs)) { continue }
            if ($client.Connected) { return [pscustomobject]@{State='open';Ms=$clock.Elapsed.TotalMilliseconds} }
        } catch {
            $errorObject=$_.Exception
            while ($errorObject.InnerException) { $errorObject=$errorObject.InnerException }
            if ($errorObject -is [Net.Sockets.SocketException] -and $errorObject.SocketErrorCode -eq 'ConnectionRefused') {
                return [pscustomobject]@{State='closed';Ms=$null}
            }
        } finally { $client.Dispose() }
    }
    return [pscustomobject]@{State='filtered';Ms=$null}
}
function Get-DiscoveryPing {
    param([string]$Address,$Options,$Control)
    $samples=New-Object 'System.Collections.Generic.List[double]'; $ttl=$null
    $ping=New-Object Net.NetworkInformation.Ping
    try {
        for ($i=0; $i -lt $Options.PingCount; $i++) {
            Wait-DiscoveryRate $Options $Control
            try {
                $reply=$ping.Send($Address,$Options.TimeoutMs)
                if ($reply.Status -eq [Net.NetworkInformation.IPStatus]::Success) {
                    $samples.Add([double]$reply.RoundtripTime)
                    if ($reply.Options) { $ttl=$reply.Options.Ttl }
                }
            } catch { Write-Verbose "ICMP $Address : $($_.Exception.Message)" }
        }
    } finally { $ping.Dispose() }
    $stats=$samples | Measure-Object -Minimum -Maximum -Average
    [pscustomobject]@{Received=$samples.Count;Sent=$Options.PingCount;Ttl=$ttl;Min=$stats.Minimum;Avg=$stats.Average;Max=$stats.Maximum;Loss=[math]::Round(100*(1-$samples.Count/[double]$Options.PingCount),1)}
}
function Read-DiscoveryDnsName {
    param([byte[]]$Packet,[ref]$Offset)
    $labels=New-Object 'System.Collections.Generic.List[string]'
    $cursor=[int]$Offset.Value; $jumped=$false; $hops=0
    while ($true) {
        if ($cursor -ge $Packet.Length -or ++$hops -gt 128) { throw 'Invalid DNS response.' }
        $length=[int]$Packet[$cursor]
        if (($length -band 192) -eq 192) {
            if ($cursor+1 -ge $Packet.Length) { throw 'Truncated DNS pointer.' }
            if (-not $jumped) { $Offset.Value=$cursor+2; $jumped=$true }
            $cursor=(($length -band 63)*256)+$Packet[$cursor+1]; continue
        }
        $cursor++
        if ($length -eq 0) { if (-not $jumped) { $Offset.Value=$cursor }; break }
        if ($length -gt 63 -or $cursor+$length -gt $Packet.Length) { throw 'Invalid DNS label.' }
        $labels.Add([Text.Encoding]::UTF8.GetString($Packet,$cursor,$length)); $cursor+=$length
    }
    return ($labels -join '.')
}
function Get-DiscoveryPtr {
    param([string]$Address,[string]$Server,[int]$Port=53,$Options,$Control)
    $octets=$Address.Split('.'); [array]::Reverse($octets); $name=($octets -join '.')+'.in-addr.arpa'
    $id=Get-Random -Minimum 1 -Maximum 65535
    if ($Port -eq 5353) { $id=0 }
    $packet=New-Object 'System.Collections.Generic.List[byte]'
    $packet.AddRange([byte[]]@(($id -shr 8),($id -band 255),1,0,0,1,0,0,0,0,0,0))
    if ($Port -ne 53) { $packet[2]=0 }
    foreach ($label in $name.Split('.')) {
        $bytes=[Text.Encoding]::ASCII.GetBytes($label); $packet.Add([byte]$bytes.Length); $packet.AddRange($bytes)
    }
    $packet.AddRange([byte[]]@(0,0,12,0,1))
    if ($Port -eq 5353) { $packet[$packet.Count-2]=128 }
    $udp=New-Object Net.Sockets.UdpClient
    try {
        Wait-DiscoveryRate $Options $Control
        $udp.Client.ReceiveTimeout=$Options.TimeoutMs
        $null=$udp.Send($packet.ToArray(),$packet.Count,$Server,$Port)
        $remote=New-Object Net.IPEndPoint([ipaddress]::Any,0); $answer=$udp.Receive([ref]$remote)
        if ($answer.Length -lt 12 -or ($answer[2] -band 128) -eq 0 -or ($answer[3] -band 15) -ne 0) { return }
        if (([int]$answer[0]*256+$answer[1]) -ne $id) { return }
        if ($Port -eq 53 -and $remote.Address.ToString() -ne $Server) { return }
        if ($Port -ne 53 -and $remote.Address.ToString() -ne $Address) { return }
        $position=12; $questions=[int]$answer[4]*256+$answer[5]
        $records=[int]$answer[6]*256+$answer[7]+[int]$answer[8]*256+$answer[9]+[int]$answer[10]*256+$answer[11]
        for ($q=0; $q -lt $questions; $q++) { $null=Read-DiscoveryDnsName $answer ([ref]$position); $position+=4 }
        for ($r=0; $r -lt $records; $r++) {
            $owner=Read-DiscoveryDnsName $answer ([ref]$position)
            if ($position+10 -gt $answer.Length) { return }
            $kind=[int]$answer[$position]*256+$answer[$position+1]
            $length=[int]$answer[$position+8]*256+$answer[$position+9]; $position+=10
            if ($position+$length -gt $answer.Length) { return }
            if ($kind -eq 12 -and $owner -ieq $name) { $pointer=$position; Read-DiscoveryDnsName $answer ([ref]$pointer) }
            $position+=$length
        }
    } catch { Write-Verbose "PTR $Address via $Server : $($_.Exception.Message)" }
    finally { $udp.Dispose() }
}
function Get-DiscoveryNbnsName {
    param([string]$Address,$Options,$Control)
    $id=Get-Random -Minimum 1 -Maximum 65535
    $packet=New-Object 'System.Collections.Generic.List[byte]'
    $packet.AddRange([byte[]]@(($id -shr 8),($id -band 255),0,0,0,1,0,0,0,0,0,0,32))
    $raw=New-Object byte[] 16; $raw[0]=42
    foreach ($b in $raw) { $packet.Add([byte](65+($b -shr 4))); $packet.Add([byte](65+($b -band 15))) }
    $packet.AddRange([byte[]]@(0,0,33,0,1))
    $udp=New-Object Net.Sockets.UdpClient
    try {
        Wait-DiscoveryRate $Options $Control; $udp.Client.ReceiveTimeout=$Options.TimeoutMs
        $udp.Connect($Address,137); $null=$udp.Send($packet.ToArray(),$packet.Count)
        $remote=New-Object Net.IPEndPoint([ipaddress]::Any,0); $data=$udp.Receive([ref]$remote)
        if ($data.Length -lt 12 -or ([int]$data[0]*256+$data[1]) -ne $id -or ($data[3] -band 15) -ne 0) { return }
        $pos=12; $questions=[int]$data[4]*256+$data[5]
        for ($i=0; $i -lt $questions; $i++) { $null=Read-DiscoveryDnsName $data ([ref]$pos); $pos+=4 }
        $null=Read-DiscoveryDnsName $data ([ref]$pos)
        if ($pos+11 -gt $data.Length) { return }
        $pos+=10; $count=[int]$data[$pos]; $pos++
        for ($i=0; $i -lt $count; $i++) {
            if ($pos+18 -gt $data.Length) { return }
            $name=[Text.Encoding]::ASCII.GetString($data,$pos,15).Trim()
            if ($data[$pos+15] -eq 0 -and ($data[$pos+16] -band 128) -eq 0 -and $name) { $name }
            $pos+=18
        }
    } catch { Write-Verbose "NBNS $Address : $($_.Exception.Message)" }
    finally { $udp.Dispose() }
}
function Get-DiscoveryName {
    param([string]$Address,$Options,$Control)
    foreach ($server in $Options.DnsServers) {
        foreach ($name in @(Get-DiscoveryPtr $Address $server 53 $Options $Control)) {
            [pscustomobject]@{Name=$name;Source="DNS PTR ($server)";Confidence='Medium';Kind='Host'}
        }
    }
    if (-not $Options.SkipUdp) {
        foreach ($name in @(Get-DiscoveryNbnsName $Address $Options $Control)) {
            [pscustomobject]@{Name=$name;Source='NBNS';Confidence='Medium';Kind='Host'}
        }
        foreach ($source in @(@('224.0.0.252',5355,'LLMNR PTR'),@('224.0.0.251',5353,'mDNS PTR'))) {
            foreach ($name in @(Get-DiscoveryPtr $Address $source[0] $source[1] $Options $Control)) {
                [pscustomobject]@{Name=$name;Source=$source[2];Confidence='Low';Kind='Host'}
            }
        }
    }
}
# TCP ranking from installed nmap-services, snapshot 2026-09-29.
$script:RankedTcpPorts = @(80,23,443,21,22,25,3389,110,445,139,143,53,135,3306,8080,1723,111,995,993,5900,1025,587,8888,199,1720,465,548,113,81,6001,10000,514,5060,179,1026,2000,8443,8000,32768,554,26,1433,49152,2001,515,8008,49154,1027,5666,646,5000,5631,631,49153,8081,2049,88,79,5800,106,2121,1110,49155,6000,513,990,5357,427,49156,543,544,5101,144,7,389,8009,3128,444,9999,5009,7070,5190,3000,5432,3986,1900,13,1029,9,5051,6646,49157,1028,873,1755,2717,4899,9100,119,37,1000,3001,5001,82,10010,1030,9090,2107,1024,2103,6004,1801,5050,19,8031,1041,255,3703,1053,1054,1056,1049,1048,2967,1065,1064,17,808,3689,1031,1071,1044,5901,9102,100,4001,8010,1039,2869,5120,9000,2105,636,1038,2601,1,7000,1066,1069,625,311,280,254,4000,1761,5003,2002,1998,2005,1032,1050,6112,3690,1521,2161,1080,6002,2401,902,4045,787,7937,1058,2383,32771,1040,1033,1059,50000,5555,10001,1494,3,2301,593,7938,3268,1234,1022,1074,1037,1036,8002,9001,1035,464,6666,497,2003,1935,6543,1352,24,3269,1111,407,500,20,2006,1034,1218,3260,15000,4444,264,2004,33,1042,42510,999,3052,1023,1068,222,888,7100,563,1717,2008,992,32770,32772,7001,2007,8082,5550,512,2009,1043,5801,2701,1700,7019,50001,4662,2065,42,2010,9535,2602,3333,161,5100,4002,5002,2604,9595,5225,32769,8194,9415,2702,1311,8701,52869,6059,8193,8652,23502,8651,35500,5226,1047,1051,1052,1055,1060,16993,1062,65000,9593,64680,64623,9594,4443,3283,33354,8089,8192,16992,6789,55555,55600,65389,20828,13782,1067,366,5902,9050,5500,85,1002,1864,5431,49999,8085,10243,51103,1863,45100,49,90,6667,27000,6881,1503,340,8021,1500,9071,5566,8088,2222,8899,32773,1501,5102,9101,6005,9876,32774,163,5679,146,648,1666,901,83,3476,5214,8001,8083,8084,5004,9207,14238,30,912,12345,2605,2030,6,541,8007,4,3005,1248,880,2500,306,1097,1088,2525,1086,52822,9009,8291,4242,6101,900,2809,7200,12000,800,211,32775,987,1083,705,20005,711,6969,13783,1077,9900,1061,1075,1063,3367,10566,2144,1073,2718,16001,2119,1070,1072,58080,1078,9080,1079,50003,8600,2135,1106,5030,1104,34573,1100,1099,2875,8649,4126,4129,7627,7625,1096,1094,3580,1093,1085,1082,3551,1081,8873,3801,57294,1057,1840,10629,50006,48080,5222,4449,10002,2607,8222,5718,2811,10628,40193,8402,1783,10025,11967,10024,5269,8400,2160,10012,8333,5414,5633,10616,17988,7106,10617,16016,60020,1046,1045,16018,11110,3404,3071,49160,49159,7741,49158,10621,19101,2100,2190,9968,3784,5810,3766,7778,7777,10626,8181,19801,1098,1108,1310,5960,3659,3827,6123,3325,6129,5961,25734,6156,14442,5911,5962,5910,1947,3998,13456,27715,24800,9011,5959,20221,3323,32781,9220,1107,9500,32782,9502,6788,14000,28201,9290,9010,3300,9503,15660,3301,3351,1272,5925,63331,9002,1687,3031,6901,4003,20222,5985,30000,2399,2492,8994,33899,20000,3211,2260,1718,5987,21571,5825,34571,7911,34572,5988,5989,19842,5986,30718,1148,31038,6389,15002,3017,15003,65129,1169,22939,8086,9485,9618,6580,2381,5877,50800,20031,8087,691,89,32776,212,1999,1001,2020,6003,50002,2998,7002,898,32,5510,3372,2033,5903,99,749,425,6502,7007,6106,13722,458,43,5405,5054,61900,55055,3493,8500,2126,3871,24444,3077,3918,2251,5298,5280,1334,27353,27352,1782,3880,8011,7443,5200,10778,7512,8654,27355,7435,1580,9998,1296,7402,3995,49175,3371,3370,3369,5904,3030,16012,56738,9877,1186,61532,4006,15742,1183,62078,19780,4111,1124,3851,9666,9110,19315,50389,8100,1087,1152,5859,50636,8090,1089,5922,5915,8180,8254,3261,2179,5963,10004,4446,3737,7103,1247,49165,51493,32784,9944,18988,9943,49163,19283,3828,3546,3011,9091,2191,2522,5822,32779,9040,32777,1021,616,700,32778,2021,666,1524,5802,1112,84,38292,49400,4321,2040,545,1600,2048,3006,1084,32780,2111,9111,16080,6699,6547,2638,801,6007,1533,667,1443,2034,555,2106,720,5560,3914,6692,5730,6689,9200,2608,3920,27356,30951,49161,12174,40911,52673,3527,6839,6792,10003,52848,5815,6779,3324,5811,8200,5221,6025,4445,60443,3905,2394,6100,54045,11111,5440,8383,8290,8300,14441,8292,6510,3168,4567,5544,7999,3878,3869,3889,5678,6565,6567,2393,3826,55056,3517,8093,7920,10009,4550,7921,3322,26214,1862,25735,3003,15004,6566,7800,49167,9917,5907,1117,1114,1199,18040,3221,1201,57797,9575,18101,9003,1091,1090,5061,2323,8045,5033,1119,5906,17877,44501,5862,1151,8099,5850,50500,50300,44176,1138,7676,7496,1175,4005,1131,2909,4004,1122,9081,8022,32785,2725,3814,3390,3945,1271,3809,4848,41511,5952,5950,8042,10180,7025,10215,49176,32783,16000,5087,3971,4900,9878,5080,16113,9898,9418,4279,54328,8800,19350,12265,3800,56737,9099,70,617,4224,1009,6346,981,417,4998,722,714,2022,777,301,524,10082,5999,765,1076,668,2041,1007,1434,7004,2068,259,1984,6009,416,44443,2038,4343,1417,726,109,2035,2046,1461,1010,4125,7201,6006,687,9103,911,6669,683,1455,6668,2047,1011,125,481,2013,903,2043,44442,2042,9929,783,256,2045,843,406,5998,31337,32792,1233,1688,8050,58632,18264,32791,3731,7770,7744,3957,9444,3963,58630,3792,7080,3968,3969,1236,9098,3972,3981,1244,7123,9501,7749,5940,5938,57665,3870,3990,32816,1187,7438,1185,3697,1594,5899,4009,9600,17595,16800,1174,61613,58001,16851,9621,5869,58002,5868,1166,1165,1583,3684,1164,1163,2557,2910,3700,58838,32822,32835,1217,1216,7241,51413,1213,5918)
function Get-DiscoveryService {
    param([string]$Address,[int]$Port,$Options,$Control)
    $known=@{22='ssh';21='ftp';25='smtp';587='smtp';80='http';8080='http';8000='http';8008='http';8081='http';8888='http';443='https';8443='https';465='smtps';993='imaps';995='pop3s';445='microsoft-ds';3389='ms-wbt-server';53='domain';135='msrpc';139='netbios-ssn';3306='mysql';5432='postgresql'}
    $service='unknown'
    if ($known.ContainsKey($Port)) { $service=$known[$Port] }
    $result=[pscustomobject]@{Port=$Port;Protocol='tcp';State='open';Name=$service;Method='port-table';Banner='';HttpTitle='';HttpStatus='';Certificate=$null;Error=''}
    if ($service -notin @('unknown','ssh','ftp','smtp','http','https','smtps','imaps','pop3s')) { return $result }
    $client=New-Object Net.Sockets.TcpClient; $tls=$null; $stream=$null
    try {
        Wait-DiscoveryRate $Options $Control
        if (-not $client.ConnectAsync($Address,$Port).Wait($Options.TimeoutMs)) { throw 'Service connection timed out.' }
        $stream=$client.GetStream(); $stream.ReadTimeout=$Options.TimeoutMs; $stream.WriteTimeout=$Options.TimeoutMs
        if ($service -in @('https','smtps','imaps','pop3s')) {
            $tls=New-Object Discovery.TlsProbe($stream)
            $auth=$tls.Stream.BeginAuthenticateAsClient($Address,$null,$null)
            if (-not $auth.AsyncWaitHandle.WaitOne($Options.TimeoutMs)) { throw 'Timeout TLS.' }
            $tls.Stream.EndAuthenticateAsClient($auth)
            $stream=$tls.Stream; $stream.ReadTimeout=$Options.TimeoutMs; $stream.WriteTimeout=$Options.TimeoutMs
            $cert=New-Object Security.Cryptography.X509Certificates.X509Certificate2($stream.RemoteCertificate)
            try {
                $san=@($cert.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.17'} | ForEach-Object {$_.Format($false)}) -join '; '
                $result.Certificate=[pscustomobject]@{
                    CN=$cert.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)
                    Subject=$cert.Subject;SAN=$san;Issuer=$cert.Issuer
                    NotBefore=$cert.NotBefore.ToUniversalTime().ToString('o')
                    NotAfter=$cert.NotAfter.ToUniversalTime().ToString('o')
                    Thumbprint=$cert.Thumbprint;PolicyErrors=$tls.PolicyErrors
                }
            } finally { $cert.Dispose() }
        }
        if ($service -in @('http','https')) {
            $crlf=[string][char]13+[char]10
            $request=[Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.0${crlf}Host: $Address${crlf}User-Agent: HostNameDiscovery/2.0${crlf}Connection: close${crlf}${crlf}")
            $stream.Write($request,0,$request.Length)
        }
        $buffer=New-Object byte[] 4096; $memory=New-Object IO.MemoryStream
        try {
            $deadline=[datetime]::UtcNow.AddMilliseconds($Options.TimeoutMs)
            do {
                if ($Control.Cancel) { break }
                $remaining=[int]($deadline-[datetime]::UtcNow).TotalMilliseconds
                if ($remaining -le 0) { break }
                $stream.ReadTimeout=[math]::Max(1,$remaining)
                try { $read=$stream.Read($buffer,0,[math]::Min(4096,32768-$memory.Length)) } catch { break }
                if ($read -le 0) { break }
                $memory.Write($buffer,0,$read)
                if ($service -notin @('http','https')) { break }
            } while ($memory.Length -lt 32768)
            $text=[Text.Encoding]::UTF8.GetString($memory.ToArray()) -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]',''
        } finally { $memory.Dispose() }
        $result.Banner=$text.Substring(0,[math]::Min(2048,$text.Length))
        if ($text) {
            $result.Method='response'
            if ($text -match '^SSH-') {$result.Name='ssh'}
            elseif ($text -match '^220.*(?i:SMTP|ESMTP)') {$result.Name='smtp'}
            elseif ($text -match '^220.*(?i:FTP)') {$result.Name='ftp'}
        }
        if ($text -match '(?is)<title[^>]*>(.*?)</title>') { $result.HttpTitle=[Net.WebUtility]::HtmlDecode(($Matches[1] -replace '\s+',' ').Trim()) }
        if ($text -match '^HTTP/\S+\s+(\d{3})') { $result.HttpStatus=$Matches[1] }
    } catch { $result.Error=$_.Exception.Message }
    finally { if ($tls) {$tls.Dispose()} elseif ($stream) {$stream.Dispose()}; $client.Dispose() }
    return $result
}
function Get-DiscoveryCim {
    param([string]$Address,$Options,$Control)
    if (-not $Options.Credential) { return }
    Wait-DiscoveryRate $Options $Control; $session=$null
    try {
        $seconds=[uint32][math]::Max(2,[math]::Ceiling($Options.TimeoutMs/1000.0))
        $sessionOption=New-CimSessionOption -Protocol Dcom -ErrorAction Stop
        $session=New-CimSession -ComputerName $Address -Credential $Options.Credential -SessionOption $sessionOption -OperationTimeoutSec $seconds -ErrorAction Stop
        $os=Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $session -OperationTimeoutSec $seconds -ErrorAction Stop
        if ($Control.Cancel) { return }
        Wait-DiscoveryRate $Options $Control
        $system=Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $session -OperationTimeoutSec $seconds -ErrorAction Stop
        [pscustomobject]@{
            Hostname=$system.Name;Domain=$system.Domain;OS=$os.Caption;Version=$os.Version
            LastBoot=$os.LastBootUpTime.ToUniversalTime().ToString('o')
            UptimeSeconds=[math]::Round(((Get-Date)-$os.LastBootUpTime).TotalSeconds)
            Manufacturer=$system.Manufacturer;Model=$system.Model;Source='Authenticated CIM/DCOM'
        }
    } finally { if ($session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue } }
}
function Select-DiscoveryName {
    param([object[]]$Candidates)
    $valid=@($Candidates | Where-Object {$_.Kind -eq 'Host' -and $_.Name -and $_.Name -notmatch '[\s*/\\<>]'} |
        Sort-Object @{Expression={if ($_.Confidence -eq 'High') {0} elseif ($_.Source -like 'DNS*') {1} elseif ($_.Source -eq 'NBNS') {2} else {3}}},Name)
    if (-not $valid.Count) { return [pscustomobject]@{Name='';Source='';Confidence='None'} }
    $best=$valid[0]; $confidence=$best.Confidence
    $confirmations=@($valid | Where-Object {$_.Name.TrimEnd('.') -ieq $best.Name.TrimEnd('.')} | Select-Object -ExpandProperty Source -Unique)
    if ($confirmations.Count -gt 1 -and @($confirmations | Where-Object {$_ -notlike 'DNS*'}).Count) { $confidence='High' }
    [pscustomobject]@{Name=$best.Name.TrimEnd('.');Source=$best.Source;Confidence=$confidence}
}
function Get-DiscoveryHost {
    param([string]$Address,$Options,$Control)
    [Threading.Thread]::CurrentThread.CurrentUICulture = [cultureinfo]'en-US'
    $ErrorActionPreference='Stop'
    $record=[pscustomobject]@{
        PSTypeName='Discovery.Host';IP=$Address;State='Unknown';Status='? Not checked';Alive=$false
        Hostname='';NameSource='';Confidence='None';Names=@();MAC='';MACSource='';Vendor=''
        LatencyMin=$null;LatencyAvg=$null;LatencyMax=$null;PacketLoss=$null;TTL=$null
        OS='';OSConfidence='';Domain='';System=$null;Ports=@();OpenPorts='';Services=@()
        Evidence=@();Errors=@();MACObservations=@();Conflict='';Change='';History=@()
        Completed=$false;Timestamp=[datetime]::UtcNow.ToString('o')
    }
    try {
        $ping=Get-DiscoveryPing $Address $Options $Control
        $record.LatencyMin=$ping.Min; $record.LatencyAvg=$ping.Avg; $record.LatencyMax=$ping.Max
        $record.PacketLoss=$ping.Loss; $record.TTL=$ping.Ttl
        if ($ping.Received -gt 0) {$record.Alive=$true; $record.Evidence+='ICMP'}
        if ($Options.Neighbors.ContainsKey($Address)) {
            $cachedMac=@($Options.Neighbors[$Address] | Where-Object {$_ -and $_ -notmatch '^(00[-:]){5}00$'})
            if ($cachedMac.Count) {
                $record.MACObservations+=$cachedMac
                $record.MAC=$cachedMac[0]
                $record.MACSource='ARP cache'
                $record.Alive=$true
                $record.Evidence+='ARP cache'
            }
        }
        $local=$false; $number=ConvertTo-DiscoveryIpNumber $Address
        foreach ($range in $Options.LocalRanges) { if ($number -ge $range.First -and $number -le $range.Last) {$local=$true; break} }
        if ($local -and $Address -notlike '127.*') {
            Wait-DiscoveryRate $Options $Control; $mac=[Discovery.Native]::Arp($Address)
            if ($mac) {$record.MACObservations+=$mac; $record.MAC=$mac; $record.MACSource='ARP'; $record.Alive=$true; $record.Evidence+='ARP'}
        }
        $checked=@{}
        if (-not $record.Alive) {
            foreach ($port in @(443,80,445,3389)) {
                $probe=Test-DiscoveryTcp $Address $port $Options $Control; $checked[$port]=$probe
                if ($probe.State -in @('open','closed')) {$record.Alive=$true; $record.Evidence+="TCP $($probe.State) $port"; break}
            }
        }
        $record.Names=@(Get-DiscoveryName $Address $Options $Control)
        if ($Address -like '127.*' -or $Address -in $Options.LocalAddresses) {
            $record.Names+=[pscustomobject]@{Name=[Environment]::MachineName;Source='Local system';Confidence='High';Kind='Host'}
        }
        if (@($record.Names | Where-Object {$_.Source -notlike 'DNS*'}).Count) {$record.Alive=$true; $record.Evidence+='Local name response'}
        if ($Options.Profile -ne 'Quick') {
            foreach ($port in $Options.TcpPorts) {
                if ($checked.ContainsKey([int]$port)) {$probe=$checked[[int]$port]} else {$probe=Test-DiscoveryTcp $Address $port $Options $Control}
                if ($probe.State -in @('open','closed') -and -not $record.Alive) {
                    $record.Alive=$true; $record.Evidence+="TCP $($probe.State) $port"
                }
                $record.Ports+=[pscustomobject]@{Port=[int]$port;Protocol='tcp';State=$probe.State}
                if ($probe.State -eq 'open' -and $Options.Profile -eq 'Deep') {
                    $serviceInfo=Get-DiscoveryService $Address $port $Options $Control
                    $record.Services+=$serviceInfo
                    if ($serviceInfo.Error) {$record.Errors+=[pscustomobject]@{Stage="TCP service/$port";Message=$serviceInfo.Error}}
                }
            }
        }
        if ($record.Alive -and $Options.Profile -eq 'Deep' -and $Options.Credential) {
            try {
                $record.System=Get-DiscoveryCim $Address $Options $Control
                if ($record.System) {
                    $record.OS=$record.System.OS; $record.OSConfidence='High (CIM)'; $record.Domain=$record.System.Domain
                    $record.Names+=[pscustomobject]@{Name=$record.System.Hostname;Source='CIM';Confidence='High';Kind='Host'}
                }
            } catch {$record.Errors+=[pscustomobject]@{Stage='CIM';Message=$_.Exception.Message}}
        }
        $best=Select-DiscoveryName $record.Names
        $record.Hostname=$best.Name; $record.NameSource=$best.Source; $record.Confidence=$best.Confidence
        $record.OpenPorts=(@($record.Ports | Where-Object State -eq 'open' | Select-Object -ExpandProperty Port) -join ', ')
        if (-not $record.OS -and $record.TTL) {
            if ($record.TTL -le 64) {$record.OS='Unix/Linux or appliance (TTL estimate)'}
            elseif ($record.TTL -le 128) {$record.OS='Windows or appliance (TTL estimate)'}
            else {$record.OS='Network appliance or Unix (TTL estimate)'}
            $record.OSConfidence='Low'
        }
        $record.MACObservations=@($record.MACObservations | Where-Object {$_ -and $_ -notmatch '^(00[-:]){5}00$'} | Sort-Object -Unique)
        if ($record.MACObservations.Count -gt 1) {$record.Conflict='Different MAC addresses observed: possible conflict or legitimate change'}
        if ($record.MAC) {$record.Vendor=Get-DiscoveryVendor $record.MAC $Options.Oui}
        if (-not $record.MAC) {
            if ($local) {$record.MACSource='ARP unavailable'}
            else {$record.MACSource='Routed subnet; remote MAC unavailable via local ARP'; $record.Evidence+='Routed subnet'}
        }
        if ($record.Alive) {$record.State='Up'; $record.Status='+ Detected'}
        else {$record.State='Unresponsive'; $record.Status='? No response'}
        $record.Completed=$true
    } catch [OperationCanceledException] {$record.State='Cancelled'; $record.Status='! Cancelled'}
    catch {$record.State='Error'; $record.Status='! Error'; $record.Errors+=[pscustomobject]@{Stage='Host';Message=$_.Exception.Message}}
    return $record
}
function Get-DiscoveryConfiguration {
    param([string]$ScanProfile='Standard',[string]$PortSpecification,[int]$PortCount=100,
        [int]$Timeout=800,[int]$Retries=0,[int]$Samples=2,[int]$Throttle=24,[int]$Rate=100,
        [string[]]$Servers,[bool]$NoUdp=$false,[pscredential]$Account,[string]$OuiPath)
    $resolvers=@($Servers | Where-Object {$_})
    if (-not $resolvers.Count) {
        $active=@(Get-NetAdapter -ErrorAction Stop | Where-Object Status -eq 'Up' | Select-Object -ExpandProperty ifIndex)
        $resolvers=@(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object {$_.InterfaceIndex -in $active} | ForEach-Object {$_.ServerAddresses} | Sort-Object -Unique)
    }
    foreach ($server in $resolvers) {$null=ConvertTo-DiscoveryIpNumber $server}
    $neighbors=@{}
    foreach ($neighbor in @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
        if ($neighbor.LinkLayerAddress -and $neighbor.LinkLayerAddress -notmatch '^(00-){5}00$') {$neighbors[$neighbor.IPAddress]=@($neighbors[$neighbor.IPAddress])+$neighbor.LinkLayerAddress}
    }
    $ranges=@()
    foreach ($subnetItem in @(Get-DiscoverySubnet)) {
        $parts=$subnetItem.Split('/'); $first=ConvertTo-DiscoveryIpNumber $parts[0]
        $ranges+=[pscustomobject]@{First=$first;Last=$first+[uint64][math]::Pow(2,32-[int]$parts[1])-1}
    }
    @{
        Profile=$ScanProfile;TcpPorts=@(Get-DiscoveryPort $PortSpecification $PortCount)
        TimeoutMs=$Timeout;Retry=$Retries;PingCount=$Samples;ThrottleLimit=$Throttle;RateLimit=$Rate
        DnsServers=$resolvers;SkipUdp=$NoUdp;Credential=$Account;Oui=(Get-DiscoveryOui $OuiPath)
        Neighbors=$neighbors;LocalRanges=$ranges
        LocalAddresses=@(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Select-Object -ExpandProperty IPAddress)
    }
}
function Get-DiscoveryControl {
    [hashtable]::Synchronized(@{
        Cancel=$false;Gate=(New-Object object);NextProbe=[long]0;Completed=0;Total=0;Alive=0
        Queue=(New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]')
        Done=$false;Failure='';Result=$null
    })
}
function Compare-DiscoverySnapshot {
    param([object[]]$Current,$Previous,[string[]]$Scope,[string]$ScanProfile,[int[]]$TcpPorts)
    if (-not $Previous) {return}
    $old=@{}; foreach ($item in $Previous.Hosts) {$old[$item.IP]=$item}
    $comparable=$Previous.Metadata.Profile -eq $ScanProfile -and
        (($Previous.Metadata.TcpPorts | Sort-Object) -join ',') -eq (($TcpPorts | Sort-Object) -join ',')
    foreach ($item in $Current) {
        if (-not $item.Completed) {$item.Change='Not comparable'; continue}
        if (-not $old.ContainsKey($item.IP)) {if ($item.Alive) {$item.Change='New'}; continue}
        $before=$old[$item.IP]
        $item.History=@([pscustomobject]@{Timestamp=$before.Timestamp;Hostname=$before.Hostname;State=$before.State;MAC=$before.MAC;OpenPorts=$before.OpenPorts})
        if (-not $before.Completed) {$item.Change='Not comparable'; continue}
        if ($item.Alive -and -not $before.Alive) {$item.Change='Reappeared'}
        elseif (-not $item.Alive -and $before.Alive) {$item.Change='No longer detected'}
        elseif ($item.Alive) {
            $changed=($item.Hostname -ne $before.Hostname) -or ($item.MAC -and $before.MAC -and $item.MAC -ne $before.MAC)
            $currentPorts=($item.OpenPorts -split ',\s*' | Where-Object {$_} | Sort-Object {[int]$_}) -join ','
            $previousPorts=($before.OpenPorts -split ',\s*' | Where-Object {$_} | Sort-Object {[int]$_}) -join ','
            if ($comparable -and $currentPorts -ne $previousPorts) {$changed=$true}
            if ($comparable -and $item.OS -and $before.OS -and $item.OS -ne $before.OS) {$changed=$true}
            if ($comparable -and $ScanProfile -eq 'Deep') {
                $currentServices=@($item.Services | Sort-Object Port | ForEach-Object {
                    '{0}|{1}|{2}|{3}' -f $_.Port,$_.Name,$_.Banner,$_.Certificate.Thumbprint
                }) -join ';'
                $previousServices=@($before.Services | Sort-Object Port | ForEach-Object {
                    '{0}|{1}|{2}|{3}' -f $_.Port,$_.Name,$_.Banner,$_.Certificate.Thumbprint
                }) -join ';'
                if ($currentServices -ne $previousServices) {$changed=$true}
            }
            if ($changed) {$item.Change='Changed'} else {$item.Change='Unchanged'}
            if ($item.MAC -and $before.MAC -and $item.MAC -ne $before.MAC) {$item.Conflict='MAC changed since baseline; this does not prove a duplicate IP'}
        }
        if ($item.IP -notin $Scope) {$item.Change='Out of scope'}
    }
}
function Invoke-DiscoveryScan {
    param([string[]]$Addresses,$Options,$Control,[string]$OutputDirectory,[string]$XmlPath,[string]$BaselinePath)
    $ErrorActionPreference='Stop'; $started=[datetime]::UtcNow
    $results=New-Object 'System.Collections.Generic.List[object]'; $pool=$null
    $active=New-Object 'System.Collections.Generic.List[object]'
    $metadata=[pscustomobject]@{
        SchemaVersion=1;Version=$script:Version;BuildDate=$script:BuildDate
        Engine='Windows native / .NET';Started=$started.ToString('o');Finished='';DurationSeconds=0
        User=[Environment]::UserName;Machine=[Environment]::MachineName;Targets=$Addresses
        Profile=$Options.Profile;TcpPorts=$Options.TcpPorts;DnsServers=$Options.DnsServers
        Completed=$false;Cancelled=$false;Errors=@();ComparedBaseline=$BaselinePath
    }
    $previous=$null; $log=$null
    try {
        $null=New-Item -ItemType Directory -Path $OutputDirectory -Force -ErrorAction Stop
        $log=Join-Path $OutputDirectory 'log.txt'
        Write-DiscoveryLog $log Info "Starting $($Options.Profile): $($Addresses.Count) targets; version $script:Version"
        Write-DiscoveryLog $log Debug "Pool=$($Options.ThrottleLimit); timeout=$($Options.TimeoutMs)ms; TCP=$($Options.TcpPorts.Count); probe/sec=$($Options.RateLimit)"
        if ($BaselinePath) {$previous=Get-Content -LiteralPath $BaselinePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop}
        Initialize-DiscoveryNative
        $initial=[Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $workerFunctions=@('ConvertTo-DiscoveryIpNumber','Wait-DiscoveryRate','Test-DiscoveryTcp','Get-DiscoveryPing',
            'Read-DiscoveryDnsName','Get-DiscoveryPtr','Get-DiscoveryNbnsName','Get-DiscoveryName',
            'Get-DiscoveryService','Get-DiscoveryCim','Select-DiscoveryName','Get-DiscoveryVendor','Get-DiscoveryHost')
        foreach ($name in $workerFunctions) {
            $entry=New-Object Management.Automation.Runspaces.SessionStateFunctionEntry($name,(Get-Item "function:$name").Definition)
            $initial.Commands.Add($entry)
        }
        $pool=[runspacefactory]::CreateRunspacePool(1,$Options.ThrottleLimit,$initial,$Host); $pool.Open()
        $Control.Total=$Addresses.Count; $next=0
        while (($next -lt $Addresses.Count -and -not $Control.Cancel) -or $active.Count) {
            while (-not $Control.Cancel -and $next -lt $Addresses.Count -and $active.Count -lt $Options.ThrottleLimit) {
                $ps=[powershell]::Create(); $ps.RunspacePool=$pool
                $null=$ps.AddCommand('Get-DiscoveryHost').AddArgument($Addresses[$next]).AddArgument($Options).AddArgument($Control)
                $handle=$ps.BeginInvoke()
                $active.Add([pscustomobject]@{PowerShell=$ps;Handle=$handle;IP=$Addresses[$next]}); $next++
            }
            for ($i=$active.Count-1; $i -ge 0; $i--) {
                $job=$active[$i]
                if (-not $job.Handle.IsCompleted) {continue}
                try {
                    foreach ($row in $job.PowerShell.EndInvoke($job.Handle)) {
                        $results.Add($row); $Control.Queue.Enqueue($row); $Control.Completed++
                        if ($row.Alive) {$Control.Alive++}
                        foreach ($issue in $row.Errors) {Write-DiscoveryLog $log Warning "$($row.IP) $($issue.Stage): $($issue.Message)"}
                    }
                    foreach ($issue in $job.PowerShell.Streams.Error) {$metadata.Errors+=[string]$issue; Write-DiscoveryLog $log Error ([string]$issue)}
                } finally {$job.PowerShell.Dispose(); $active.RemoveAt($i)}
            }
            Start-Sleep -Milliseconds 40
        }
        Compare-DiscoverySnapshot $results.ToArray() $previous $Addresses $Options.Profile $Options.TcpPorts
        $metadata.Completed=(-not $Control.Cancel -and $results.Count -eq $Addresses.Count -and @($results | Where-Object {-not $_.Completed}).Count -eq 0)
    } catch {
        $Control.Failure=$_.Exception.Message; $metadata.Errors+=$_.Exception.Message
        if ($log) {Write-DiscoveryLog $log Error $_.Exception.Message}
    } finally {
        foreach ($job in $active) {try {$job.PowerShell.Stop()} finally {$job.PowerShell.Dispose()}}
        if ($pool) {$pool.Close(); $pool.Dispose()}
        $metadata.Cancelled=[bool]$Control.Cancel; $metadata.Finished=[datetime]::UtcNow.ToString('o')
        $metadata.DurationSeconds=[math]::Round(([datetime]::UtcNow-$started).TotalSeconds,2)
        $snapshot=[pscustomobject]@{Metadata=$metadata;Hosts=@($results.ToArray() | Sort-Object {ConvertTo-DiscoveryIpNumber $_.IP})}
        $Control.Result=$snapshot
        try {
            Export-DiscoverySnapshot $snapshot $OutputDirectory $XmlPath
            if ($log) {Write-DiscoveryLog $log Info "Finished: $($results.Count) results; completed=$($metadata.Completed); cancelled=$($metadata.Cancelled)"}
        } catch {$Control.Failure="Export: $($_.Exception.Message)"}
        $Control.Done=$true
    }
    return $snapshot
}
function ConvertTo-DiscoverySafeText {
    param([AllowNull()][object]$Value)
    return ([string]$Value -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]','')
}
function Export-DiscoverySnapshot {
    param($Snapshot,[string]$Directory,[string]$XmlPath)
    $null=New-Item -ItemType Directory -Path $Directory -Force -ErrorAction Stop
    if (-not $XmlPath) {$XmlPath=Join-Path $Directory 'scan_complete.xml'}
    $xmlParent=Split-Path -Parent ([IO.Path]::GetFullPath($XmlPath))
    $null=New-Item -ItemType Directory -Path $xmlParent -Force -ErrorAction Stop
    $json=$Snapshot | ConvertTo-Json -Depth 20
    $json | Set-Content -LiteralPath (Join-Path $Directory 'scan_complete.json') -Encoding UTF8 -ErrorAction Stop
    $columns=@('IP','Status','Hostname','NameSource','Confidence','MAC','MACSource','Vendor','LatencyMin','LatencyAvg','LatencyMax','PacketLoss','TTL','OS','OSConfidence','Domain','OpenPorts','Conflict','Change','Timestamp')
    $flat=@(foreach ($item in $Snapshot.Hosts) {
        $row=[ordered]@{ScanVersion=$Snapshot.Metadata.Version;ScanStarted=$Snapshot.Metadata.Started;ScanDuration=$Snapshot.Metadata.DurationSeconds;ScanUser=$Snapshot.Metadata.User;ScanMachine=$Snapshot.Metadata.Machine;ScanProfile=$Snapshot.Metadata.Profile}
        foreach ($key in $columns) {
            $value=$item.$key
            if ($value -is [string] -and $value -match '^[\s]*[=+@\-\t\r]') {$value="'"+$value}
            $row[$key]=$value
        }
        [pscustomobject]$row
    })
    $csvPath=Join-Path $Directory 'scan_complete.csv'
    if ($flat.Count) {$flat | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop}
    else {('"'+((@('ScanVersion','ScanStarted','ScanDuration','ScanUser','ScanMachine','ScanProfile')+$columns) -join '","')+'"') | Set-Content -LiteralPath $csvPath -Encoding UTF8}
    $html=New-Object Text.StringBuilder
    $null=$html.Append('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Network inventory</title><style>body{font:16px system-ui,sans-serif;background:#f4f6fa;color:#14243b;margin:2rem}h1{margin-bottom:.4rem}table{border-collapse:collapse;background:white;width:100%}th,td{padding:.65rem;text-align:left;border-bottom:1px solid #ccd3de}th{background:#14243b;color:white}pre{white-space:pre-wrap;overflow-wrap:anywhere}details{padding:.7rem;background:white;margin:.4rem 0}.table{overflow:auto}small{color:#40516a}</style></head><body><h1>Network inventory</h1>')
    $meta=$Snapshot.Metadata | ConvertTo-Json -Depth 5
    $null=$html.Append('<details><summary>Metadata and coverage</summary><pre>'+[Net.WebUtility]::HtmlEncode($meta)+'</pre></details>')
    $null=$html.Append('<p>No response does not mean offline. Estimated OS and MAC changes require verification.</p><div class="table"><table><thead><tr>')
    foreach ($key in @('Status','IP','Hostname','MAC','MAC source','Vendor','Avg. ms','OS','Ports','Source','Change')) {$null=$html.Append('<th>'+ $key +'</th>')}
    $null=$html.Append('</tr></thead><tbody>')
    foreach ($item in $Snapshot.Hosts) {
        $null=$html.Append('<tr>')
        foreach ($value in @($item.Status,$item.IP,$item.Hostname,$item.MAC,$item.MACSource,$item.Vendor,$item.LatencyAvg,$item.OS,$item.OpenPorts,$item.NameSource,$item.Change)) {
            $null=$html.Append('<td>'+[Net.WebUtility]::HtmlEncode([string]$value)+'</td>')
        }
        $null=$html.Append('</tr>')
    }
    $null=$html.Append('</tbody></table></div><h2>Details</h2>')
    foreach ($item in $Snapshot.Hosts) {
        $null=$html.Append('<details><summary>'+[Net.WebUtility]::HtmlEncode(($item.IP+' '+$item.Hostname))+'</summary><pre>'+[Net.WebUtility]::HtmlEncode(($item | ConvertTo-Json -Depth 15))+'</pre></details>')
    }
    $null=$html.Append('</body></html>')
    $html.ToString() | Set-Content -LiteralPath (Join-Path $Directory 'scan_complete.html') -Encoding UTF8 -ErrorAction Stop
    $settings=New-Object Xml.XmlWriterSettings; $settings.Indent=$true; $settings.Encoding=New-Object Text.UTF8Encoding($false)
    $writer=[Xml.XmlWriter]::Create($XmlPath,$settings)
    try {
        $writer.WriteStartDocument()
        $writer.WriteRaw('<!DOCTYPE nmaprun SYSTEM "https://nmap.org/book/dtd/nmap.dtd">')
        $writer.WriteStartElement('nmaprun')
        $writer.WriteAttributeString('scanner','nmap')
        $writer.WriteAttributeString('args','HostNameDiscovery native inventory (not an Nmap execution)')
        $epoch=[datetime]'1970-01-01T00:00:00Z'
        $start=[long]((([datetime]$Snapshot.Metadata.Started).ToUniversalTime()-$epoch.ToUniversalTime()).TotalSeconds)
        $end=[long]((([datetime]$Snapshot.Metadata.Finished).ToUniversalTime()-$epoch.ToUniversalTime()).TotalSeconds)
        $writer.WriteAttributeString('start',[string]$start); $writer.WriteAttributeString('startstr',$Snapshot.Metadata.Started)
        $writer.WriteAttributeString('version',$Snapshot.Metadata.Version); $writer.WriteAttributeString('xmloutputversion','1.05')
        $writer.WriteComment('Compatibility container. Engine: Windows native/.NET. TTL estimates are not Nmap OS fingerprints.')
        if ($Snapshot.Metadata.Profile -ne 'Quick') {
            $writer.WriteStartElement('scaninfo'); $writer.WriteAttributeString('type','connect'); $writer.WriteAttributeString('protocol','tcp')
            $writer.WriteAttributeString('numservices',[string]@($Snapshot.Metadata.TcpPorts).Count)
            $writer.WriteAttributeString('services',($Snapshot.Metadata.TcpPorts -join ',')); $writer.WriteEndElement()
        }
        $writer.WriteStartElement('verbose'); $writer.WriteAttributeString('level','0'); $writer.WriteEndElement()
        $writer.WriteStartElement('debugging'); $writer.WriteAttributeString('level','0'); $writer.WriteEndElement()
        foreach ($item in $Snapshot.Hosts) {
            $writer.WriteStartElement('host')
            $writer.WriteStartElement('status')
            $state='unknown'; if ($item.Alive) {$state='up'}
            $writer.WriteAttributeString('state',$state); $writer.WriteAttributeString('reason','user-set'); $writer.WriteAttributeString('reason_ttl','0'); $writer.WriteEndElement()
            $writer.WriteStartElement('address'); $writer.WriteAttributeString('addr',$item.IP); $writer.WriteAttributeString('addrtype','ipv4'); $writer.WriteEndElement()
            if ($item.MAC) {
                $writer.WriteStartElement('address'); $writer.WriteAttributeString('addr',$item.MAC.Replace('-',':'))
                $writer.WriteAttributeString('addrtype','mac'); $writer.WriteAttributeString('vendor',(ConvertTo-DiscoverySafeText $item.Vendor)); $writer.WriteEndElement()
            }
            $writer.WriteStartElement('hostnames')
            foreach ($name in @($item.Names | Where-Object {$_.Kind -eq 'Host'} | Sort-Object Name -Unique)) {
                $writer.WriteStartElement('hostname'); $writer.WriteAttributeString('name',(ConvertTo-DiscoverySafeText $name.Name))
                $kind='user'; if ($name.Source -like 'DNS*') {$kind='PTR'}
                $writer.WriteAttributeString('type',$kind); $writer.WriteEndElement()
            }
            $writer.WriteEndElement()
            if ($item.Ports.Count) {
                $writer.WriteStartElement('ports')
                foreach ($port in $item.Ports) {
                    $writer.WriteStartElement('port'); $writer.WriteAttributeString('protocol','tcp'); $writer.WriteAttributeString('portid',[string]$port.Port)
                    $writer.WriteStartElement('state'); $writer.WriteAttributeString('state',$port.State); $writer.WriteAttributeString('reason','user-set'); $writer.WriteAttributeString('reason_ttl','0'); $writer.WriteEndElement()
                    $service=$item.Services | Where-Object Port -eq $port.Port | Select-Object -First 1
                    if ($service) {
                        $writer.WriteStartElement('service'); $writer.WriteAttributeString('name',$service.Name)
                        $method='table'; $confidence='3'
                        if ($service.Method -eq 'response') {$method='probed'; $confidence='7'}
                        $writer.WriteAttributeString('method',$method); $writer.WriteAttributeString('conf',$confidence); $writer.WriteEndElement()
                        $writer.WriteStartElement('script'); $writer.WriteAttributeString('id','native-service-info')
                        $writer.WriteAttributeString('output',(ConvertTo-DiscoverySafeText ($service | ConvertTo-Json -Depth 8 -Compress))); $writer.WriteEndElement()
                    }
                    $writer.WriteEndElement()
                }
                $writer.WriteEndElement()
            }
            if ($item.OS) {
                $writer.WriteStartElement('os')
                $writer.WriteStartElement('osmatch')
                $writer.WriteAttributeString('name',(ConvertTo-DiscoverySafeText $item.OS))
                $accuracy='0'
                if ($item.OSConfidence -like 'High*') {$accuracy='95'}
                elseif ($item.OSConfidence -like 'Medium*') {$accuracy='60'}
                elseif ($item.OSConfidence -like 'Low*') {$accuracy='35'}
                $writer.WriteAttributeString('accuracy',$accuracy)
                $writer.WriteAttributeString('line','0')
                $writer.WriteEndElement(); $writer.WriteEndElement()
            }
            if ($item.System -and $item.System.UptimeSeconds -ne $null) {
                $writer.WriteStartElement('uptime')
                $writer.WriteAttributeString('seconds',[string][math]::Max(0,[int64]$item.System.UptimeSeconds))
                if ($item.System.LastBoot) {$writer.WriteAttributeString('lastboot',[string]$item.System.LastBoot)}
                $writer.WriteEndElement()
            }
            $writer.WriteStartElement('hostscript')
            $writer.WriteStartElement('script'); $writer.WriteAttributeString('id','discovered-hostname')
            $writer.WriteAttributeString('output',(ConvertTo-DiscoverySafeText ($item.Hostname+'; '+$item.NameSource+'; '+$item.Confidence)))
            $writer.WriteStartElement('elem'); $writer.WriteAttributeString('key','inventory')
            $writer.WriteString((ConvertTo-DiscoverySafeText ($item | ConvertTo-Json -Depth 15 -Compress)))
            $writer.WriteEndElement(); $writer.WriteEndElement(); $writer.WriteEndElement(); $writer.WriteEndElement()
        }
        $writer.WriteStartElement('runstats'); $writer.WriteStartElement('finished')
        $writer.WriteAttributeString('time',[string]$end); $writer.WriteAttributeString('timestr',$Snapshot.Metadata.Finished)
        $writer.WriteAttributeString('elapsed',$Snapshot.Metadata.DurationSeconds.ToString([cultureinfo]::InvariantCulture))
        $exit='error'; if ($Snapshot.Metadata.Completed) {$exit='success'}
        $writer.WriteAttributeString('exit',$exit); $writer.WriteAttributeString('summary','Native inventory; consult JSON metadata for incomplete coverage.'); $writer.WriteEndElement()
        $writer.WriteStartElement('hosts')
        $up=@($Snapshot.Hosts | Where-Object Alive).Count
        $writer.WriteAttributeString('up',[string]$up); $writer.WriteAttributeString('down','0')
        $writer.WriteAttributeString('total',[string]@($Snapshot.Hosts).Count)
        $writer.WriteEndElement(); $writer.WriteEndElement(); $writer.WriteEndElement(); $writer.WriteEndDocument()
    } finally {$writer.Dispose()}
}
function Send-DiscoveryWakePacket {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([Parameter(Mandatory=$true)][string]$Mac,[string]$Broadcast='255.255.255.255')
    $hex=$Mac -replace '[:-]',''
    if ($hex -notmatch '^[0-9a-fA-F]{12}$') {throw 'Invalid MAC address.'}
    if (-not $PSCmdlet.ShouldProcess($Mac,'Send Wake-on-LAN UDP/9')) {return}
    $bytes=New-Object 'System.Collections.Generic.List[byte]'
    $bytes.AddRange([byte[]]@(255,255,255,255,255,255))
    for ($i=0; $i -lt 16; $i++) {for ($j=0; $j -lt 12; $j+=2) {$bytes.Add([Convert]::ToByte($hex.Substring($j,2),16))}}
    $udp=New-Object Net.Sockets.UdpClient
    try {$udp.EnableBroadcast=$true; $null=$udp.Send($bytes.ToArray(),$bytes.Count,$Broadcast,9)}
    finally {$udp.Dispose()}
}
function Invoke-DiscoveryBackground {
    param([hashtable]$Arguments,$Control)
    $ps=New-DiscoveryPowerShell
    $null=$ps.AddScript({
        param($Arguments,$Control)
        try {
            [Threading.Thread]::CurrentThread.CurrentUICulture = [cultureinfo]'en-US'
            $optionArguments=$Arguments.Options; $options=Get-DiscoveryConfiguration @optionArguments
            $null=Invoke-DiscoveryScan -Addresses $Arguments.Addresses -Options $options -Control $Control -OutputDirectory $Arguments.OutputDirectory -XmlPath $Arguments.XmlPath -BaselinePath $Arguments.BaselinePath
        } catch {$Control.Failure=$_.Exception.Message; $Control.Done=$true}
    }).AddArgument($Arguments).AddArgument($Control)
    [pscustomobject]@{PowerShell=$ps;Handle=$ps.BeginInvoke()}
}
function Invoke-DiscoveryUtility {
    param([ValidateSet('Subnet','Export','Targets')][string]$Operation,$Snapshot,[string]$Destination)
    $ps=New-DiscoveryPowerShell
    $null=$ps.AddScript({
        param($Operation,$Snapshot,$Destination)
        $ErrorActionPreference='Stop'
        [Threading.Thread]::CurrentThread.CurrentUICulture = [cultureinfo]'en-US'
        if ($Operation -eq 'Subnet') {Get-DiscoverySubnet; return}
        if ($Operation -eq 'Targets') {Get-DiscoveryTarget -InputTarget $Snapshot.Input -File $Snapshot.File; return}
        $directory=Split-Path -Parent $Destination
        Export-DiscoverySnapshot $Snapshot $directory ''
        $source=Join-Path $directory ('scan_complete'+[IO.Path]::GetExtension($Destination))
        if ([IO.Path]::GetFullPath($source) -ne [IO.Path]::GetFullPath($Destination)) {
            Copy-Item -LiteralPath $source -Destination $Destination -Force -ErrorAction Stop
        }
        return $directory
    }).AddArgument($Operation).AddArgument($Snapshot).AddArgument($Destination)
    [pscustomobject]@{PowerShell=$ps;Handle=$ps.BeginInvoke();Operation=$Operation}
}
function New-DiscoveryPowerShell {
    $initial=[Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    foreach ($function in Get-ChildItem Function: | Where-Object Name -match '^[A-Za-z]+-Discovery') {
        $initial.Commands.Add([Management.Automation.Runspaces.SessionStateFunctionEntry]::new($function.Name,$function.Definition))
    }
    foreach ($name in @('Version','BuildDate','RankedTcpPorts')) {
        $value=Get-Variable -Name $name -Scope Script -ValueOnly
        $initial.Variables.Add([Management.Automation.Runspaces.SessionStateVariableEntry]::new($name,$value,''))
    }
    return [powershell]::Create($initial)
}
function Show-DiscoveryGui {
    param([switch]$SmokeTest,[switch]$SmokeScan,[switch]$SmokeDark,[string]$CapturePath)
    $ErrorActionPreference='Stop'
    $captureDestination=$CapturePath
    if ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {throw 'GUI requires STA: powershell.exe -STA -File "<script>" -Gui'}
    Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase -ErrorAction Stop
    [xml]$xaml=@"
 <Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
 Title="HostName Discovery" Width="1250" Height="800" MinWidth="900" MinHeight="620" WindowStartupLocation="CenterScreen" UseLayoutRounding="True"
 Background="{DynamicResource Canvas}" BorderBrush="{DynamicResource Canvas}" BorderThickness="0" SnapsToDevicePixels="True">
 <Window.Resources>
  <Style x:Key="ScrollPage" TargetType="RepeatButton"><Setter Property="Focusable" Value="False"/><Setter Property="Template"><Setter.Value><ControlTemplate TargetType="RepeatButton"><Border Background="Transparent"/></ControlTemplate></Setter.Value></Setter></Style>
  <Style TargetType="ScrollBar">
   <Setter Property="Background" Value="{DynamicResource Canvas}"/>
   <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="ScrollBar"><Grid Background="{TemplateBinding Background}"><Track x:Name="PART_Track" Orientation="{TemplateBinding Orientation}" IsDirectionReversed="True"><Track.DecreaseRepeatButton><RepeatButton Style="{StaticResource ScrollPage}" Command="ScrollBar.PageUpCommand"/></Track.DecreaseRepeatButton><Track.Thumb><Thumb><Thumb.Template><ControlTemplate TargetType="Thumb"><Border Background="{DynamicResource BorderStrong}" CornerRadius="4" Margin="3"/></ControlTemplate></Thumb.Template></Thumb></Track.Thumb><Track.IncreaseRepeatButton><RepeatButton Style="{StaticResource ScrollPage}" Command="ScrollBar.PageDownCommand"/></Track.IncreaseRepeatButton></Track></Grid><ControlTemplate.Triggers><Trigger Property="Orientation" Value="Horizontal"><Setter TargetName="PART_Track" Property="IsDirectionReversed" Value="False"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter>
  </Style>
  <Style TargetType="ProgressBar"><Setter Property="Template"><Setter.Value><ControlTemplate TargetType="ProgressBar"><Grid Background="{DynamicResource Border}"><Border x:Name="PART_Track"/><Border x:Name="PART_Indicator" Background="{DynamicResource Accent}" HorizontalAlignment="Left" CornerRadius="3"/></Grid></ControlTemplate></Setter.Value></Setter></Style>
  <SolidColorBrush x:Key="Canvas" Color="#F4F7FB"/><SolidColorBrush x:Key="Surface" Color="#FFFFFF"/>
  <SolidColorBrush x:Key="SurfaceRaised" Color="#FFFFFF"/><SolidColorBrush x:Key="ControlSurface" Color="#FFFFFF"/>
  <SolidColorBrush x:Key="Ink" Color="#172B4D"/><SolidColorBrush x:Key="Muted" Color="#5E6C84"/>
  <SolidColorBrush x:Key="Border" Color="#CBD5E1"/><SolidColorBrush x:Key="BorderStrong" Color="#94A3B8"/>
  <SolidColorBrush x:Key="Accent" Color="#2563EB"/><SolidColorBrush x:Key="AccentHover" Color="#1D4ED8"/>
  <SolidColorBrush x:Key="AccentPressed" Color="#1E40AF"/><SolidColorBrush x:Key="Selection" Color="#DBEAFE"/>
  <SolidColorBrush x:Key="HeaderSurface" Color="#E8EEF8"/><SolidColorBrush x:Key="Danger" Color="#DC2626"/>
  <CornerRadius x:Key="ControlRadius">6</CornerRadius>
  <Style TargetType="TextBlock"><Setter Property="Foreground" Value="{DynamicResource Ink}"/><Setter Property="TextOptions.TextFormattingMode" Value="Display"/></Style>
  <Style TargetType="Label"><Setter Property="Foreground" Value="{DynamicResource Muted}"/><Setter Property="FontSize" Value="12"/></Style>
  <Style TargetType="Button">
   <Setter Property="MinHeight" Value="36"/><Setter Property="Padding" Value="14,6"/><Setter Property="Margin" Value="4"/>
   <Setter Property="Background" Value="{DynamicResource ControlSurface}"/><Setter Property="Foreground" Value="{DynamicResource Ink}"/>
   <Setter Property="BorderBrush" Value="{DynamicResource Border}"/><Setter Property="BorderThickness" Value="1"/>
   <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
   <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button"><Border x:Name="ButtonBorder" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="6" Padding="{TemplateBinding Padding}"><ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}" VerticalAlignment="{TemplateBinding VerticalContentAlignment}" RecognizesAccessKey="True"/></Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="ButtonBorder" Property="Background" Value="{DynamicResource AccentHover}"/><Setter Property="Foreground" Value="White"/><Setter TargetName="ButtonBorder" Property="BorderBrush" Value="{DynamicResource AccentHover}"/></Trigger><Trigger Property="IsPressed" Value="True"><Setter TargetName="ButtonBorder" Property="Background" Value="{DynamicResource AccentPressed}"/><Setter Property="Foreground" Value="White"/></Trigger><Trigger Property="IsEnabled" Value="False"><Setter TargetName="ButtonBorder" Property="Opacity" Value=".45"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter>
  </Style>
  <Style x:Key="PrimaryButton" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}"><Setter Property="Background" Value="{DynamicResource Accent}"/><Setter Property="Foreground" Value="White"/><Setter Property="BorderBrush" Value="{DynamicResource Accent}"/></Style>
  <Style x:Key="DangerButton" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}"><Setter Property="Foreground" Value="{DynamicResource Danger}"/><Setter Property="BorderBrush" Value="{DynamicResource Danger}"/></Style>
  <Style TargetType="TextBox">
   <Setter Property="MinHeight" Value="34"/><Setter Property="Padding" Value="9,5"/><Setter Property="Margin" Value="4"/>
   <Setter Property="Background" Value="{DynamicResource ControlSurface}"/><Setter Property="Foreground" Value="{DynamicResource Ink}"/><Setter Property="BorderBrush" Value="{DynamicResource Border}"/><Setter Property="BorderThickness" Value="1"/><Setter Property="CaretBrush" Value="{DynamicResource Accent}"/><Setter Property="FocusVisualStyle" Value="{x:Null}"/>
   <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="TextBox"><Border x:Name="TextBorder" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="6"><ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}"/></Border><ControlTemplate.Triggers><Trigger Property="IsKeyboardFocusWithin" Value="True"><Setter TargetName="TextBorder" Property="BorderBrush" Value="{DynamicResource Accent}"/><Setter TargetName="TextBorder" Property="BorderThickness" Value="2"/></Trigger><Trigger Property="IsEnabled" Value="False"><Setter TargetName="TextBorder" Property="Opacity" Value=".5"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter>
  </Style>
  <Style TargetType="PasswordBox"><Setter Property="MinHeight" Value="34"/><Setter Property="Margin" Value="4"/><Setter Property="Padding" Value="9,5"/><Setter Property="Background" Value="{DynamicResource ControlSurface}"/><Setter Property="Foreground" Value="{DynamicResource Ink}"/><Setter Property="BorderBrush" Value="{DynamicResource Border}"/><Setter Property="BorderThickness" Value="1"/></Style>
  <Style TargetType="ComboBox"><Setter Property="MinHeight" Value="34"/><Setter Property="Margin" Value="4"/><Setter Property="Background" Value="{DynamicResource ControlSurface}"/><Setter Property="Foreground" Value="{DynamicResource Ink}"/><Setter Property="BorderBrush" Value="{DynamicResource Border}"/><Setter Property="BorderThickness" Value="1"/><Setter Property="Padding" Value="9,5"/><Setter Property="FocusVisualStyle" Value="{x:Null}"/><Setter Property="Template"><Setter.Value><ControlTemplate TargetType="ComboBox"><Grid><Border x:Name="ComboBorder" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="6"><Grid><ContentPresenter Margin="{TemplateBinding Padding}" VerticalAlignment="Center" HorizontalAlignment="Left" Content="{TemplateBinding SelectionBoxItem}" ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}"/><ToggleButton x:Name="DropDownButton" Width="30" HorizontalAlignment="Right" Focusable="False" ClickMode="Press" IsChecked="{Binding IsDropDownOpen, RelativeSource={RelativeSource TemplatedParent}}" Background="Transparent" BorderThickness="0"><Path Data="M 0 0 L 4 4 L 8 0" Stroke="{DynamicResource Muted}" StrokeThickness="1.5" HorizontalAlignment="Center" VerticalAlignment="Center"/></ToggleButton></Grid></Border><Popup x:Name="PART_Popup" AllowsTransparency="True" Focusable="False" IsOpen="{TemplateBinding IsDropDownOpen}" Placement="Bottom" PopupAnimation="Slide"><Border Background="{DynamicResource SurfaceRaised}" BorderBrush="{DynamicResource Border}" BorderThickness="1" CornerRadius="6" MinWidth="{Binding ActualWidth, RelativeSource={RelativeSource TemplatedParent}}"><ScrollViewer MaxHeight="300" CanContentScroll="True"><ItemsPresenter/></ScrollViewer></Border></Popup></Grid><ControlTemplate.Triggers><Trigger Property="IsKeyboardFocusWithin" Value="True"><Setter TargetName="ComboBorder" Property="BorderBrush" Value="{DynamicResource Accent}"/><Setter TargetName="ComboBorder" Property="BorderThickness" Value="2"/></Trigger><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="ComboBorder" Property="BorderBrush" Value="{DynamicResource Accent}"/></Trigger><Trigger Property="IsEnabled" Value="False"><Setter TargetName="ComboBorder" Property="Opacity" Value=".45"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter></Style>
  <Style TargetType="ComboBoxItem"><Setter Property="Foreground" Value="{DynamicResource Ink}"/><Setter Property="Background" Value="{DynamicResource ControlSurface}"/><Setter Property="Padding" Value="9,7"/><Style.Triggers><Trigger Property="IsHighlighted" Value="True"><Setter Property="Background" Value="{DynamicResource Selection}"/></Trigger></Style.Triggers></Style>
  <Style TargetType="ContextMenu"><Setter Property="Background" Value="{DynamicResource Surface}"/><Setter Property="Foreground" Value="{DynamicResource Ink}"/><Setter Property="BorderBrush" Value="{DynamicResource Border}"/></Style>
  <Style TargetType="MenuItem"><Setter Property="Foreground" Value="{DynamicResource Ink}"/><Setter Property="Padding" Value="10,7"/></Style>
  <Style TargetType="CheckBox"><Setter Property="Foreground" Value="{DynamicResource Ink}"/><Setter Property="Margin" Value="8"/><Setter Property="FocusVisualStyle" Value="{x:Null}"/></Style>
  <Style TargetType="Expander"><Setter Property="Foreground" Value="{DynamicResource Ink}"/><Setter Property="Margin" Value="4,0,4,10"/></Style>
  <Style TargetType="DataGrid"><Setter Property="Background" Value="{DynamicResource Surface}"/><Setter Property="Foreground" Value="{DynamicResource Ink}"/><Setter Property="BorderBrush" Value="{DynamicResource Border}"/><Setter Property="BorderThickness" Value="1"/><Setter Property="RowBackground" Value="{DynamicResource Surface}"/><Setter Property="AlternatingRowBackground" Value="{DynamicResource Canvas}"/><Setter Property="HorizontalGridLinesBrush" Value="{DynamicResource Border}"/><Setter Property="VerticalGridLinesBrush" Value="{DynamicResource Border}"/><Setter Property="SelectionUnit" Value="FullRow"/></Style>
  <Style TargetType="DataGridRow"><Setter Property="Foreground" Value="{DynamicResource Ink}"/><Setter Property="Background" Value="{DynamicResource Surface}"/><Setter Property="BorderBrush" Value="{DynamicResource Border}"/><Style.Triggers><Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{DynamicResource Selection}"/><Setter Property="Foreground" Value="{DynamicResource Ink}"/></Trigger></Style.Triggers></Style>
  <Style TargetType="DataGridCell"><Setter Property="Foreground" Value="{DynamicResource Ink}"/><Setter Property="Background" Value="Transparent"/><Setter Property="BorderBrush" Value="Transparent"/><Setter Property="Padding" Value="8,6"/></Style>
  <Style TargetType="DataGridColumnHeader"><Setter Property="Background" Value="{DynamicResource HeaderSurface}"/><Setter Property="Foreground" Value="{DynamicResource Ink}"/><Setter Property="BorderBrush" Value="{DynamicResource Border}"/><Setter Property="BorderThickness" Value="0,0,0,1"/><Setter Property="Padding" Value="10,8"/><Setter Property="FontWeight" Value="SemiBold"/></Style>
 </Window.Resources>
 <Grid Background="{DynamicResource Canvas}" Margin="18">
  <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
  <DockPanel Grid.Row="0" Margin="4,0,0,10">
   <StackPanel DockPanel.Dock="Right" Orientation="Horizontal"><Button Name="ThemeButton" Content="Theme"/><Button Name="ColumnsButton" Content="Columns"/><Button Name="AboutButton" Content="About"/></StackPanel>
   <StackPanel><TextBlock Text="HostName Discovery" FontSize="26" FontWeight="SemiBold"/><TextBlock Text="Authorized network inventory · presence, identity and services" FontSize="13"/></StackPanel>
  </DockPanel>
  <Grid Grid.Row="1"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="125"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
   <TextBox Name="TargetBox" AutomationProperties.Name="IPv4 targets" ToolTip="IP, CIDR or range; separate with spaces or commas"/>
   <Button Grid.Column="1" Name="AutoButton" Content="Local subnets" ToolTip="Detect all active subnets"/>
   <ComboBox Grid.Column="2" Name="ProfileBox" SelectedIndex="0" AutomationProperties.Name="Profile"><ComboBoxItem Content="Quick"/><ComboBoxItem Content="Standard"/><ComboBoxItem Content="Deep"/></ComboBox>
   <Button Grid.Column="3" Name="ScanButton" Style="{StaticResource PrimaryButton}" Content="_Scan" FontWeight="Bold" ToolTip="Start (F5)"/>
   <Button Grid.Column="4" Name="StopButton" Style="{StaticResource DangerButton}" Content="_Stop" IsEnabled="False" ToolTip="Cancel and save partial results (Esc)"/>
  </Grid>
  <TextBlock Grid.Row="2" Name="ValidationText" Margin="6,3,0,8" TextWrapping="Wrap"/>
  <Expander Name="AdvancedOptions" Grid.Row="3" Header="Advanced options" Margin="4,0,4,10" Foreground="{DynamicResource Ink}">
   <ScrollViewer MaxHeight="240" VerticalScrollBarVisibility="Auto"><StackPanel>
    <WrapPanel>
     <StackPanel Width="220"><TextBlock Text="Custom ports (blank = top ports)"/><TextBox Name="PortsBox" ToolTip="22,80,443,8000-8010"/></StackPanel>
     <StackPanel Width="100"><TextBlock Text="Top ports"/><ComboBox Name="TopBox" SelectedIndex="0"><ComboBoxItem Content="100"/><ComboBoxItem Content="1000"/></ComboBox></StackPanel>
     <StackPanel Width="100"><TextBlock Text="Timeout ms"/><TextBox Name="TimeoutBox" Text="800"/></StackPanel>
     <StackPanel Width="120"><TextBlock Text="Concurrent hosts"/><TextBox Name="ThrottleBox" Text="24"/></StackPanel>
     <StackPanel Width="100"><TextBlock Text="Probe/sec"/><TextBox Name="RateBox" Text="100"/></StackPanel>
     <StackPanel Width="80"><TextBlock Text="Retry TCP"/><TextBox Name="RetryBox" Text="0"/></StackPanel>
     <StackPanel Width="80"><TextBlock Text="Ping/host"/><TextBox Name="PingBox" Text="2"/></StackPanel>
     <CheckBox Name="SkipUdpBox" Content="Skip NBNS/multicast" Margin="12" VerticalAlignment="Center" Foreground="{DynamicResource Ink}"/>
    </WrapPanel>
    <WrapPanel>
     <StackPanel Width="250"><TextBlock Text="Target file (optional)"/><TextBox Name="FileBox"/></StackPanel>
     <StackPanel Width="250"><TextBlock Text="DNS servers (comma-separated)"/><TextBox Name="DnsBox"/></StackPanel>
     <StackPanel Width="250"><TextBlock Text="Baseline JSON (optional)"/><TextBox Name="BaselineBox"/></StackPanel>
     <StackPanel Width="250"><TextBlock Text="OUI CSV: Prefix,Vendor"/><TextBox Name="OuiBox"/></StackPanel>
    </WrapPanel>
    <WrapPanel>
     <StackPanel Width="500"><TextBlock Text="Report folder"/><TextBox Name="OutputBox"/></StackPanel>
     <StackPanel Width="250"><TextBlock Text="CIM account (Deep only)"/><TextBox Name="UserBox" ToolTip="DOMAIN\user. Not saved."/></StackPanel>
     <StackPanel Width="220"><TextBlock Text="Password (in memory only)"/><PasswordBox Name="PasswordBox" Margin="4" Height="32" AutomationProperties.Name="CIM password"/></StackPanel>
    </WrapPanel>
   </StackPanel></ScrollViewer>
  </Expander>
  <Grid Grid.Row="4"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="5"/><RowDefinition Height="150"/></Grid.RowDefinitions>
   <DockPanel>
    <Button Name="ExportButton" DockPanel.Dock="Right" VerticalAlignment="Bottom" Content="Export…" ToolTip="HTML, CSV, JSON and XML (Ctrl+E)" IsEnabled="False"/>
    <ComboBox Name="FilterBox" DockPanel.Dock="Right" VerticalAlignment="Bottom" Width="160" SelectedIndex="0" AutomationProperties.Name="Filter hosts"><ComboBoxItem Content="All"/><ComboBoxItem Content="Detected"/><ComboBoxItem Content="Unresponsive"/><ComboBoxItem Content="Changed"/></ComboBox>
    <StackPanel><Label Content="_Search hosts — IP, hostname, MAC, vendor, OS or ports" Target="{Binding ElementName=SearchBox}" Foreground="{DynamicResource Ink}" Padding="5,0,5,2"/><TextBox Name="SearchBox" AutomationProperties.Name="Search hosts by IP, hostname, MAC, vendor, OS or ports" ToolTip="Search IP, hostname, MAC, vendor, OS or ports (Ctrl+F)"/></StackPanel>
   </DockPanel>
   <DataGrid Grid.Row="1" Name="ResultsGrid" AutoGenerateColumns="False" IsReadOnly="True" CanUserAddRows="False" CanUserReorderColumns="True"
    CanUserResizeColumns="True" SelectionMode="Single" EnableRowVirtualization="True" EnableColumnVirtualization="True" Background="{DynamicResource Surface}" RowHeaderWidth="0" ScrollViewer.HorizontalScrollBarVisibility="Auto" ScrollViewer.VerticalScrollBarVisibility="Auto">
    <DataGrid.Columns>
     <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="145"/>
     <DataGridTextColumn Header="IP" Binding="{Binding IP}" SortMemberPath="IpSort" Width="125"/>
     <DataGridTextColumn Header="Hostname" Binding="{Binding Hostname}" Width="160"/>
     <DataGridTextColumn Header="MAC" Binding="{Binding MAC}" Width="145"/>
     <DataGridTextColumn Header="MAC source" Binding="{Binding MACSource}" Width="260"/>
     <DataGridTextColumn Header="Vendor" Binding="{Binding Vendor}" Width="150"/>
     <DataGridTextColumn Header="Avg. ms" Binding="{Binding LatencyAvg,StringFormat=F1}" Width="90"/>
     <DataGridTextColumn Header="OS" Binding="{Binding OS}" Width="220"/>
     <DataGridTextColumn Header="Ports" Binding="{Binding OpenPorts}" Width="130"/>
     <DataGridTextColumn Header="Name source" Binding="{Binding NameSource}" Width="150"/>
     <DataGridTextColumn Header="Confidence" Binding="{Binding Confidence}" Width="100"/>
     <DataGridTextColumn Header="Change" Binding="{Binding Change}" Width="130"/>
    </DataGrid.Columns>
    <DataGrid.ContextMenu><ContextMenu>
     <MenuItem Name="CopyIp" Header="Copy IP"/><MenuItem Name="CopyMac" Header="Copy MAC"/><MenuItem Name="CopyName" Header="Copy hostname"/>
     <Separator/><MenuItem Name="PingAction" Header="Ping"/><MenuItem Name="TraceAction" Header="Traceroute"/>
     <MenuItem Name="BrowserAction" Header="Open in browser"/><MenuItem Name="RdpAction" Header="Remote Desktop"/><MenuItem Name="SshAction" Header="SSH"/>
     <Separator/><MenuItem Name="WakeAction" Header="Wake-on-LAN…"/>
    </ContextMenu></DataGrid.ContextMenu>
   </DataGrid>
   <GridSplitter Grid.Row="2" Height="5" HorizontalAlignment="Stretch" Background="{DynamicResource Border}"/>
   <TextBox Grid.Row="3" Name="DetailsBox" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Hidden" FontFamily="Consolas" FontSize="12" AutomationProperties.Name="Details host" Text="Select a host to inspect ports, services, certificates, errors and history."/>
  </Grid>
  <StackPanel Grid.Row="5" Margin="4,12,4,0"><ProgressBar Name="Progress" Height="8" Minimum="0" Maximum="100"/><TextBlock Name="StatusText" Margin="0,8,0,0" Text="Ready. Quick discovers presence and names." TextWrapping="Wrap"/></StackPanel>
 </Grid>
</Window>
"@
    $reader=New-Object Xml.XmlNodeReader($xaml)
    $window=[Windows.Markup.XamlReader]::Load($reader)
    $ui=@{}
    foreach ($node in $xaml.SelectNodes('//*[@Name]')) {$ui[$node.Name]=$window.FindName($node.Name)}
    $state=@{Job=$null;AuxJob=$null;Prepared=$null;Control=$null;Snapshot=$null;Started=$null;Dark=$false;Closing=$false;Items=(New-Object 'System.Collections.ObjectModel.ObservableCollection[object]')}
    $ui.ResultsGrid.ItemsSource=$state.Items
    $view=[Windows.Data.CollectionViewSource]::GetDefaultView($state.Items)
    $settingsFolder=Join-Path $env:APPDATA 'HostNameDiscovery'
    $settingsFile=Join-Path $settingsFolder 'settings.json'
    $ui.OutputBox.Text=Join-Path ([Environment]::GetFolderPath('MyDocuments')) ('NetworkScans\scan_'+(Get-Date -Format 'yyyyMMdd_HHmmss'))
    $applyTheme={
        $colors=@{Canvas='#F4F7FB';Surface='#FFFFFF';SurfaceRaised='#FFFFFF';ControlSurface='#FFFFFF';Ink='#172B4D';Muted='#5E6C84';Border='#CBD5E1';BorderStrong='#94A3B8';Accent='#2563EB';AccentHover='#1D4ED8';AccentPressed='#1E40AF';Selection='#DBEAFE';HeaderSurface='#E8EEF8';Danger='#DC2626'}
        if ($state.Dark) {$colors=@{Canvas='#101722';Surface='#182231';SurfaceRaised='#202D3D';ControlSurface='#202D3D';Ink='#F3F6FB';Muted='#A8B5C7';Border='#34445A';BorderStrong='#50647D';Accent='#60A5FA';AccentHover='#93C5FD';AccentPressed='#3B82F6';Selection='#23466E';HeaderSurface='#25364D';Danger='#F87171'}}
        foreach ($key in $colors.Keys) {$window.Resources[$key]=[Windows.Media.SolidColorBrush]::new([Windows.Media.ColorConverter]::ConvertFromString($colors[$key]))}
    }
    try {
        if (-not $SmokeTest -and (Test-Path -LiteralPath $settingsFile)) {
            $saved=Get-Content -LiteralPath $settingsFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $ui.TargetBox.Text=[string]$saved.Target; $state.Dark=[bool]$saved.Dark
            foreach ($item in $ui.ProfileBox.Items) {if ($item.Content -eq $saved.Profile) {$ui.ProfileBox.SelectedItem=$item}}
            foreach ($column in $ui.ResultsGrid.Columns) {
                $config=$saved.Columns | Where-Object Header -eq $column.Header | Select-Object -First 1
                if ($config) {$column.Width=[double]$config.Width; $column.Visibility=[Windows.Visibility]$config.Visibility}
            }
            foreach ($config in @($saved.Columns | Sort-Object Index)) {
                $column=$ui.ResultsGrid.Columns | Where-Object Header -eq $config.Header | Select-Object -First 1
                if ($column -and $config.Index -ge 0 -and $config.Index -lt $ui.ResultsGrid.Columns.Count) {$column.DisplayIndex=[int]$config.Index}
            }
        }
    } catch {$ui.StatusText.Text="Settings could not be loaded: $($_.Exception.Message)"}
    & $applyTheme
    $validate={
        try {
            if ([string]::IsNullOrWhiteSpace($ui.TargetBox.Text) -and [string]::IsNullOrWhiteSpace($ui.FileBox.Text)) {throw 'Enter a target or select Local subnets.'}
            foreach ($token in ($ui.TargetBox.Text -split '[,;\s]+' | Where-Object {$_})) {
                if ($token -notmatch '^\d{1,3}(\.\d{1,3}){3}(/([0-9]|[12][0-9]|3[0-2])|-(\d{1,3}|\d{1,3}(\.\d{1,3}){3}))?$') {throw "Invalid target format: $token"}
            }
            $ui.ValidationText.Text='IPv4: address, CIDR or range. Coverage is checked before scanning.'
            if (-not $state.Job) {$ui.ScanButton.IsEnabled=$true}
        } catch {$ui.ValidationText.Text=$_.Exception.Message; $ui.ScanButton.IsEnabled=$false}
    }
    $ui.TargetBox.Add_TextChanged($validate); $ui.FileBox.Add_TextChanged($validate); & $validate
    $ui.AutoButton.Add_Click({
        if ($state.AuxJob -or $state.Job) {return}
        try {
            $state.AuxJob=Invoke-DiscoveryUtility -Operation Subnet
            $ui.AutoButton.IsEnabled=$false; $ui.ScanButton.IsEnabled=$false
            $ui.StatusText.Text='Detecting subnets…'
        } catch {$ui.ValidationText.Text=$_.Exception.Message}
    })
    $view.Filter={
        param($row)
        $search=$ui.SearchBox.Text
        if ($search -and (($row.IP,$row.Hostname,$row.MAC,$row.Vendor,$row.OS,$row.OpenPorts -join ' ') -notlike ('*'+[WildcardPattern]::Escape($search)+'*'))) {return $false}
        switch ($ui.FilterBox.SelectedIndex) {
            1 {return [bool]$row.Alive}
            2 {return (-not $row.Alive)}
            3 {return [bool]($row.Change -and $row.Change -ne 'Unchanged')}
        }
        return $true
    }
    $ui.SearchBox.Add_TextChanged({$view.Refresh()}); $ui.FilterBox.Add_SelectionChanged({$view.Refresh()})
    $ui.ResultsGrid.Add_SelectionChanged({if ($ui.ResultsGrid.SelectedItem) {$ui.DetailsBox.Text=$ui.ResultsGrid.SelectedItem | ConvertTo-Json -Depth 15}})
    $startScan={
        if ($state.Job -or $state.AuxJob) {return}
        try {
            if (-not $state.Prepared) {
                $state.AuxJob=Invoke-DiscoveryUtility -Operation Targets -Snapshot @{Input=@($ui.TargetBox.Text);File=$ui.FileBox.Text}
                $ui.TargetBox.IsEnabled=$false; $ui.FileBox.IsEnabled=$false; $ui.ScanButton.IsEnabled=$false
                $ui.StatusText.Text='Validating and expanding targets in the background…'
                return
            }
            $addresses=@($state.Prepared); $state.Prepared=$null
            $profileName=[string]$ui.ProfileBox.SelectedItem.Content
            $message=''
            if ($addresses.Count -gt 1024) {$message+="Large scan: $($addresses.Count) addresses. "}
            if ($profileName -eq 'Deep') {$message+='Deep sends service requests. Use Quick or an agreed maintenance window for sensitive devices. '}
            if ($message -and [Windows.MessageBox]::Show($window,$message+'Continue?','Confirm scan','YesNo','Warning') -ne 'Yes') {return}
            $timeoutValue=[int]$ui.TimeoutBox.Text; $throttleValue=[int]$ui.ThrottleBox.Text; $rateValue=[int]$ui.RateBox.Text
            $retryValue=[int]$ui.RetryBox.Text; $pingValue=[int]$ui.PingBox.Text
            if ($timeoutValue -lt 100 -or $timeoutValue -gt 30000) {throw 'Timeout: 100-30000 ms.'}
            if ($throttleValue -lt 1 -or $throttleValue -gt 128) {throw 'Concurrent hosts: 1-128.'}
            if ($rateValue -lt 1 -or $rateValue -gt 5000) {throw 'Probe/sec: 1-5000.'}
            if ($retryValue -lt 0 -or $retryValue -gt 3 -or $pingValue -lt 1 -or $pingValue -gt 10) {throw 'Retry: 0-3; ping/host: 1-10.'}
            $null=Get-DiscoveryPort $ui.PortsBox.Text ([int]$ui.TopBox.SelectedItem.Content)
            if ([string]::IsNullOrWhiteSpace($ui.OutputBox.Text)) {throw 'Specify a report folder.'}
            $account=$null
            if ($ui.UserBox.Text) {$account=New-Object Management.Automation.PSCredential($ui.UserBox.Text,$ui.PasswordBox.SecurePassword)}
            $options=@{
                ScanProfile=$profileName;PortSpecification=$ui.PortsBox.Text;PortCount=[int]$ui.TopBox.SelectedItem.Content
                Timeout=$timeoutValue;Retries=$retryValue;Samples=$pingValue;Throttle=$throttleValue;Rate=$rateValue
                Servers=@($ui.DnsBox.Text -split '[,;\s]+' | Where-Object {$_});NoUdp=[bool]$ui.SkipUdpBox.IsChecked
                Account=$account;OuiPath=$ui.OuiBox.Text
            }
            $arguments=@{Addresses=$addresses;Options=$options;OutputDirectory=$ui.OutputBox.Text;BaselinePath=$ui.BaselineBox.Text;XmlPath=''}
            $state.Items.Clear(); $state.Snapshot=$null; $state.Control=Get-DiscoveryControl
            $state.Control.Total=$addresses.Count; $state.Started=Get-Date
            $state.Job=Invoke-DiscoveryBackground $arguments $state.Control
            $ui.PasswordBox.Clear(); $ui.ScanButton.IsEnabled=$false; $ui.StopButton.IsEnabled=$true; $ui.ExportButton.IsEnabled=$false
            $ui.StatusText.Text='Scan started. Stop preserves completed results.'
        } catch {$ui.StatusText.Text='Error: '+$_.Exception.Message}
    }
    $stopScan={if ($state.Control -and $state.Job) {$state.Control.Cancel=$true; $ui.StopButton.IsEnabled=$false; $ui.StatusText.Text='Cancelling and saving partial results…'}}
    $export={
        if (-not $state.Snapshot -or $state.Job -or $state.AuxJob) {return}
        $dialog=New-Object Microsoft.Win32.SaveFileDialog
        $dialog.Title='Export report (all four formats)'
        $dialog.Filter='Report HTML (*.html)|*.html|CSV (*.csv)|*.csv'; $dialog.FileName='scan_complete.html'
        if ($dialog.ShowDialog($window)) {
            try {
                $state.AuxJob=Invoke-DiscoveryUtility -Operation Export -Snapshot $state.Snapshot -Destination $dialog.FileName
                $ui.ExportButton.IsEnabled=$false; $ui.ScanButton.IsEnabled=$false
                $ui.StatusText.Text='Exporting in the background…'
            } catch {$ui.StatusText.Text='Export failed: '+$_.Exception.Message}
        }
    }
    $ui.ScanButton.Add_Click($startScan); $ui.StopButton.Add_Click($stopScan); $ui.ExportButton.Add_Click($export)
    $timer=New-Object Windows.Threading.DispatcherTimer; $timer.Interval=[timespan]::FromMilliseconds(150)
    $timer.Add_Tick({
        if ($state.AuxJob -and $state.AuxJob.Handle.IsCompleted) {
            $startPrepared=$false
            try {
                $utilityResult=@($state.AuxJob.PowerShell.EndInvoke($state.AuxJob.Handle))
                if ($state.AuxJob.Operation -eq 'Subnet') {$ui.TargetBox.Text=$utilityResult -join ', '; $ui.StatusText.Text='Subnets detected: review targets before starting.'}
                elseif ($state.AuxJob.Operation -eq 'Targets') {$state.Prepared=$utilityResult; $startPrepared=$true}
                else {$ui.StatusText.Text='Exported HTML, CSV, JSON and XML to '+($utilityResult -join '')}
            } catch {$ui.StatusText.Text='Error: '+$_.Exception.Message}
            finally {$state.AuxJob.PowerShell.Dispose(); $state.AuxJob=$null}
            $ui.AutoButton.IsEnabled=$true; $ui.ScanButton.IsEnabled=$true
            $ui.TargetBox.IsEnabled=$true; $ui.FileBox.IsEnabled=$true
            $ui.ExportButton.IsEnabled=($null -ne $state.Snapshot)
            if ($state.Closing) {$window.Close()}
            elseif ($startPrepared) {& $startScan}
        }
        if (-not $state.Job) {return}
        $row=$null; $drained=0
        while ($drained -lt 100 -and $state.Control.Queue.TryDequeue([ref]$row)) {
            $row | Add-Member -NotePropertyName IpSort -NotePropertyValue (ConvertTo-DiscoveryIpNumber $row.IP) -Force
            $state.Items.Add($row); $drained++
        }
        $elapsed=((Get-Date)-$state.Started).TotalSeconds
        $done=[int]$state.Control.Completed; $total=[int]$state.Control.Total
        $eta='calculating…'
        if ($done -gt 0) {$eta=([timespan]::FromSeconds([math]::Max(0,$elapsed*($total-$done)/$done))).ToString('hh\:mm\:ss')}
        $ui.Progress.Value=100*$done/[math]::Max(1,$total)
        $ui.StatusText.Text='{0}/{1} hosts | detected {2} | elapsed {3} | estimated remaining {4}' -f $done,$total,$state.Control.Alive,([timespan]::FromSeconds($elapsed)).ToString('hh\:mm\:ss'),$eta
        if ($state.Job.Handle.IsCompleted) {
            try {$null=$state.Job.PowerShell.EndInvoke($state.Job.Handle)}
            catch {$state.Control.Failure=$_.Exception.Message}
            finally {$state.Job.PowerShell.Dispose(); $state.Job=$null}
            $state.Snapshot=$state.Control.Result; $state.Items.Clear()
            if ($state.Snapshot) {
                foreach ($hostRow in $state.Snapshot.Hosts) {
                    $hostRow | Add-Member -NotePropertyName IpSort -NotePropertyValue (ConvertTo-DiscoveryIpNumber $hostRow.IP) -Force
                    $state.Items.Add($hostRow)
                }
            }
            $ui.ScanButton.IsEnabled=$true; $ui.StopButton.IsEnabled=$false; $ui.ExportButton.IsEnabled=($null -ne $state.Snapshot)
            if ($state.Control.Failure) {$ui.StatusText.Text='Error: '+$state.Control.Failure}
            elseif ($state.Control.Cancel) {$ui.StatusText.Text="Cancelled. Saved $($state.Items.Count) partial results."}
            elseif ($state.Snapshot -and -not $state.Snapshot.Metadata.Completed) {$ui.StatusText.Text+=' | Incomplete results: review errors and logs.'}
            else {$ui.StatusText.Text+=' | Reports saved.'}
            $view.Refresh()
            if ($state.Closing) {$window.Close()}
        }
    })
    $timer.Start()
    $ui.ThemeButton.Add_Click({$state.Dark=-not $state.Dark; & $applyTheme})
    $ui.ColumnsButton.Add_Click({
        $menu=New-Object Windows.Controls.ContextMenu
        foreach ($column in $ui.ResultsGrid.Columns) {
            $entry=New-Object Windows.Controls.MenuItem
            $entry.Header=$column.Header; $entry.IsCheckable=$true; $entry.IsChecked=($column.Visibility -eq 'Visible'); $entry.Tag=$column
            $entry.Add_Click({param($eventSource,$routedEvent) $null=$eventSource; $null=$routedEvent
                if ($eventSource.IsChecked) {$eventSource.Tag.Visibility='Visible'} else {$eventSource.Tag.Visibility='Collapsed'}
            })
            $null=$menu.Items.Add($entry)
        }
        $menu.PlacementTarget=$ui.ColumnsButton; $menu.IsOpen=$true
    })
    $ui.AboutButton.Add_Click({
        [Windows.MessageBox]::Show($window,('HostName Discovery '+$script:Version+' | '+$script:BuildDate+[Environment]::NewLine+'Native Windows network inventory. Use only on authorized networks.'),'About','OK','Information') | Out-Null
    })
    $actions=@{CopyIp='IP';CopyMac='MAC';CopyName='Hostname'}
    foreach ($key in $actions.Keys) {
        $ui[$key].Tag=$actions[$key]
        $ui[$key].Add_Click({param($eventSource,$routedEvent) $null=$eventSource; $null=$routedEvent
            $selected=$ui.ResultsGrid.SelectedItem
            if ($selected -and $selected.($eventSource.Tag)) {[Windows.Clipboard]::SetText([string]$selected.($eventSource.Tag))}
        })
    }
    foreach ($key in @('PingAction','TraceAction','BrowserAction','RdpAction','SshAction','WakeAction')) {
        $ui[$key].Tag=$key
        $ui[$key].Add_Click({param($eventSource,$routedEvent) $null=$eventSource; $null=$routedEvent
            $selected=$ui.ResultsGrid.SelectedItem; if (-not $selected) {return}
            try {
                $ip=$selected.IP; $null=ConvertTo-DiscoveryIpNumber $ip
                switch ($eventSource.Tag) {
                    'PingAction' {Start-Process powershell.exe -ArgumentList @('-NoProfile','-NoExit','-Command',"ping.exe -n 4 $ip") -ErrorAction Stop}
                    'TraceAction' {Start-Process powershell.exe -ArgumentList @('-NoProfile','-NoExit','-Command',"tracert.exe -d $ip") -ErrorAction Stop}
                    'BrowserAction' {
                        $webService=$selected.Services | Where-Object Name -in @('https','http') | Select-Object -First 1
                        if ($webService) {Start-Process ('{0}://{1}:{2}/' -f $webService.Name,$ip,$webService.Port)}
                        elseif (@($selected.Ports | Where-Object {$_.Port -eq 443 -and $_.State -eq 'open'}).Count) {Start-Process "https://$ip/"}
                        else {Start-Process "http://$ip/"}
                    }
                    'RdpAction' {Start-Process mstsc.exe -ArgumentList "/v:$ip" -ErrorAction Stop}
                    'SshAction' {Start-Process ssh.exe -ArgumentList $ip -ErrorAction Stop}
                    'WakeAction' {
                        if (-not $selected.MAC) {throw 'MAC address unavailable for Wake-on-LAN.'}
                        if ([Windows.MessageBox]::Show($window,"Send Wake-on-LAN to $($selected.MAC)?",'Wake-on-LAN','YesNo','Question') -eq 'Yes') {Send-DiscoveryWakePacket -Mac $selected.MAC}
                    }
                }
            } catch {$ui.StatusText.Text=$_.Exception.Message}
        })
    }
    $window.Add_PreviewKeyDown({param($eventSource,$routedEvent) $null=$eventSource; $null=$routedEvent
        $ctrl=([Windows.Input.Keyboard]::Modifiers -band [Windows.Input.ModifierKeys]::Control) -ne 0
        if ($routedEvent.Key -eq 'F5') {& $startScan; $routedEvent.Handled=$true}
        elseif ($routedEvent.Key -eq 'Escape') {& $stopScan; $routedEvent.Handled=$true}
        elseif ($ctrl -and $routedEvent.Key -eq 'F') {$null=$ui.SearchBox.Focus(); $routedEvent.Handled=$true}
        elseif ($ctrl -and $routedEvent.Key -eq 'E') {& $export; $routedEvent.Handled=$true}
    })
    $window.Add_Closing({param($eventSource,$routedEvent) $null=$eventSource; $null=$routedEvent
        if ($state.AuxJob) {$state.Closing=$true; $routedEvent.Cancel=$true; $ui.StatusText.Text='Waiting for background tasks to finish…'; return}
        if ($state.Job) {$state.Closing=$true; & $stopScan; $routedEvent.Cancel=$true; return}
        $timer.Stop()
        if (-not $SmokeTest) {
            try {
                $null=New-Item -ItemType Directory -Path $settingsFolder -Force -ErrorAction Stop
                $save=[pscustomobject]@{Target=$ui.TargetBox.Text;Profile=[string]$ui.ProfileBox.SelectedItem.Content;Dark=$state.Dark
                    Columns=@($ui.ResultsGrid.Columns | ForEach-Object {[pscustomobject]@{Header=$_.Header;Width=$_.ActualWidth;Index=$_.DisplayIndex;Visibility=[string]$_.Visibility}})}
                $save | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $settingsFile -Encoding UTF8 -ErrorAction Stop
            } catch {Write-Warning "Settings could not be saved: $($_.Exception.Message)"}
        }
    })
    if ($SmokeScan -or $SmokeDark) {$SmokeTest=$true}
    if ($SmokeTest) {
        $ui.TargetBox.Text='192.0.2.0/24'
        $ui.OutputBox.Text='Select a report folder'
        $ui.AdvancedOptions.IsExpanded=$true
        $window.ShowInTaskbar=$false; $window.Opacity=0; $window.WindowState='Normal'
        $smokeStart=Get-Date
        $smokeState=@{Started=$false;Ticks=0}
        $smokeTimer=New-Object Windows.Threading.DispatcherTimer; $smokeTimer.Interval=[timespan]::FromMilliseconds(100)
        $smokeTimer.Add_Tick({
            $smokeState.Ticks++
            if ($SmokeDark -and $smokeState.Ticks -eq 2) {$state.Dark=$true; & $applyTheme}
            if ($SmokeScan -and -not $smokeState.Started) {
                $smokeState.Started=$true
                $ui.TargetBox.Text='127.0.0.1'; $ui.DnsBox.Text='127.0.0.1'; $ui.TimeoutBox.Text='100'
                $ui.SkipUdpBox.IsChecked=$true; $ui.ProfileBox.SelectedIndex=0
                $ui.OutputBox.Text=Join-Path ([IO.Path]::GetTempPath()) ('HostNameDiscovery-tests\'+$PID)
                & $startScan
            }
            $finished=((-not $SmokeScan) -and (-not $SmokeDark)) -or ($state.Snapshot -and -not $state.Job) -or ($SmokeDark -and $smokeState.Ticks -ge 5)
            if (((Get-Date)-$smokeStart).TotalSeconds -gt 45) {
                if ($state.Control) {$state.Control.Cancel=$true}
                $finished=$true
            }
            if ($finished) {
                $smokeTimer.Stop()
                if ($captureDestination) {
                    $rootVisual=$window.Content
                    $rootVisual.Margin=[Windows.Thickness]::new(0)
                    $rootVisual.Measure([Windows.Size]::new(1250,800)); $rootVisual.Arrange([Windows.Rect]::new(0,0,1250,800)); $rootVisual.UpdateLayout()
                    $bitmap=[Windows.Media.Imaging.RenderTargetBitmap]::new(1250,800,96,96,[Windows.Media.PixelFormats]::Pbgra32)
                    $bitmap.Render($rootVisual)
                    $encoder=[Windows.Media.Imaging.PngBitmapEncoder]::new()
                    $encoder.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
                    $file=[IO.File]::Create($captureDestination)
                    try {$encoder.Save($file)} finally {$file.Dispose()}
                }
                $window.Close()
            }
        }); $smokeTimer.Start()
    }
    $null=$window.ShowDialog()
    if ($SmokeScan) {
        if (-not $state.Snapshot -or -not $state.Snapshot.Metadata.Completed) {throw "GUI scan failed: $($ui.StatusText.Text)"}
        if ($state.Items.Count -ne 1 -or -not $state.Items[0].Alive) {throw 'GUI: missing results.'}
        $ui.SearchBox.Text='no-results-expected'
        if (-not $view.IsEmpty) {throw 'GUI: search filter not applied.'}
        $ui.SearchBox.Text=''
        if ($view.IsEmpty) {throw 'GUI: filter reset failed.'}
        "GUI scan: loopback completed, search filter verified, $($smokeState.Ticks) Dispatcher ticks."
    }
    if ($SmokeTest) {'GUI smoke test: XAML, bindings, events and Dispatcher initialized.'}
}
if ($MyInvocation.InvocationName -eq '.') {return}
if ($SelfTest) {
    if (-not $SelfTestReport) {throw 'SelfTestReport is required for self-tests.'}
    try {
        $messages=@(Show-DiscoveryGui -SmokeTest -SmokeScan:($SelfTest -eq 'Scan') -SmokeDark:($SelfTest -eq 'Dark') -CapturePath $CapturePath)
        @{Passed=$true;Version=$script:Version;Messages=$messages} | ConvertTo-Json | Set-Content -LiteralPath $SelfTestReport -Encoding UTF8
    } catch {
        @{Passed=$false;Error=$_.Exception.Message;Stack=$_.ScriptStackTrace} | ConvertTo-Json | Set-Content -LiteralPath $SelfTestReport -Encoding UTF8
        exit 1
    }
    return
}
if ($ShowVersion) {[pscustomobject]@{Version=$script:Version;BuildDate=$script:BuildDate}; return}
if ($Gui -or ($PSBoundParameters.Count -eq 0 -and -not $Cli)) {
    if ($WhatIfPreference) {Write-Output 'WhatIf: open GUI'; return}
    Show-DiscoveryGui
    return
}
$inputTargets=@($Target | Where-Object {$_})
if ($Subnet) {$inputTargets+=$Subnet}
if (-not $inputTargets.Count -and -not $TargetFile) {
    $inputTargets=@(Get-DiscoverySubnet)
    foreach ($detected in $inputTargets) {if ([int]($detected.Split('/')[1]) -lt 22 -and -not $Force) {throw "Large automatic subnet ($detected): specify -Target or -Force."}}
}
$addresses=@(Get-DiscoveryTarget -InputTarget $inputTargets -File $TargetFile)
if (-not $PSCmdlet.ShouldProcess(($inputTargets -join ', '),"$ScanProfile scan of $($addresses.Count) authorized addresses")) {return}
if (-not $Force -and ($addresses.Count -gt 1024 -or $ScanProfile -eq 'Deep')) {
    if (-not $PSCmdlet.ShouldContinue("Targets: $($addresses.Count). Deep sends application requests; check device compatibility. Continue?",'Network scan')) {return}
}
if ($ScanProfile -eq 'Deep') {Write-Warning 'Deep: application probes and, if configured, authenticated CIM inventory.'}
$arguments=@{
    Addresses=$addresses;OutputDirectory=$OutDir;XmlPath=$OutFile;BaselinePath=$Baseline
    Options=@{ScanProfile=$ScanProfile;PortSpecification=$Ports;PortCount=$TopPorts;Timeout=$TimeoutMs;Retries=$Retry;Samples=$PingCount
        Throttle=$ThrottleLimit;Rate=$RateLimit;Servers=$DnsServer;NoUdp=[bool]$SkipUdp;Account=$Credential;OuiPath=$OuiFile}
}
$control=Get-DiscoveryControl
$background=Invoke-DiscoveryBackground $arguments $control
try {
    while (-not $background.Handle.IsCompleted) {
        $percentage=0
        if ($control.Total) {$percentage=100*$control.Completed/$control.Total}
        Write-Progress -Activity 'Network inventory' -Status "$($control.Completed)/$($control.Total), detected $($control.Alive)" -PercentComplete $percentage
        Start-Sleep -Milliseconds 150
    }
    $null=$background.PowerShell.EndInvoke($background.Handle)
    if ($control.Failure) {throw $control.Failure}
    $control.Result.Hosts
} finally {
    $control.Cancel=$true
    $null=$background.Handle.AsyncWaitHandle.WaitOne()
    $background.PowerShell.Dispose()
    Write-Progress -Activity 'Network inventory' -Completed
}

