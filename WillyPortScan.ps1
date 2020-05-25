class IPv4Subnet {
    [uint64]$ipInt
    [uint64]$prefixLen
    [uint64]$broadcast
    [uint64]$span

    IPv4Subnet([String]$cidr) {

        $parts = $cidr.split("/")
        $ipString = $parts[0]
        $this.prefixLen = [int]$parts[1]
        $octets = $ipString.Split(".")

        $this.ipInt = 16777216 * [int]$octets[0] + 65536 * [int]$octets[1] + 256 * [int]$octets[2] + [int]$octets[3]
        $this.span = [Math]::pow(2, 32-$this.prefixLen)
        $this.broadcast = $this.ipInt + $this.span - 1
        
    }

    [string[]]GetHostIPs() {
        $offset = 0
        $ip_0 = $this.ipInt + 1
        $max = $this.span - 1
        $ips = New-Object string[] $max

        while ($offset -lt $max) {
            $int = $ip_0 + $offset
            $ips[$offset] = $([IPAddress]$int).ToString()
            $offset++
        }

        return $ips
    }

    [string[]]GetIPs() {
        $offset = 0
        $ip_0 = $this.ipInt
        $max = $this.span
        $ips = New-Object string[] $max

        while ($offset -lt $max) {
            $int = $ip_0 + $offset
            $ips[$offset] = $([IPAddress]$int).ToString()
            $offset++
        }

        return $ips
    }
}


Class TestSocket {
    [string]$HostIp
    [uint32]$Port
    [System.Threading.Tasks.Task]$Task
    [Bool]$IsOpen = $False

    TestSocket([string] $HostIp, [uint32] $Port) {
        $this.HostIp = $HostIp
        $this.Port = $Port
    }

    [void] ConnectAsync() {
        $this.Task = (New-Object System.Net.Sockets.TcpClient).ConnectAsync($this.HostIp, $this.Port)
    }
}

Function WillyPortScan {
    Param(
        [String[]]$Hosts,
        [uint32[]]$Ports,
        [int]$MaxOpenSockets = 100
    )
    
    $Sockets = ForEach ($_host in $Hosts) {
        ForEach ($port in $Ports) {
            New-Object TestSocket($_host, $port)
        }
    }


    $progress = 0

    for ($i = 0; $i -lt $Sockets.Count; $i += $MaxOpenSockets) {
        Write-Progress -Activity "Port scan in progress" -Status "$progress% Complete:" -PercentComplete $progress;
        [TestSocket[]]$socketsChunk = @($Sockets[$i..($i + $MaxOpenSockets - 1)])

        $socketsChunk | % {$_.ConnectAsync()}
        Try {
            [void][Threading.Tasks.Task]::WaitAll($socketsChunk.Task)
        } Catch {}

        $socketsChunk | % {
            $_.IsOpen = !$_.Task.IsFaulted
            $_.Task.Dispose()
        }

        $progress = [Math]::Floor($i * 100 / $Sockets.Count)
    }

    $Sockets | Where-Object {$_.IsOpen -eq $True} |  Select-Object -Property HostIp, Port, IsOpen
}


$network = [IPv4Subnet]::new("192.168.0.0/24")


WillyPortScan -Hosts $network.GetHostIPs() -Ports $(1..99) -MaxOpenSockets 1024
