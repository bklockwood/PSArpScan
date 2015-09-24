
Param (
  [Parameter(Position=0)][string]$Subnet,
  [Parameter(Position=1)][string]$NmapLocation = "C:\Users\Bryan\SkyDrive\Filer\Tools\nmap-6.49BETA4\nmap.exe"
)

function New-Arpscan {
<#
.Synopsis
Scan each IP in subnet for ARP responses, using nmap
.DESCRIPTION
TBD
.PARAMETER Subnet
A subnet specified in CIDR notation, eg 10.0.0.0/24
.PARAMETER OutputFile
Location of the nmap executable
.EXAMPLE
TBD
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, Position=0)]$Subnet,
        [Parameter(Mandatory=$true, Position=1)]$NmapLocation
    )

    Begin {
        if (!(test-path $nmaplocation)) {
            Write-Warning "nmap not found at $NmapLocation, please rectify."
            break
        }
        Write-Host "Performing nmap ARP scan of $Subnet ... " -NoNewline
    }
    Process {
        $ErrorActionPreference = "SilentlyContinue"
        [xml]$output = (& $Nmaplocation -sn $subnet -oX -)        
        $ErrorActionPreference = "Continue"
        $output
    }
    End { 
        Write-Host " Done!"
        Write-Host ""
    }

}

function Parse-NmapXML {
<#
.Synopsis
Parse result of an "nmap -sn" subnet scan.
.DESCRIPTION
TBD
.PARAMETER NmapXML
XML output of an nmap scan, such as: nmap.exe -sn 10.0.0.1/24 -oX -
.EXAMPLE
TBD
#>

    [CmdletBinding()]
    Param ( [Parameter(Mandatory=$true, Position=0)]$NmapXML )
 
    Begin {
        if (!$NmapXML.nmaprun.host) {
            Write-Warning "oops"
            #break
        }
    }

    Process {        
        foreach ($item in $NmapXML.nmaprun.host) {
            if (!$item.hostnames.hostname.name) {
                $name = $false
            } else {
                $name = $item.hostnames.hostname.name
            }
            foreach ($address in $item.address) {
                if ($address.addrtype -eq "mac") {
                    $MACAddress = $address.addr
                    $NicVendor = $address.vendor
                }
                if ($address.addrtype -eq "ipv4") {$ipv4Address = $address.addr}
            }
            Write-Host "$ipv4Address `t $MACAddress ($NicVendor)" -NoNewline
            if (!$name) {
                Write-Host -ForegroundColor Yellow " No DNS name found"
            } else {
                Write-Host " $name"
            }                
           
        }
    }
    End{}

}

$output = New-Arpscan -Subnet $Subnet -NmapLocation $NmapLocation
Parse-NmapXML -NmapXML $output
