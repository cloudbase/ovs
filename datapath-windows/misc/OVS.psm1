<#
Copyright 2014, 2015 Cloudbase Solutions Srl

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
#>

$WMI_JOB_STATUS_STARTED = 4096
$WMI_JOB_STATE_RUNNING = 4
$WMI_JOB_STATE_COMPLETED = 7

$hvassembly = [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.HyperV.PowerShell")

function Set-VMNetworkAdapterOVSPort
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [Microsoft.HyperV.PowerShell.VMNetworkAdapter]$VMNetworkAdapter,

        [parameter(Mandatory=$true)]
        [ValidateLength(1, 48)]
        [string]$OVSPortName
    )
    process
    {
        $ns = "root\virtualization\v2"
        $EscapedId = $VMNetworkAdapter.Id.Replace('\', '\\')

        $sd = gwmi -namespace $ns -class Msvm_EthernetPortAllocationSettingData -Filter "ElementName = '$OVSPortName'"
        if($sd)
        {
            if($sd.InstanceId.Contains($VMNetworkAdapter.Id))
            {
                throw "The OVS port name '$OVSPortName' is already assigned to this port."
            }
            throw "Cannot assign the OVS port name '$OVSPortName' as it is already assigned to an other port."
        }

        $sd = gwmi -namespace $ns -class Msvm_EthernetPortAllocationSettingData -Filter "InstanceId like '$EscapedId%'"

        if($sd)
        {
            $sd.ElementName = $OVSPortName

            $vsms = gwmi -namespace $ns -class Msvm_VirtualSystemManagementService
            $retVal = $vsms.ModifyResourceSettings(@($sd.GetText(1)))
            try
            {
                CheckWMIReturnValue $retVal
            }
            catch
            {
                throw "Assigning OVS port '$OVSPortName' failed"
            }
        }
    }
}

function Get-VMNetworkAdapterByOVSPort
{
    [CmdletBinding()]
    param
    (

        [parameter(Mandatory=$true)]
        [ValidateLength(1, 48)]
        [string]$OVSPortName
    )
    process
    {
        $ns = "root\virtualization\v2"

        $sd = gwmi -namespace $ns -class Msvm_EthernetPortAllocationSettingData -Filter "ElementName = '$OVSPortName'"
        if($sd)
        {
            return $sd
        }
    }
}

function Get-VMByOVSPort
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true)]
        [ValidateLength(1, 48)]
        [string]$OVSPortName
    )
    process
    {
        $ns = "root\virtualization\v2"

        $vms = gwmi -namespace $ns -class Msvm_VirtualSystemSettingData
        ForEach($vm in $vms)
        {
            $ports = gwmi -Namespace $ns -Query "
                Associators of {$vm} Where
                ResultClass = Msvm_EthernetPortAllocationSettingData"
            if ($ports.ElementName -eq $OVSPortName)
            {
                return $vm
            }
        }
    }
}

#This function returns the Msvm_VirtualSystemSettingData given a VMName
function Get-VMNetworkAdapterWithOVSPort
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true)]
        [ValidateLength(1, 1024)]
        [string]$vmName
    )
    process
    {
        $ns = "root\virtualization\v2"
        $vm = {}
        $ports = {}

        $vm = gwmi -namespace $ns -class Msvm_VirtualSystemSettingData -Filter "ElementName = '$VMName'"

        $ports = gwmi -Namespace $ns -Query "
                 Associators of {$vm} Where
                 ResultClass = Msvm_EthernetPortAllocationSettingData"

        return $ports
    }
}

function CheckWMIReturnValue($retVal)
{
    if ($retVal.ReturnValue -ne 0)
    {
        if ($retVal.ReturnValue -eq $WMI_JOB_STATUS_STARTED)
        {
            do
            {
                $job = [wmi]$retVal.Job
            }
            while ($job.JobState -eq $WMI_JOB_STATE_RUNNING)

            if ($job.JobState -ne $WMI_JOB_STATE_COMPLETED)
            {
                echo $job.ReturnValue
                $errorString = "Job Failed. Job State: " + $job.JobState.ToString()
                if ($job.__CLASS -eq "Msvm_ConcreteJob")
                {
                    $errorString += " Error Code: " + $job.ErrorCode.ToString()
                    $errorString += " Error Details: " + $job.ErrorDescription
                }
                else
                {
                    $error = $job.GetError()
                    if ($error.Error)
                    {
                        $errorString += " Error:" + $error.Error
                    }
                }
                throw $errorString
            }
        }
        else
        {
            throw "Job Failed. Return Value: {0}" -f $job.ReturnValue
        }
    }
}

function Set-VMNetworkAdapterOVSPortDirect
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true)]
        [ValidateLength(1, 1024)]
        [string]$vmName,

        [parameter(Mandatory=$true)]
        [ValidateLength(1, 48)]
        [string]$OVSPortName
    )
    process
    {
        $vnic = 0

        if ($vmName)
        {
            $vnic = Get-VMNetworkAdapter -VMName $vmName
        }
        # XXX the vnic index should be provided by the caller
        $vnic[0] | Set-VMNetworkAdapterOVSPort -OVSPortName $OVSPortName
    }
}

function Get-OVSEnabledHNSNetworks
{
    return (Get-HNSNetwork) | Where-Object {($_.Extensions.Id -eq '583cc151-73ec-4a6a-8b47-578297ad7623') -and ($_.Extensions.IsEnabled -eq 'True')}
}

function Add-OVSHNSInternalPort
{
    param
    (
        [parameter(Mandatory=$true)] [string] $PortName
    )
    $test = [array](Get-NetAdapter -IncludeHidden -InterfaceAlias "$PortName" -ErrorAction SilentlyContinue)
    if (!($test -eq $null))
    {
        return
    }
    $test = [array]((Get-HnsEndpoint) | Where-Object {($_.Name -eq "$PortName")})
    if (!($test -eq $null))
    {
        return
    }
    $a = [array](Get-OVSEnabledHNSNetworks).Id
    if ($a.count -eq 0)
    {
        $a = [array]$env:OVS_ENABLED_NETWORK_ID
        if ($a.count -eq 0)
        {
            $a = [array](Get-HNSNetwork | where {$_.type -eq "transparent"}).ID
            if ($a.count -eq 0)
            {
                return
            }
        }
    }
    $temp = New-HnsEndpoint -NetworkId $a[0] -Name "$PortName"
    Attach-HnsHostEndpoint $temp.Id 1
    Rename-NetAdapter -IncludeHidden -InterfaceAlias "vEthernet ($PortName)" -NewName "$PortName" -ErrorAction SilentlyContinue
    Remove-NetRoute -InterfaceAlias "$PortName" -Confirm:$false -ErrorAction SilentlyContinue
    #Set-DnsClientServerAddress -InterfaceAlias "$PortName" -ResetServerAddresse  -ErrorAction SilentlyContinue
    #Remove-NetIPAddress -Confirm:$false -InterfaceAlias "$PortName" -ErrorAction SilentlyContinue
    #Set-NetIPInterface -Confirm:$false -InterfaceAlias "$PortName"  -Dhcp Enabled  -ErrorAction SilentlyContinue
    Disable-NetAdapter -Confirm:$false -IncludeHidden -InterfaceAlias "$PortName" -ErrorAction SilentlyContinue
}

function Delete-OVSHNSInternalPort
{
    param
    (
        [parameter(Mandatory=$true)] [string] $PortName
    )
    $a = [array]((Get-HnsEndpoint) | Where-Object {($_.Name -eq "$PortName")})
    $request = @{
        SystemType  = "Host";
    };

    return Invoke-HNSRequest -Method DELETE -Type endpoints -Data (ConvertTo-Json $request ) -Id $a[0].ID
}

function Enable-OVSOnHNSNetwork
{
    param
    (
        [parameter(Mandatory=$true)] [string] $NetworkId
    )
    return Set-HnsSwitchExtension -NetworkId $NetworkId -ExtensionId 583cc151-73ec-4a6a-8b47-578297ad7623 -state $True
}

function Disable-OVSOnHNSNetwork
{
    param
    (
        [parameter(Mandatory=$true)] [string] $NetworkId
    )
    return Set-HnsSwitchExtension -NetworkId $NetworkId -ExtensionId 583cc151-73ec-4a6a-8b47-578297ad7623 -state $False
}

Export-ModuleMember -function Set-*, Get-*, Enable-*, Disable-*, Add-*, Delete-*
