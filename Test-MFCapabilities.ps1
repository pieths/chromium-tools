# Copyright (c) 2026 Piet Hein Schouten
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
  Reports the Media Foundation / PlayReady capabilities
  for every display attached to this PC.

.DESCRIPTION
  Read-only. For each display it creates a hidden window over that display and
  queries Windows Media Foundation using IMFExtendedDRMTypeSupport::IsTypeSupportedEx().
  It also prints the Windows settings which determine HDR availability.

  Run:  powershell -ExecutionPolicy Bypass -File .\Test-MFCapabilities.ps1
  Save: powershell -ExecutionPolicy Bypass -File .\Test-MFCapabilities.ps1 > report.txt

.PARAMETER ShowQueries
  Also print the content type string passed to IsTypeSupportedEx() for each feature.
#>
#Requires -Version 5.1
param(
  [switch]$ShowQueryStrings
)

$KeySystems = @(
  'com.microsoft.playready.recommendation.3000'
  'com.microsoft.playready.recommendation'
  'com.microsoft.playready.hardware'
)

function Get-ContentTypeString($Codecs, $Features) {
  'video/mp4;codecs="{0}";features="{1}"' -f $Codecs, ($Features -join ',')
}

$CrDecode    = 'decode-bpp=8,decode-res-x=1920,decode-res-y=1080,decode-bitrate=10000000,decode-fps=30'
$CrClearLead = 'encryption-iv-size=8,encryption-type=cenc-clearlead'
$CrCbcs      = 'encryption-iv-size=16,encryption-type=cbcs'

$Queries = [ordered]@{
  'Group1 HEVC Main10 decode' = 'video/mp4;codecs="hvc1,mp4a";features="decode-res-x=1920,decode-res-y=1080,decode-bpc=10,decode-bitrate=5800,decode-fps=30"'
  'Group1 HEVC HDR10'         = 'video/mp4;codecs="hvc1,mp4a";features="decode-res-x=1920,decode-res-y=1080,decode-bpc=10,decode-bitrate=5800,decode-fps=30,display-res-x=1920,display-res-y=1080,display-bpc=8,hdr=1"'
  'Group1 HEVC Dolby Vision'  = 'video/mp4;codecs="hvc1,mp4a";features="decode-res-x=1920,decode-res-y=1080,decode-bpc=10,decode-bitrate=5800,decode-fps=30,display-res-x=1920,display-res-y=1080,display-bpc=8,hdr=1,ext-profile=dvhe.05"'
  'Group1 HEVC 4K'            = 'video/mp4;codecs="hvc1,mp4a";features="decode-res-x=3840,decode-res-y=2160,decode-bpc=10,decode-bitrate=16000,decode-fps=30,display-res-x=2560,display-res-y=1440,display-bpc=8"'
  'Group1 HDCP 2.2'           = 'video/mp4;codecs="hvc1,mp4a";features="hdcp=2"'

  'Group2 H.264'            = Get-ContentTypeString 'avc1' $CrDecode, $CrClearLead
  'Group2 HEVC'             = Get-ContentTypeString 'hvc1' $CrDecode, $CrClearLead
  'Group2 VP9'              = Get-ContentTypeString 'vp09' $CrDecode, $CrClearLead
  'Group2 AV1'              = Get-ContentTypeString 'av01' $CrDecode, $CrClearLead
  'Group2 Dolby Vision'     = Get-ContentTypeString 'hvc1' 'ext-profile=dvhe.05', $CrDecode, $CrClearLead
  'Group2 Dolby Vision HDR' = Get-ContentTypeString 'hvc1' 'ext-profile=dvhe.05', $CrDecode, $CrClearLead, 'hdr=1'
  'Group2 AAC audio'        = Get-ContentTypeString 'avc1,mp4a' $CrDecode, $CrClearLead
  'Group2 EAC-3 audio'      = Get-ContentTypeString 'avc1,ec-3' $CrDecode, $CrClearLead
  'Group2 AC-3 audio'       = Get-ContentTypeString 'avc1,ac-3' $CrDecode, $CrClearLead
  'Group2 AC-4 audio'       = Get-ContentTypeString 'avc1,ac-4' $CrDecode, $CrClearLead
  'Group2 MPEG-H audio'     = Get-ContentTypeString 'avc1,mhm1' $CrDecode, $CrClearLead
  'Group2 H.264 CBCS'       = Get-ContentTypeString 'avc1' $CrDecode, $CrCbcs

  'Group3 AV1 CBCS'         = Get-ContentTypeString 'av01' $CrDecode, $CrCbcs
}

if (-not ('MfCapabilitiesProbe' -as [type])) {
  Add-Type -Path (Join-Path $PSScriptRoot 'Test-MFCapabilities.cs')
}

function Get-RegValue($Path, $Name) {
  $v = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
  if ($v) { $v.$Name } else { '(not set)' }
}

# Lists every value under a key (except the unnamed default)
function Get-RegValues($Path) {
  $key = Get-Item -Path $Path -ErrorAction SilentlyContinue
  if (-not $key) { return '(key missing)' }
  $names = $key.Property | Where-Object { $_ -ne '(default)' }
  if (-not $names) { return '(no values)' }
  ($names | ForEach-Object { "$_=$($key.GetValue($_))" }) -join '; '
}

function Write-Section($Title) {
  "`n=== $Title ==="
}

# Formats objects as a table (or list) without the blank lines PowerShell adds.
function Out-Report([switch]$List) {
  $formatted = if ($List) { $input | Format-List } else { $input | Format-Table -AutoSize }
  ($formatted | Out-String -Width 200).Trim()
}

# SHA-256 of this script with line endings normalized to LF, so git/copies don't change it.
function Get-ScriptHash {
  if (-not $PSCommandPath) { return '(unknown - not run from a file)' }
  $text = (Get-Content -LiteralPath $PSCommandPath -Raw -Encoding UTF8) -replace "`r`n", "`n"
  $hash = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($text))
  -join ($hash | ForEach-Object { $_.ToString('x2') })
}

# --- System -----------------------------------------------------------------
Write-Section 'System'
$os = Get-CimInstance Win32_OperatingSystem
$ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
Add-Type -AssemblyName System.Windows.Forms
[pscustomobject]@{
  Script      = Get-ScriptHash
  OS          = "$($os.Caption) (build $($os.BuildNumber).$ubr)"
  PowerSource = [System.Windows.Forms.SystemInformation]::PowerStatus.PowerLineStatus
} | Out-Report -List

Write-Section 'GPUs'
Get-CimInstance Win32_VideoController | Select-Object Name, DriverVersion, DriverDate | Out-Report

Write-Section 'Codec packages'
'Microsoft.HEVCVideoExtension*', 'Microsoft.AV1VideoExtension' |
  ForEach-Object { Get-AppxPackage -Name $_ } | Select-Object Name, Version | Out-Report

Write-Section 'Windows HDR playback settings'
[pscustomobject]@{
  '(HKCU VideoSettings\EnableHDRForPlayback)' =
    Get-RegValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\VideoSettings' 'EnableHDRForPlayback'
  'Video processor settings (HKLM ...\Platform\XVP)' =
    Get-RegValues 'HKLM:\Software\Microsoft\Windows Media Foundation\Platform\XVP'
  'DWM HDR override (HKLM ...\DWM\HighColor)' =
    Get-RegValue 'HKLM:\Software\Microsoft\Windows\DWM' 'HighColor'
} | Out-Report -List

# --- Displays ---------------------------------------------------------------
$displays = [MfCapabilitiesProbe]::GetDisplays()
Write-Section "Displays ($($displays.Count))"
$displays | Select-Object Display, Adapter, VendorId,
  @{ n = 'Bounds (physical px)'; e = { "$($_.X),$($_.Y) $($_.Width)x$($_.Height)" } },
  @{ n = 'Scale'; e = { '{0}%' -f [math]::Round($_.Dpi * 100 / 96) } },
  BitsPerColor,
  @{ n = 'ColorSpace'; e = { switch ($_.ColorSpace) { 0 { 'SDR (sRGB)' } 12 { 'HDR (PQ/BT.2020)' } default { $_ } } } },
  @{ n = 'MaxNits'; e = { [int]$_.MaxLuminance } } | Out-Report

# --- Media Foundation queries -----------------------------------------------
# $null = no window (shown for comparison)
foreach ($display in @($displays) + $null) {
  if ($display) { Write-Section "IsTypeSupportedEx on $($display.Display) ($($display.Adapter))" }
  else          { Write-Section 'IsTypeSupportedEx with no window' }

  $rows = foreach ($feature in $Queries.Keys) {
    $row = [ordered]@{ Feature = $feature }
    foreach ($keySystem in $KeySystems) {
      $row[$keySystem] = [MfCapabilitiesProbe]::Query($display, $keySystem, $Queries[$feature])
    }
    [pscustomobject]$row
  }
  $rows | Out-Report
}

if ($ShowQueryStrings) {
  Write-Section 'Query strings'
  # Plain lines rather than a table so long strings aren't truncated.
  $width = ($Queries.Keys | Measure-Object -Property Length -Maximum).Maximum
  foreach ($feature in $Queries.Keys) {
    "{0}  {1}" -f $feature.PadRight($width), $Queries[$feature]
  }
}
