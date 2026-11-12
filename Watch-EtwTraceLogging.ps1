<#
.SYNOPSIS
  Live-prints ETW TraceLogging events from any TraceLogging provider, filtered with a regex.

.DESCRIPTION
  Starts a real-time ETW session on the specified provider GUID(s), decodes the
  TraceLogging events they emit, filters them with a regex and writes the matches to
  the output stream as they arrive, one string per event. With nothing downstream the
  host prints them. They can also be piped or redirected (see the examples). No files
  are written and nothing needs to be closed.

  Only TraceLogging events are shown. Events from providers that use other kinds of ETW
  events are skipped without any message. A field whose type the script cannot decode
  (arrays, structs, binary data, SIDs, SYSTEMTIME) is shown as <undecoded>, and the
  remaining fields of that event are left out.

  Each provider's GUID and keyword mask are required. For Chromium's ETW export
  they are defined in the Chromium source:

    provider GUID  components/tracing/common/etw_export_win.cc (kChromeETWGUID)
    keyword bits   base/trace_event/etw_interceptor_win.cc (kFilteredEventGroupNames,
                   one bit per trace category)

  The ETW consumer is the C# file Watch-EtwTraceLogging.cs next to this script; it
  is compiled on each run with Add-Type, so keep the two files together.

  Start this first, then exercise the app. ETW only delivers events while a session
  is listening, so there is no history. ETW delivers events with a delay (up to about
  3 seconds in tests with a busy provider), so a line appears some time after the time it
  shows.

  Fields named Phase/Id/Timestamp/Duration follow Chromium's ETW export
  (base/trace_event/etw_interceptor_win.cc). Phase is Begin, End or Instant, and a scoped
  trace event is a Begin/End pair. Id is the uuid of the trace track the event was written
  on, so many events share the same Id. Timestamp is the time the event happened, in
  microseconds on Chromium's trace clock. The time shown at the start of each line is when
  the event was written to ETW, which is usually within about a millisecond of that but
  sometimes much later. Only End events carry Duration, in microseconds. The
  script treats all of these as ordinary fields. Every decoded field is shown
  unless -HideFields lists it, and events are selected only with -Pattern and
  -ExcludePattern. End events can be nearly half of all events, so
  -ExcludePattern ' Phase=End( |$)' roughly halves the output (and drops
  Duration, which only End events have).

  Output line format

    Each event is written as a time of day, two spaces and then the event text. The time
    is not part of the text that -Pattern and -ExcludePattern are matched against. Apart
    from that the matched text is the same, except that it also contains any fields hidden
    with -HideFields, which are left out of the printed line:

      HH:mm:ss.fff  <process>[<pid>]  <provider>  <event name> name=value name=value

      15:10:35.183  chrome:renderer[12345]  d2d578d9  Scroll Delta This Frame Phase=Instant Timestamp=86515199381 Id=3190708990060044014 x=0 y=0
      15:10:35.190  chrome:utility/NetworkService[4412]  d2d578d9  SequenceManager::DoIdleWork Phase=Begin Id=3190708991934093816 Timestamp=86515195051
      15:10:35.190  chrome:utility/NetworkService[4412]  d2d578d9  SequenceManager::DoIdleWork Phase=End Id=3190708991934093816 Timestamp=86515195081 Duration=29

    time      The time stamp in the ETW event header, shown as local time to the millisecond
              when the provider wrote the event to ETW. It is not when the line is printed,
              which is later (see above). ProcessTrace tries to deliver events oldest to
              newest, so the times shown normally do not go backwards, but its documentation
              says the order can be unpredictable in some cases, for example for events with
              the same time stamp on different CPUs:
              https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace
              A provider may write an event after it happened. For Chromium's export, the
              Timestamp field is when it happened.
    process   Process name without ".exe", then the decimal PID in brackets. For Chromium
              child processes the command line adds ":<type>" from --type= (renderer,
              gpu-process, utility, ...) and, for utility processes, "/<subtype>" from
              --utility-sub-type= (its last dotted segment: network.mojom.NetworkService is
              shown as NetworkService). The switches are defined in Chromium's
              content/public/common/content_switches.cc (kProcessType, kUtilitySubType). The
              browser process has no --type, so it has no suffix. The command line is read
              once per PID, when it is first seen. "?" is shown if the process cannot be read.
    provider  First 8 hex digits of the provider GUID, in lower case.
    fields    Each field as " name=value" after the event name, in the order the provider
              wrote them (Chromium writes Phase, Id, Timestamp, but Phase, Timestamp, Id on
              events that have debug annotations, as in the first example). Strings are
              shown as they are, integers in decimal, hex-typed fields as 0x..., booleans
              as true/false and FILETIME fields as a UTC date and time such as
              2026-11-12T18:25:48.8321234Z (a value outside the range of dates is shown as
              the number). A provider can also attach a formatting hint to a field, and these
              are followed when they fit the field's type: unsigned integers marked hex are
              shown as 0x..., a port number (16 bits, stored big-endian) as a number, an IPv4
              address (32 bits) as 192.168.1.200, and HRESULT, NTSTATUS and Win32 error
              codes as 0x.... Any other hint is ignored. Fields listed in -HideFields are
              left out of the printed line, but -Pattern and -ExcludePattern still see
              them. An End event normally has the name of its Begin event but is
              occasionally empty.

  Run from powershell.exe or Windows Terminal (64-bit). Needs permission to start ETW
  sessions: elevated or a member of "Performance Log Users".

.PARAMETER Provider
  One or more providers to listen to, each written as 'GUID:keywords' or
  'GUID:keywords:level'. Required. Every provider has its own keywords and level
  because each provider defines what its keyword bits mean.

    GUID      ETW provider GUID, e.g. D2D578D9-2936-45B6-A09F-30E32715F42D.
    keywords  ETW "match any" keyword mask: hex, 0x prefix required. Join several
              values with '|' to OR them together (0x1|0x8 is the same as 0x9).
              The provider writes an event when its keyword shares a bit with the
              mask, or when the event has no keyword bits at all.
    level     ETW level 0-5, optional (default 5 = verbose). Chromium's current ETW
              export ignores the level (it writes every event at level 0), so only
              the keywords matter there.

  Keywords and level are the MatchAnyKeyword and Level arguments of EnableTraceEx2, which
  defines how they select events:
  https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2

  Always quote the value: an unquoted '|' is the PowerShell pipeline operator.
  List each provider only once.

.PARAMETER Pattern
  One or more regexes (case-insensitive, matched anywhere in the text). An event
  is shown when its text matches at least one of them (OR). The text is
  "<process>[<pid>]  <provider>  <event name> <fields>", exactly as described under
  "Output line format" in the description, and it includes fields hidden by -HideFields.
  The time is not part of the text, so '^chrome' matches by process name. Default '.'
  shows every event the keywords let through. To require several conditions at once (AND),
  use one regex with lookaheads, such as '^(?=.*Frame)(?=.*:renderer\[)', or pipe the
  output to Select-String. Examples:
    '^chrome:renderer\['         renderer processes of chrome.exe
    ':utility/NetworkService\['  the network service process
    '^chrome\['                  the browser process only (it has no :type suffix)
    'Frame.* Phase=Begin'        Begin events whose name contains "Frame"
    'd2d578d9'                   events of one provider when several are enabled
    'x=0 y=0'                    a field value

.PARAMETER ExcludePattern
  One or more regexes with the same rules as -Pattern, matched against the same text.
  An event whose text matches any of them is dropped, even if it matches -Pattern.
  Default: none. Examples:
    ' Phase=End( |$)'                End events of Chromium's export, about half of all
                                     events (the "( |$)" keeps "Phase=Ending" from matching)
    '  d2d578d9  .* Phase=End( |$)'  the same, for one provider only

.PARAMETER HideFields
  Names of fields to leave out of the printed line, e.g. Id,Timestamp. By default every
  decoded field is shown. Names are matched exactly but ignoring case. A name on its own
  applies to every provider. 'provider:name' applies to one provider only, where provider
  is the 8 hex digits shown on each line (or the full GUID) of a provider listed in
  -Provider, e.g. 'd2d578d9:Id'.

  Hiding only changes what is printed. -Pattern and -ExcludePattern still see every field,
  so -HideFields Phase -ExcludePattern ' Phase=End( |$)' hides the field and still drops
  the End events. A field the script cannot decode is shown as <undecoded> even if it is
  listed, because the fields after it are left out of the event anyway.

.PARAMETER DurationSeconds
  Stop automatically after this many seconds. Default 0 = run until Ctrl+C.

.PARAMETER SessionName
  Name of the ETW session (default EtwWatch). An existing session with this name is
  replaced, so only one watcher per name can run at a time.

.EXAMPLE
  # Chromium's own ETW export registers the "Google.Chrome" provider (kChromeETWGUID in
  # components/tracing/common/etw_export_win.cc), and each process of an application that
  # uses it exports its events through it.  Add -Pattern to pick a process,
  # e.g. -Pattern '^chrome'. An application built on Chromium may register a
  # different provider; pass its GUID instead.  The following enables the "media"
  # category (0x20000) for all Chromium processes and drops the End events, which can be
  # nearly half of the output (only they carry Duration):
  .\Watch-EtwTraceLogging.ps1 -Provider 'D2D578D9-2936-45B6-A09F-30E32715F42D:0x20000' -ExcludePattern ' Phase=End( |$)'

.EXAMPLE
  # "benchmark" (0x1) + "cc" (0x8) categories, written as one mask (0x9) or as OR'd values,
  # only chrome.exe events whose text matches the regex.
  .\Watch-EtwTraceLogging.ps1 -Provider 'D2D578D9-2936-45B6-A09F-30E32715F42D:0x1|0x8' -Pattern '^chrome.*(Frame|Draw)'

.EXAMPLE
  # Two providers with different keywords and levels (the second GUID is a placeholder),
  # stop after 60 seconds.
  .\Watch-EtwTraceLogging.ps1 -Provider 'D2D578D9-2936-45B6-A09F-30E32715F42D:0x9:4', '11111111-2222-3333-4444-555555555555:0x2000' -DurationSeconds 60

.EXAMPLE
  # Shorter lines: leave out the Id and Timestamp fields that Chromium adds to every event.
  .\Watch-EtwTraceLogging.ps1 -Provider 'D2D578D9-2936-45B6-A09F-30E32715F42D:0x20000' -HideFields Id,Timestamp

.EXAMPLE
  # With two providers, hide fields for one of them only (use the 8 digits shown on each
  # line). Phase is hidden too, yet End events of that provider are still dropped, because
  # -ExcludePattern sees hidden fields. The second GUID is a placeholder.
  .\Watch-EtwTraceLogging.ps1 -Provider 'D2D578D9-2936-45B6-A09F-30E32715F42D:0x9', '11111111-2222-3333-4444-555555555555:0x2000' -HideFields 'd2d578d9:Id','d2d578d9:Timestamp','d2d578d9:Phase' -ExcludePattern '  d2d578d9  .* Phase=End( |$)'

.EXAMPLE
  # Several include patterns (an event matching any of them is shown), minus unwanted ones.
  .\Watch-EtwTraceLogging.ps1 -Provider 'D2D578D9-2936-45B6-A09F-30E32715F42D:0x9' -Pattern ':renderer\[', ':gpu-process\[' -ExcludePattern ' Phase=End( |$)', 'Idle'

.EXAMPLE
  # Each event is one output string, so the output can be piped or redirected. Keep only
  # events from renderer processes and save them to a file while they scroll by.
  .\Watch-EtwTraceLogging.ps1 -Provider 'D2D578D9-2936-45B6-A09F-30E32715F42D:0x20000' | Select-String ':renderer\[' | Tee-Object trace.txt

.OUTPUTS
  System.String. One string per event, written as the event arrives. Status messages
  (the banner, "Listening...", warnings) are not part of the output, so they do not
  end up in a pipeline or a file.

.NOTES
  If the output is slower than the events arrive, a "Falling behind" warning appears and
  lines queue up in memory. At the end of a -DurationSeconds run the queue is written for
  up to 5 more seconds; anything still queued is reported and discarded. If ETW itself drops
  events, a warning with the counts is shown when the script stops. In all these cases
  narrow the keywords or level in -Provider. For slow output, -ExcludePattern (for example
  the End events) and -HideFields also reduce what has to be written.

  If a run is killed without Ctrl+C the session may linger. logman is a Windows tool
  (https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/logman)
  which can be used to query and stop the session:
    logman query -ets            (look for the session name, default EtwWatch)
    logman stop EtwWatch -ets
  The next run also replaces a leftover session with the same name automatically.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string[]]$Provider,
  [string[]]$Pattern = @('.'),
  [string[]]$ExcludePattern = @(),
  [ValidateNotNullOrEmpty()]
  [string[]]$HideFields = @(),
  [ValidateRange(0, 86400)]
  [int]$DurationSeconds = 0,
  [ValidatePattern('^[A-Za-z0-9_.-]{1,64}$')]
  [string]$SessionName = 'EtwWatch'
)

$ErrorActionPreference = 'Stop'

if (-not [Environment]::Is64BitProcess) {
  throw 'Run this from 64-bit PowerShell.'
}

#-------------------------------------------------------------------------------
# Load and compile the ETW session implementation.
#-------------------------------------------------------------------------------

if (-not ('EtwWatch.EtwSession' -as [type])) {
  Add-Type -Path (Join-Path $PSScriptRoot 'Watch-EtwTraceLogging.cs') -ReferencedAssemblies 'System.Management'
}

#-------------------------------------------------------------------------------
# Parse provider specifications and build the provider list.
#-------------------------------------------------------------------------------

# 'GUID:keywords[:level]' where keywords is one or more 0x-prefixed hex values joined with '|'.
$specPattern = '^(?<guid>[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}):(?<keywords>0x[0-9a-f]{1,16}(?:\|0x[0-9a-f]{1,16})*)(?::(?<level>[0-5]))?$'
$seen = @{}
$providers = @(foreach ($spec in $Provider) {
  if ($spec -notmatch $specPattern) {
    throw "Invalid -Provider '$spec'. Expected 'GUID:0xKEYWORDS[:LEVEL]', e.g. 'D2D578D9-2936-45B6-A09F-30E32715F42D:0x9:4'."
  }
  $p = New-Object EtwWatch.ProviderSpec
  $p.Id = [Guid]$Matches.guid
  foreach ($value in $Matches.keywords -split '\|') {
    $p.Keywords = $p.Keywords -bor [Convert]::ToUInt64($value, 16)  # "0x" prefix is accepted for base 16
  }
  $p.Level = if ($Matches.level) { [byte]$Matches.level } else { 5 }
  # A second EnableTraceEx2 call for the same provider would silently replace the first mask.
  if ($seen.ContainsKey($p.Id)) {
    throw "Provider $($p.Id) is listed more than once. Join its keywords with '|' in a single entry."
  }
  $seen[$p.Id] = $true
  $p
})

#-------------------------------------------------------------------------------
# Parse hidden fields and assign them to the providers.
#-------------------------------------------------------------------------------

# -HideFields entries are 'field' (every provider) or 'provider:field', where provider is the
# first 8 hex digits of a listed provider's GUID, or the full GUID.
$hidden = @{}
foreach ($p in $providers) { $hidden[$p.Id] = New-Object 'System.Collections.Generic.List[string]' }
foreach ($entry in $HideFields) {
  if ($entry -match '^(?<prov>[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|[0-9a-f]{8}):(?<field>.+)$') {
    $prefix = $Matches.prov
    $field = $Matches.field
    $targets = @($providers | Where-Object { $_.Id.ToString().StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) })
    if ($targets.Count -eq 0) {
      throw "Invalid -HideFields '$entry': no provider in -Provider starts with '$prefix'."
    }
    if ($targets.Count -gt 1) {
      throw "Invalid -HideFields '$entry': more than one provider in -Provider starts with '$prefix'. Use the full GUID."
    }
    $hidden[$targets[0].Id].Add($field)
  }
  else {
    foreach ($p in $providers) { $hidden[$p.Id].Add($entry) }
  }
}
foreach ($p in $providers) { $p.HideFields = $hidden[$p.Id].ToArray() }

#-------------------------------------------------------------------------------
# Display the session configuration details.
#-------------------------------------------------------------------------------

foreach ($p in $providers) {
  $line = 'Provider  : {0}   Keywords: 0x{1:X}   Level: {2}' -f $p.Id, $p.Keywords, $p.Level
  if ($p.HideFields.Count -gt 0) { $line += '   Hidden fields: ' + ($p.HideFields -join ',') }
  Write-Host $line
}
Write-Host ('Pattern   : {0}' -f (($Pattern | ForEach-Object { "'$_'" }) -join ', '))
if ($ExcludePattern.Count -gt 0) {
  Write-Host ('Exclude   : {0}' -f (($ExcludePattern | ForEach-Object { "'$_'" }) -join ', '))
}
Write-Host ('Session   : {0}' -f $SessionName)

#-------------------------------------------------------------------------------
# Start the session and drain decoded events to the output.
#-------------------------------------------------------------------------------

[EtwWatch.EtwSession]::Start($SessionName, [string[]]$Pattern, [string[]]$ExcludePattern, [EtwWatch.ProviderSpec[]]$providers)

$batchSize = 500          # lines written to the output per pass
$backlogWarning = 50000   # warn when this many decoded lines are waiting to be written (about 15 MB)

try {
  Write-Host 'Listening... exercise the app now. Ctrl+C to stop.' -ForegroundColor Cyan
  $deadline = if ($DurationSeconds -gt 0) { [DateTime]::UtcNow.AddSeconds($DurationSeconds) } else { [DateTime]::MaxValue }
  $lastWarning = [DateTime]::MinValue
  while ([DateTime]::UtcNow -lt $deadline) {
    $err = [EtwWatch.EtwSession]::WorkerError
    if ($err) { throw $err }
    $batch = @([EtwWatch.EtwSession]::Drain($batchSize))
    if ($batch.Count -eq 0) {
      # sleep only when idle, so a backlog is worked off at full speed
      Start-Sleep -Milliseconds 100
      continue
    }
    $batch  # one output string per event
    $backlog = [EtwWatch.EtwSession]::Backlog
    if ($backlog -ge $backlogWarning -and ([DateTime]::UtcNow - $lastWarning).TotalSeconds -ge 10) {
      Write-Warning "Falling behind: $backlog lines are queued. Events arrive faster than they are consumed; narrow the keywords or level in -Provider, or use -Pattern or -ExcludePattern."
      $lastWarning = [DateTime]::UtcNow
    }
  }
  # Stop the session first. Once it no longer produces, the remaining queue is
  # finite.  Write what is left, but give a very slow consumer only a few
  # seconds so that the script always ends.
  [EtwWatch.EtwSession]::Stop()
  $drainUntil = [DateTime]::UtcNow.AddSeconds(5)
  while ([DateTime]::UtcNow -lt $drainUntil -and ($batch = @([EtwWatch.EtwSession]::Drain($batchSize))).Count -gt 0) { $batch }
  $unwritten = [EtwWatch.EtwSession]::Backlog
  if ($unwritten -gt 0) { Write-Warning "$unwritten queued lines were not written because the output was too slow." }
}
finally {
  [EtwWatch.EtwSession]::Stop()  # does nothing if the normal path already stopped it
  $lost = [EtwWatch.EtwSession]::EventsLost
  $lostBuffers = [EtwWatch.EtwSession]::RealTimeBuffersLost
  if ($lost -gt 0 -or $lostBuffers -gt 0) {
    Write-Warning "ETW lost $lost events ($lostBuffers real-time buffers) because they were produced faster than they could be read. Narrow the keywords or level in -Provider."
  }
  Write-Host 'Stopped.' -ForegroundColor Cyan
}
