# chromium-tools

Diagnostic and debugging tools for Chromium.

> Unofficial. Not affiliated with or endorsed by the Chromium project or Google.

| Tool | Platform | What it does |
|---|---|---|
| [`Watch-EtwTraceLogging.ps1`](Watch-EtwTraceLogging.ps1) | Windows | Live-prints ETW TraceLogging events, such as Chromium's ETW export, filtered with a regex |
| [`Test-MFCapabilities.ps1`](Test-MFCapabilities.ps1) | Windows | Reports Media Foundation and PlayReady capabilities for each display |

Each script has built-in help (`Get-Help .\<script>.ps1 -Full`). Keep each
`.ps1` next to its `.cs` file, which it compiles on each run.

## License

[MIT](LICENSE)
