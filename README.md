# rrlog

**rrlog** (Roblox Ruleset Logger) is a proof-of-concept tool that logs memory scan results from Roblox's [YARA](https://github.com/VirusTotal/yara)-based detection system. It supports my [reversal](http://blog.nestra.tech/everyones-detected-roblox-part-i-yara-memory-scanning-2) of Roblox’s mechanism for detecting unsigned executable memory using custom YARA rulesets.

rrlog simulates the YARA memory scans performed by Hyperion at runtime. It searches for executable memory regions that exceed 10 pages in size (40 KB). When such a region is found, its `AllocationBase` is identified and the full memory allocation is recovered into a temporary buffer. This buffer is scanned using YARA, and any matches are logged along with relevant metadata.

## Usage

To use `rrlog.dll`, inject it into the Roblox process using your preferred method. Once loaded, a message box will provide further instructions. After the scan completes, results will be saved to the `\AppData\rrlog\` directory. Visit that folder to view the latest scan output.
