# EKFiddle v.0.9.3.2

A framework based on the Fiddler web debugger to analyze malicious web traffic.

![Settings Window](https://github.com/malwareinfosec/EKFiddle/blob/master/Screenshots/Version_0.8.gif)

# Installation

## Download and install the latest version of Fiddler

`Windows`

Download and install from here: https://www.telerik.com/fiddler

`Linux`

* Download Fiddler: http://telerik-fiddler.s3.amazonaws.com/fiddler/fiddler-linux.zip

* Download and install Mono: https://www.mono-project.com/download/stable/#download-lin

* Run Fiddler: *cd fiddler-linux*, *mono Fiddler.exe*

* Additional instructions (certs, etc): https://www.telerik.com/blogs/fiddler-for-linux-beta-is-here

`Mac`

* Instructions: https://www.telerik.com/blogs/introducing-fiddler-for-os-x-beta-1

## Enable C# scripting (Windows only)

Launch Fiddler, and go to `Tools -> Options`

In the `Scripting` tab, change the default (JScript.NET) to C#. 

## Change default text editor (optional)

In the same `Tools -> Options` menu, click on the `Tools` tab.

* Windows: `notepad.exe` or `notepad++.exe`
* Linux: `gedit`
* Mac: `/Applications/TextEdit.app` or `/Applications/TextWrangler.app`

Close Fiddler

## Download or clone CustomRules.cs into the appropriate folder based on your operating system:

* Windows (7/10) `C:\Users\[username]\Documents\Fiddler2\Scripts\`

* Ubuntu `/home/[username]/Fiddler2/Scripts/`

* Mac `/Users/[username]/Fiddler2/Scripts/`

## Finish up the installation

Start Fiddler to complete the installation of EKFiddle. That's it, you're all set!

# Features

# Toolbar buttons

The added toolbar buttons give you quick shortcuts to some of the main features:

![Settings Window](https://github.com/malwareinfosec/EKFiddle/blob/master/Screenshots/toolbar.png)

## QuickSave

Dumps current web sessions into a SAZ named (QuickSave-"MM-dd-yyyy-HH-mm-ss".saz) to EKFiddle\Captures\.

## UI mode

Toggle between the default column view or extra columns with additional information (includes time stamp, server IP and type, method, etc.).

## VPN

VPN GUI directly built into Fiddler.
It uses the OpenVPN client on Windows and Linux with ovpn files (sigining up with commercial VPN provider may be required).
It will open up a new terminal/xterm whenever it connects to a new server via the selected .ovpn config file, killing the previous to ensure only one TAP adapter is used at any given time. 

* Windows

Download and install OpenVPN in default directory

Place your .ovpn files inside OpenVPN's `config` folder.

* Linux (tested on Ubuntu 16.04)

`sudo apt-get install openvpn`

Place your .ovpn files in /etc/openvpn.

## Proxy

Allows you to connect to an upstream proxy (HTTP/s or SOCKS).

## Import SAZ/PCAP

A shortcut to load SAZ (Fiddler's native format) or PCAP (i.e. from Wireshark) captures.

## View/Edit Regexes

View and create your custom regular expressions. Note: a master list is provided with auto-updates via GitHub. Additionally the custom list lets you create your own rules.

There are 4 types of indicators to match on:

* URI (full or partial URI match)
* IP (Single IP address or IP range)
* SourceCode (Response Body)
* Headers (any value within a Response's Headers)

Syntax:

Important! Fields are TAB delimited

`URI	My_URI_rule	[a-z0-9]{2} Match URI`

`IP	My_IP_address_rule	5\.154\.191\.67 Match static IP address`

`IP	My_IP_address_rule 5\.154\.191\.(6[0-9]|70) Match an IP range`

`SourceCode	My_sourcecode_rule	vml=1 Look for specific string`

`Headers	My_headers_rule	nginx Look for specific string`

## Run Regexes

Run the master and custom regular expressions against current web sessions.

## Clear Markings

Clear any comment and colour highlighting in the currently loaded sessions.

# ContextAction menu

The ContextAction menu (accessed by right-clicking on any session(s) allows you to perform additional commands on selected sections. This can be very helpful to do quick lookups, compute hashes or extract IOCs.

## Hostname or IP address (Google Search, RiskIQ, URLQuery, RiskIQ)

Query the hostname for the currently selected session.

## URI

### Build Regex

Create a regular expression from the currently selected URI. This action opens up a regex website and the URI is already in the clipboard, ready to be pasted into the query field.

### Open in... Internet Explorer, Chrome, Firefox, Edge

This opens up the URI with the browser you selected.

## Response Body

### Remove encoding

Decodes the currently selected sessions (from their basic encoding).

### Build Regex

Create a regular expression from the currently selected session's source code. This action opens up a regex website and the URI is already in the clipboard, ready to be pasted into the query field.

### Calculate MD5/SHA256 hash

Get the current session's body and computes its hash.

### Hybrid Analysis / VirusTotal lookup

Checks the current session's body for hash, then look up that hash.

### Extract to Disk

Downloads the currently selection session(s)'s body to disk, into the 'Artifacts' folder.

## Extract IOCs

Copies into memory basic information from selected sessions so that they can be shared as IOCs.
Extract Coinhive site keys

## Connect-the-dots

Allows you to identify the sequence of events between sessions. Right-clik on the session you are interested in retracing your steps to and simply 'connect the dots'. It will label the sequence of events from 01, to n within the comments column. You can reorder that column to have a condensed view of the sequence.

![Settings Window](https://pbs.twimg.com/media/DRHzpwDUIAA-E24.jpg)

## Crawler (experimental)
Load a list of URLs from a text file and let the browser automically visit them.
Tools -> Crawler (experimental) -> Start crawler
May require some tweaks in your browser's settings, in particular with regards to crash recovery.

# Uninstalling EKFiddle

Delete CustomRules.cs
