# EKFiddle v.0.5.4

A framework based on the Fiddler web debugger to study Exploit Kits, malvertising and malicious traffic in general.

![Settings Window](https://github.com/malwareinfosec/EKFiddle/blob/master/Screenshots/Main_view.png)

# Installation

## Download and install the latest version of Fiddler

http://www.telerik.com/fiddler

Special instructions for Linux and Mac here:

http://www.telerik.com/blogs/fiddler-for-linux-beta-is-here

http://www.telerik.com/blogs/introducing-fiddler-for-os-x-beta-1

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

## VPN

With EKFiddle 0.2, a VPN GUI (.ovpn) is now available inside of Fiddler.
It uses the OpenVPN client on Windows and Linux with ovpn files which you can acquire from commercial VPN providers.
It will open up a new terminal/xterm whenever it connects to a new server, killing the previous to ensure only one TAP adapter is used at any given time. 

* Windows

Download and install OpenVPN in default directory

Place your .ovpn files inside OpenVPN's `config` folder.

* Linux (tested on Ubuntu 16.04)

`sudo apt-get install openvpn`

Place your .ovpn files in /etc/openvpn.

## Import SAZ/PCAP

A shortcut to load SAZ or PCAP captures.

## View/Edit Regexes

View and create your custom regular expressions. Note: a master list is provided with auto-updates via GitHub.

## Run Regexes

Run your regular expressions against current web sessions.

## Clear Markings

Clear any comment and colour highlighting in the currently loaded sessions.

## Advanced UI on/off

Toggle between the default column view or extra columns with additional information.

# ContextAction menu

The ContextAction menu (accessed by right-clicking on any session(s) allows you to perform additional commands:

## Regexes

### Build source code Regex
Copies the currently selected sessions' body into memory and opens up a regex website, where you can paste the source code and then work on a regular expression.

### Build URI Regex
Copies the currently selected sessions' URI into memory and opens up a regex website, where you can paste the URI and then work on a regular expression.

## Connect the dots (BETA)

Allows you to identify the sequence of events between sessions. Right-clik on the session you are interested in retracing your steps to and simply 'connect the dots'. It will label the sequence of events from 01, to n within the comments column. You can reorder that column to have a condensed view of the sequence.

## VirusTotal, RiskIQ

Opens up VirusTotal/RiskIQ's page for the currently selected host(s).
Opens up VirusTotal/RiskIQ's page for the currently selected session(s)' IP address.

## Extract IOCs

Copies into memory basic information from selected sessions so that they can be shared as IOCs.

## Extract Response Body to Disk

Downloads the currently selection session(s)'s body to disk, into the 'Artifacts' folder.

## Remove encoding

Decodes the currently selected sessions (from their basic encoding).

# Uninstalling EKFiddle

Open Fiddler, go to `Tools -> EKFiddle -> Uninstall EKFiddle`

Delete CustomRules.cs
