# EKFiddle v.0.9.4.2

A framework based on the Fiddler web debugger to analyze malicious web traffic.

![Settings Window](https://github.com/malwareinfosec/EKFiddle/blob/master/Screenshots/ekfiddle_main.png)

# Main commands

The following commands can be typed in the QuickExec bar:

  `save` Save current traffic

  `ui` Change UI mode between standard, and advanced

  `vpn` Load a custom .opvn file

  `proxy` Chain Fiddler to upstream proxy

  `import` Import a SAZ or PCAP

  `regexes` View MasterRegexesand CustomRegexes

  `scan` Run regexes against current traffic

  `reset` Clear current comments and colors

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

# Uninstalling EKFiddle

Delete CustomRules.cs
