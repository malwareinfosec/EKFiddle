# EKFiddle v.1.2.6

An extension/rules for the **Fiddler Classic** web debugger to analyze malicious web traffic.

# Fiddler Classic

![Settings Window](https://github.com/malwareinfosec/EKFiddle/blob/master/Screenshots/EKFiddle.png)

# Installation

* Download and install Fiddler from here: https://www.telerik.com/fiddler

* Download and run EKFiddleExtension.exe

Alternatively, download EKFiddle.dll and put it into Fiddler's Scripts folder (`%AppData%\Local\Programs\Fiddler\Scripts`)

Note: The `EKFiddle.dll` version replaces the previous `CustomRules.cs`.

# Features

## Top level menu

The top level menu gives you the ability to access certain features and settings for the EKFiddle extension.

### Regexes

The Regexes menu item lets you view, edit, run and update the regexes that are used to identify web sessions and color them / add comments accordingly.

![Settings Window](https://github.com/malwareinfosec/EKFiddle/blob/master/Screenshots/regexes_menu.png)

Added support for AND/OR operators:

[regex] \*AND\* [regex] \*AND\* [regex]

[regex] \*OR\* [regex] \*OR\* [regex]

### YARA support

![image](https://github.com/malwareinfosec/EKFiddle/blob/master/Screenshots/yara.png)

### Advanced Filters

The Advanced Filters menu item is for filtering web traffic based on a compiled list of domains, URLs, IP addresses, or hashes that you want to exclude.

![Settings Window](https://github.com/malwareinfosec/EKFiddle/blob/master/Screenshots/menufilters.png)

You can also filter traffic by tags:

![Settings Window](https://github.com/malwareinfosec/EKFiddle/blob/master/Screenshots/tagsfilter.png)

### UI mode

Fiddler's default UI only shows a limited number of columns. By choosing the Advanced UI, you can view more information about web sessions, including CMS type, SHA-256, etc.

![Settings Window](https://github.com/malwareinfosec/EKFiddle/blob/master/Screenshots/UI_menu.png)

### Real-time monitoring options

* Real-time monitoring
* CMS detection
* Inspect Images (slow)

These real-time options can be enabled to automatically flag traffic as web sessions are being captured. CMS detection attempts to identify what kind of Content Management System a website is running and displays it within a new column (Advanced UI required).
Inspect Images will look at the content of supposed images to see if they are the wrong mime-type or hide content (steganography).

![Settings Window](https://github.com/malwareinfosec/EKFiddle/blob/master/Screenshots/monitoring_menu.png)

### Themes

Customize Fiddler's application and SAZ icons with the EKFiddle theme or retro versions of Fiddler.

![Settings Window](https://github.com/malwareinfosec/EKFiddle/blob/master/Screenshots/themes_menu.png)

![Settings Window](https://github.com/malwareinfosec/EKFiddle/blob/master/Screenshots/ico.png)

### AutoBrowser

Automate browsing tasks by loading a list of URLs from a text file and let Fiddler record all the traffic.

![Settings Window](https://github.com/malwareinfosec/EKFiddle/blob/master/Screenshots/autobrowser.png)

### Upstream proxy

Connect to another proxy (anonymous or private) via Fiddler

![Settings Window](https://github.com/malwareinfosec/EKFiddle/blob/master/Screenshots/upstreamproxy.png)

### Check for Updates...

Check for the latest version of EKFiddle.

### About

Displays the About page for the EKFiddle project.

## Contextual menu

The contextual menu (right click) allows you to perform additional actions on the selected web session(s).

![Settings Window](https://github.com/malwareinfosec/EKFiddle/blob/master/Screenshots/contextual_menu.png)

### Hostname

* Copy
* Google Search
* Internet Archive Lookup
* Sucuri SiteCheck Scan
* Urlscan.io Lookup
* VirusTotal Lookup

### IP Address

* Copy
* Google Search
* Urlscan.io Lookup
* VirusTotal Lookup

### Response Body

* Copy SHA-256
* Copy SHA-1
* Copy MD5
* Save to Disk
* Urlscan.io Lookup
* VirusTotal Lookup

### Extract

* Google Analytics ID
* Phone Number

### Filter

* Hide Hostname
* Hide IP Address
* Hide URL
* Hide Response Body Hash

### Connect-the-dots

This feature enables you to see the flow between a web session and previous ones. This is helpful to retrace traffic.

### Full Traffic Summary

Copies to the clipboard a text-base summary of web sessions that can be easily used to share with others.

### Tags

Add or edit tags (separate column in Advanced UI mode) for each web session.

![Settings Window](https://github.com/malwareinfosec/EKFiddle/blob/master/Screenshots/tags.png)

# Uninstallation

* Delete EKFiddle.dll from Fiddler's Script folder, delete EKFiddle's folder (`Documents\Fiddler2\EKFiddle`)
