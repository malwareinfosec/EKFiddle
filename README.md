# EKFiddle v.1.0.0

Your Swiss Army knife to analyze malicious web traffic.

![Settings Window](https://github.com/malwareinfosec/EKFiddle/blob/master/Screenshots/ekfiddle_main.png)

# Installation

* Download and install Fiddler from here: https://www.telerik.com/fiddler

* Download and run EKFiddleExtension.exe

Alternatively, download EKFiddle.dll and put it into Fiddler's Scripts folder (`%AppData%\Local\Programs\Fiddler\Scripts`)

# Features

## Top level menu

The top level menu gives you the ability to access certain features and settings for the EKFiddle extension.

### Regexes

The Regexes menu item lets you view, edit, run and update the regexes that are used to identify web sessions and color them / add comments accordingly.

![Settings Window](https://github.com/malwareinfosec/EKFiddle/blob/master/Screenshots/regexes_menu.png)

### Advanced Filters

The Advanced Filters menu item is for filtering web traffic based on a compiled list of domains, URLs, IP addresses or hashes that you want to exclude.

![Settings Window](https://github.com/malwareinfosec/EKFiddle/blob/master/Screenshots/advancedfilters_menu.png)

### UI mode

Fiddler's default UI only shows a limited number of columns. By choosing the Advanced UI, you can view more information about werb sessions, including CMS type, SHA-256, etc.

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

### AutoBrowser

Automate browsing tasks by loading a list of URLs from a text file and let Fiddler record all the traffic.

![Settings Window](https://github.com/malwareinfosec/EKFiddle/blob/master/Screenshots/autobrowser.png)

## Contextual menu

The contextual menu (right click) allows you to perform additional actions on the selected web session(s).

# Uninstallation

* Delete EKFiddle.dll from Fiddler's Script folder, delete EKFiddle's folder (`Documents\Fiddler2\EKFiddle`)