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

## Contextual menu

The contextual menu (right click) allows you to perform additional actions on the selection web session(s).

# Uninstallation

* Delete EKFiddle.dll from Fiddler's Script folder, delete EKFiddle's folder (`Documents\Fiddler2\EKFiddle`)
