The icons in this package allow you to revert Fiddler to an earlier look. This feature requires v2.4.6.2+ or v4.4.6.2+.

------- FIRST -------
 Extract these icons directly into the C:\program files(x86)\fiddler2 folder, or wherever you installed Fiddler.

------- CHANGE FIDDLER RUNNING ICON -------
 To replace Fiddler's main icon, in the QuickExec box beneath the Session list, type:

	prefs set fiddler.ui.overrideIcon 2012.ico

 ...and hit Enter. Restart Fiddler.

 (If you'd like, instead specify the full path to any icon on your system).

 To undo this change later, type 

	about:config

 ... in Fiddler's QuickExec box and remove the preference.

------- CHANGE FIDDLER START MENU ICON -------
 1. Find the shortcut to Fiddler in the Start Menu or use Explorer to find Fiddler2.lnk in C:\ProgramData\Microsoft\Windows\Start Menu\Programs\
 2. Right-Click the shortcut.
 3. Choose Properties. 
 4. On the Shortcut tab, click "Change icon..." Select desired icon.

------- CHANGE SAZ ICON -------

 1. To change the SAZ file icon, user RegEdit to open HKEY_CLASSES_ROOT\Fiddler.ArchiveZip\DefaultIcon.
 2. Change the default value to the path to the new SAZ icon.

Note that Windows Explorer caches icons, so you may need to restart and/or clear the Windows icon cache (procedure varies by OS).

---------------
(c)2014 Telerik