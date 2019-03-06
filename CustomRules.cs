using System;
using Fiddler;
using System.Text;
using System.Windows.Forms;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Net;
using System.Threading;
using Microsoft.Win32;

// EKFiddle
// This is a modified version of the default CustomRules.cs file.
// Its purpose is to provide a framework to analyze exploit kits,
// malvertising, and malicious traffic in general.
// For more information and to get the latest version:
// https://github.com/malwareinfosec/EKFiddle

// INTRODUCTION
// This is the FiddlerScript Rules file, which creates some of the menu commands and
// other features of Fiddler. You can edit this file to modify or add new commands.
//
// NOTE: This is the C# version of the script, which can be used on Windows and Mono,
// unlike the JScript.NET script, which can be used only on Windows. In order to use
// a JScript.NET script on Mono, you must rewrite it in C#.
//
// The original version of this file is named SampleRules.cs and it is in the
// \Fiddler\ app folder. When Fiddler first starts, it creates a copy named
// CustomRules.cs inside your \Documents\Fiddler2\Scripts folder. If you make a 
// mistake in editing this file, simply delete the CustomRules.cs file and restart
// Fiddler. A fresh copy of the default rules will be created from the original
// sample rules file.

namespace Fiddler
{
    public static class Handlers 
    {
        // The following snippet demonstrates a custom-bound column for the Web Sessions list.
        // See http://fiddler2.com/r/?fiddlercolumns for more info
        /*
        [BindUIColumn("Method", 60)]
        public static string FillMethodColumn(Session oS)
        {
         return oS.RequestMethod;
        }
        */
        
        // The following snippet demonstrates how to create a custom tab that shows simple text
        /*
        [BindUITab("Flags")]
        public static string FlagsReport(Session[] arrSess)
        {
            StringBuilder oSB = new StringBuilder();
            for (int i = 0; i < arrSess.Length; i++)
            {
                oSB.AppendLine("SESSION FLAGS");
                oSB.AppendFormat("{0}: {1}\n", arrSess[i].id, arrSess[i].fullUrl);
                foreach(DictionaryEntry sFlag in arrSess[i].oFlags)
                {
                    oSB.AppendFormat("\t{0}:\t\t{1}\n", sFlag.Key, sFlag.Value);
                }
            }

            return oSB.ToString();
        }
        */

        [QuickLinkMenu("&Links")]
        [QuickLinkItem("EKFiddle GitHub page", "https://github.com/malwareinfosec/EKFiddle")]
        [QuickLinkItem("EKFiddle Twitter page", "https://www.twitter.com/EKFiddle")]
        public static void DoLinksMenu(string sText, string sAction)
        {
            Utilities.LaunchHyperlink(sAction);
        }
        
        // EKFiddle realtime monitoring
        [RulesOption("EKFiddle Real-Time Monitoring")]
        public static bool m_EKFiddleRealTime = true;
        
        [RulesOption("Hide 304s")]
        [BindPref("fiddlerscript.rules.Hide304s")]
        public static bool m_Hide304s = false;
        
        // Automatic Authentication
        [RulesOption("&Automatically Authenticate")]
        [BindPref("fiddlerscript.rules.AutoAuth")]
        public static bool m_AutoAuth = false;
        
        // Cause Fiddler to delay HTTP traffic to simulate typical 56k modem conditions
        [RulesOption("Simulate &Modem Speeds", "Per&formance")]
        public static bool m_SimulateModem = false;

        // Removes HTTP-caching related headers and specifies "no-cache" on requests and responses
        [RulesOption("&Disable Caching", "Per&formance")]
        public static bool m_DisableCaching = false;

        [RulesOption("Cache Always &Fresh", "Per&formance")]
        public static bool m_AlwaysFresh = false;

        // Cause Fiddler to override the Accept-Language header with one of the defined values
        // Inspired by http://tobint.com/blog/fiddler-script-for-accept-language-testing/
        [RulesString("&Accept-Languages", true)] 
        [BindPref("fiddlerscript.ephemeral.AcceptLanguage")]
        [RulesStringValue(0, "&Custom...", "%CUSTOM%")]
        [RulesStringValue(1, "English (US)", "en-US")]
        [RulesStringValue(2, "English (UK)", "en-GB")]
        [RulesStringValue(3, "English (Canada)", "en-CA")]
        [RulesStringValue(4, "English (Australia)", "en-CA")]
        [RulesStringValue(5, "French", "fr")]
        [RulesStringValue(6, "Spanish", "es")]
        [RulesStringValue(7, "Italian", "it-IT")]
        [RulesStringValue(8, "Portuguese (Brazil)", "pt-BR")]
        [RulesStringValue(9, "German", "de")]
        [RulesStringValue(10, "Japanese", "ja")]
        [RulesStringValue(11, "Korean", "ko")]
        [RulesStringValue(12, "Chinese (PRC)", "zh-CN")]
        [RulesStringValue(13, "Chinese (Taiwan)", "zh-TW")]
        [RulesStringValue(14, "Russian", "ru")]
        public static string sAL = null;

        // Cause Fiddler to override the User-Agent header with one of the defined values
        [RulesString("&User-Agents", true)] 
        [BindPref("fiddlerscript.ephemeral.UserAgentString")]
        [RulesStringValue(0, "&Custom...", "%CUSTOM%")]
        [RulesStringValue(1, "Internet Explorer", "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko")]
        [RulesStringValue(2, " -> IE &8 (Win7)", "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)")]
        [RulesStringValue(3, " -> IE 9 (Win7)", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)")]
        [RulesStringValue(4, " -> IE 10 (Win7)", "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)")]
        [RulesStringValue(5, " -> IE 11 (Win7)", "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko")]
        [RulesStringValue(6, "Chrome", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36")]
        [RulesStringValue(7, " -> Chrome (Win7)", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36")]
        [RulesStringValue(8, " -> Chrome (Win10)", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36")]
        [RulesStringValue(9, " -> Chrome (Android)", "Mozilla/5.0 (Linux; Android 5.1.1; Nexus 5 Build/LMY48B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.78 Mobile Safari/537.36")]
        [RulesStringValue(10, " -> Chrome (iPhone)", "Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/603.1.30 (KHTML, like Gecko) CriOS/60.0.3112.89 Mobile/15A5370a Safari/602.1")]
        [RulesStringValue(11, " -> ChromeBook", "Mozilla/5.0 (X11; CrOS x86_64 6680.52.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.74 Safari/537.36")]
        [RulesStringValue(12, "Edge (Win10)", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299")]
        [RulesStringValue(13, "&Opera", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36 OPR/46.0.2597.57")]
        [RulesStringValue(14, " -> &Opera 46 (Win7)", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36 OPR/46.0.2597.57")]
        [RulesStringValue(15, " -> &Opera 49 (Win10)", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3188.4 Safari/537.36 OPR/49.0.2705.0 (Edition developer)")]
        [RulesStringValue(16, "&Firefox", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0")]
        [RulesStringValue(17, " -> &Firefox 3.6 (Win7)", "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.2.7) Gecko/20100625 Firefox/3.6.7")]
        [RulesStringValue(18, " -> &Firefox 58 (Win7)", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0")]
        [RulesStringValue(19, " -> &Firefox 58 (Win10)", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0")]
        [RulesStringValue(20, " -> &Firefox (Mac)", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0")]
        [RulesStringValue(21, "Safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 11.0) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/11.0 Safari/602.1.50")]
        [RulesStringValue(22, " -> Mac (Safari 11)", "Mozilla/5.0 (Macintosh; Intel Mac OS X 11.0) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/11.0 Safari/602.1.50")]
        [RulesStringValue(23, " -> iPhone (Safari 11)", "Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A356 Safari/604.1")]
        [RulesStringValue(24, " -> iPad (Safari 11)", "Mozilla/5.0 (iPad; CPU OS 11_0 like Mac OS X) AppleWebKit/604.1.25 (KHTML, like Gecko) Version/11.0 Mobile/15A5304j Safari/604.1")]
        [RulesStringValue(25, "GoogleBot Crawler", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")]
        public static string sUA = null;
            
        // VPN
        [ToolsAction("VPN")]
        public static void DoVPN()
        {
            DoEKFiddleVPN();
        }
        
        // Proxy
        [ToolsAction("Proxy")]
        public static void DoProxy()
        {
            DoEKFiddleProxy();
        }

        // Import traffic capture
        [ToolsAction("Import SAZ/PCAP")]
        public static void DoCallImportCapture()
        {
            DoImportCapture();
        }

         // Update/View Regexes
        [ToolsAction("Update/View Regexes", "&Regexes")]
        public static void DoCallOpenRegexes()
        {
            DoOpenRegexes();
        }

        // Run Regexes
        [ToolsAction("Run Regexes", "&Regexes")]
        public static void DoCallEKFiddleRunRegexes() 
        {
            DoEKFiddleRunRegexes();
        }
        
        // Crawler
        [ToolsAction("Start crawler", "&Crawler (experimental)")]
        public static void DoCallEKFiddleStartCrawler() 
        {
            EKFiddleStartCrawler();
        }

        [ToolsAction("Stop crawler", "&Crawler (experimental)")]
        public static void DoCallEKFiddleStopCrawler() 
        {
            FiddlerApplication.Prefs.SetBoolPref("fiddler.ekfiddleCrawl", false);
        }
        
        // Misc. tasks
        [ToolsAction("Keep unique hostnames only", "Misc.")]
        public static void doUniqHostnames() 
        {
            // Loop through each session
            FiddlerObject.UI.actSelectAll();        
            var arrSessions = FiddlerApplication.UI.GetSelectedSessions();
            // Create new list
            List<string> HostnameList = new List<string>();
            for (int x = 0; x < arrSessions.Length; x++)
            {
                var currentHostname = arrSessions[x].hostname;
                if (HostnameList.Contains(currentHostname))
                {
                    // item already exists
                    arrSessions[x].oFlags["ui-comments"] = "deleteme";
                }else{
                    // item is new
                    HostnameList.Add(currentHostname);
                }
            }
            FiddlerApplication.UI.actSelectSessionsMatchingCriteria(
                delegate(Session oS)
                {
                    return ("deleteme" == oS.oFlags["ui-comments"]);
                }
            );
            FiddlerApplication.UI.actRemoveSelectedSessions();
        }
        
        // Themes
        [ToolsAction("EKFiddle", "Themes")]
        public static void DoThemesEKFiddle()
        {
            DoFiddlerTheme("EKFiddle.ico", "EKFiddle_saz.ico");
        }
        
        [ToolsAction("Fiddler 2003", "Themes")]
        public static void DoThemesFiddler2003()
        {
            DoFiddlerTheme("2003.ico", "SAZ2008.ico");
        }
        
        [ToolsAction("Fiddler 2008", "Themes")]
        public static void DoThemesFiddler2008()
        {
            DoFiddlerTheme("2008.ico", "SAZ2008.ico");
        }
        
        [ToolsAction("Fiddler 2012", "Themes")]
        public static void DoThemesFiddler2012()
        {
            DoFiddlerTheme("2012.ico", "SAZ2008.ico");
        }
        
        [ToolsAction("Restore default", "Themes")]
        public static void DoThemesFiddlerDefault()
        {
            DoFiddlerTheme("App.ico", "saz.ico");
        }
        
        // Force a manual reload of the script file.  Resets all
        // RulesOption variables to their defaults.
        [ToolsAction("Reset Script")]
        public static void DoManualReload()
        {
            FiddlerObject.ReloadScript();
        }
       
        // Connect the dots
        [ContextAction("Connect-the-dots")]
        public static void DoConnectTheDots(Session[] arrSessions) 
        {
            // Check how many sessions are selected (we only allow 1)
            if (arrSessions.Length > 1)
            {
                MessageBox.Show("Please select only 1 session.", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {    
                List<int> maliciousSessionsList = new List<int>();
                connectDots(arrSessions[0].id, arrSessions[0].hostname, arrSessions[0].fullUrl, maliciousSessionsList);
            }
        }
        
        // Extract IOCs
        [ContextAction("Traffic Summary", "IOCs")]
        public static void DoExtractIOCs(Session[] arrSessions)
        {
            List<string> IOCsList = new List<string>();
            IOCsList.Add("Time,Method,IP address,Hostname,Comments");
            for (int x = 0; x < arrSessions.Length; x++)
            {
                var currentMethod = arrSessions[x].oRequest.headers.HTTPMethod;
                var currentIP = arrSessions[x].oFlags["x-hostIP"];
                var currentHostname = arrSessions[x].host;
                var currentComments = arrSessions[x].oFlags["ui-comments"];
                //var referer = arrSessions[x].oRequest["Referer"]; 
                if (currentComments == null)
                {
                    currentComments = "N/A";
                }
                var currentTime = arrSessions[x].Timers.ClientBeginRequest.ToString();
                IOCsList.Add(currentTime + "," + currentMethod + "," + currentIP + "," + currentHostname + "," + currentComments);
            }
             
            var trafficSummary = string.Join(Environment.NewLine, IOCsList.ToArray());
            Utilities.CopyToClipboard(trafficSummary);
            MessageBox.Show("Traffic Summary has been copied to the clipboard.", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        
        [ContextAction("Referer(s)", "IOCs")]
        public static void doReferers(Session[] arrSessions) {
        // Initialize a new list
            List<string> referersList = new List<string>();
            for (int x = 0; x < arrSessions.Length; x++)
            {
                if (arrSessions[x].oRequest.headers.Exists("Referer")) {
                    referersList.Add(arrSessions[x].oRequest["Referer"]);
                }
            }
            // Dup check
            if (referersList.Count != 0)
            {
                // Remove duplicate items
                referersList.Sort();
                Int32 index = 0;
                while (index < referersList.Count - 1)
                {
                    if (referersList[index] == referersList[index + 1])
                        referersList.RemoveAt(index);
                    else
                        index++;
                }
                // Convert to Array
                var referersJoined = string.Join(Environment.NewLine, referersList.ToArray());
                Utilities.CopyToClipboard(referersJoined);
                MessageBox.Show(referersJoined, "EKFiddle: Referers", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }else{
                MessageBox.Show("No referer was found!", "EKFiddle: Referers", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }   
        }
        
        [ContextAction("MD5 Hash(es)", "IOCs")]
        public static void doMD5Hash(Session[] arrSessions) {
        // Initialize a new list
            List<string> HashList = new List<string>();
            for (int x = 0; x < arrSessions.Length; x++)
            {
                if (arrSessions[x].bHasResponse) {
                    HashList.Add(arrSessions[x].GetResponseBodyHash("md5").Replace("-","").ToLower());
                }
            }
            var HashJoined = string.Join(Environment.NewLine, HashList.ToArray());
            Utilities.CopyToClipboard(HashJoined);
            MessageBox.Show(HashJoined, "EKFiddle: MD5 Hash", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        
        [ContextAction("SHA256 Hash(es)", "IOCs")]
        public static void doSHA256Hash( Session[] arrSessions) {
        // Initialize a new list
            List<string> HashList = new List<string>();
            for (int x = 0; x < arrSessions.Length; x++)
            {
                if (arrSessions[x].bHasResponse) {
                    HashList.Add(arrSessions[x].GetResponseBodyHash("sha256").Replace("-","").ToLower());
                }
            }
            var HashJoined = string.Join(Environment.NewLine, HashList.ToArray());
            Utilities.CopyToClipboard(HashJoined);
            MessageBox.Show(HashJoined, "EKFiddle: SHA256 Hash", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        
        //  Google Analytics Tracking ID extraction
        [ContextAction("Google Analytics Tracking ID(s)", "IOCs")]
        public static void DoExtractGA(Session[] arrSessions)
        {
            List<string> GAList = new List<string>();
            for (int x = 0; x < arrSessions.Length; x++)
            {
                var sourceCode = arrSessions[x].GetResponseBodyAsString().Replace('\0', '\uFFFD');
                var match = Regex.Match(sourceCode, @"', 'UA-([^']*)").Groups[1].Value;
                if (match != "" && arrSessions[x].fullUrl != "https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/CustomRules.cs")
                {
                    GAList.Add(arrSessions[x].host + "," + "UA-" + match);
                }
            }
            
            if (GAList.Count != 0)
            {
                // Remove duplicate items
                GAList.Sort();
                Int32 index = 0;
                while (index < GAList.Count - 1)
                {
                    if (GAList[index] == GAList[index + 1])
                        GAList.RemoveAt(index);
                    else
                        index++;
                }
                // Convert to Array
                var siteKeys = string.Join(Environment.NewLine, GAList.ToArray());
                Utilities.CopyToClipboard(siteKeys);
                MessageBox.Show(siteKeys, "EKFiddle: Google Analytics Tracking ID extraction", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }else{
                MessageBox.Show("No Google Analytics Tracking ID was found!", "EKFiddle: Google Analytics Tracking ID Extraction", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }
        
        //  Coinhive Site Key extraction
        [ContextAction("Coinhive Site Key(s)", "IOCs")]
        public static void DoExtractCoinhive(Session[] arrSessions)
        {
            List<string> siteKeysList = new List<string>();
            for (int x = 0; x < arrSessions.Length; x++)
            {
                var sourceCode = arrSessions[x].GetResponseBodyAsString().Replace('\0', '\uFFFD');
                var match = Regex.Match(sourceCode, "var miner = new CoinHive.(Anonymous|User)(.*?)(;|,)").Groups[2].Value.Replace("(", "").Replace(")", "").Replace("'", "").Replace("\"", "").Replace("‘", "").Replace("’", "");
                if (match != "")
                {
                    siteKeysList.Add(arrSessions[x].host + "," + match);
                }
            }
            if (siteKeysList.Count != 0)
            {
                // Remove duplicate items
                siteKeysList.Sort();
                Int32 index = 0;
                while (index < siteKeysList.Count - 1)
                {
                    if (siteKeysList[index] == siteKeysList[index + 1])
                        siteKeysList.RemoveAt(index);
                    else
                        index++;
                }
                // Convert to Array
                var siteKeys = string.Join(Environment.NewLine, siteKeysList.ToArray());
                Utilities.CopyToClipboard(siteKeys);
                MessageBox.Show(siteKeys, "EKFiddle: Coinhive Site Key Extraction", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }else{
                MessageBox.Show("No Coinhive Site Key was found!", "EKFiddle: Coinhive Site Key Extraction", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }
        
        // Remove any encoding
        [ContextAction("Remove Encoding", "Response Body")]
        public static void DoRemoveEncoding(Session[] arrSessions) 
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                arrSessions[x].utilDecodeRequest();
                arrSessions[x].utilDecodeResponse();
            }

            FiddlerApplication.UI.actUpdateInspector(true,true);
        }
        
        // Create a regex from the current source code
        [ContextAction("Build Regex", "Response Body")]
        public static void DoBuildRegexSourceCode(Session[] arrSessions)
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                var sourceCode = arrSessions[x].GetResponseBodyAsString().Replace('\0', '\uFFFD');
                Utilities.CopyToClipboard(sourceCode.ToString());
                Utilities.LaunchHyperlink("http://regexr.com/");
            }
        }
        
        // Save the current session body response to disk
        [ContextAction("Extract to Disk", "Response Body")]
        public static void DoSaveBody(Session[] arrSessions)
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                arrSessions[x].SaveResponseBody(EKFiddleArtifactsPath + arrSessions[x].SuggestedFilename);
            }
            FiddlerApplication.UI.actUpdateInspector(true,true);
            Process.Start(@EKFiddleArtifactsPath);
        }
        
        // Save the current session body response to disk using MD5 as name
        [ContextAction("Extract to Disk as MD5", "Response Body")]
        public static void DoSaveBodyMD5(Session[] arrSessions)
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                arrSessions[x].SaveResponseBody(EKFiddleArtifactsPath + arrSessions[x].GetResponseBodyHash("md5").Replace("-","").ToLower());
            }
            FiddlerApplication.UI.actUpdateInspector(true,true);
            Process.Start(@EKFiddleArtifactsPath);
        }
        
        // Save the current session body response to disk using SHA256 as name
        [ContextAction("Extract to Disk as SHA256", "Response Body")]
        public static void DoSaveBodySHA256(Session[] arrSessions)
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                arrSessions[x].SaveResponseBody(EKFiddleArtifactsPath + arrSessions[x].GetResponseBodyHash("sha256").Replace("-","").ToLower());
            }
            FiddlerApplication.UI.actUpdateInspector(true,true);
            Process.Start(@EKFiddleArtifactsPath);
        }
        
        // Check the current hash in Hybrid Analysis
        [ContextAction("Hybrid Analysis Lookup", "Response Body")]
        public static void DoCheckHA(Session[] arrSessions) 
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                if (arrSessions[x].bHasResponse) {
                    Utilities.LaunchHyperlink(string.Format("https://www.reverse.it/sample/{0}",arrSessions[x].GetResponseBodyHash("sha256").Replace("-","").ToLower()));
                }
            }
        }
        
        // Check the current hash against VT
        [ContextAction("VirusTotal Lookup", "Response Body")]
        public static void DoCheckHashVT(Session[] arrSessions) 
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                if (arrSessions[x].bHasResponse) {
                    Utilities.LaunchHyperlink(string.Format("https://www.virustotal.com/en/file/{0}/analysis/",arrSessions[x].GetResponseBodyHash("sha256").Replace("-","").ToLower()));   
                }
            }
        }
        
        [ContextAction("Open in default browser", "URI")]
        public static void DoOpenURL(Session[] arrSessions)
        {
            // Loop through URLs
            for (int x = 0; x < arrSessions.Length; x++)
            {
                Utilities.LaunchHyperlink(arrSessions[x].fullUrl);
            }
        }
        
        [ContextAction("Build Regex", "URI")]
        public static void DoBuildRegexURL(Session[] arrSessions)
        {
            // Initialize a new list
            List<string> URIList = new List<string>();
            for (int x = 0; x < arrSessions.Length; x++)
            {
                URIList.Add(arrSessions[x].fullUrl);
            }
            var URI = string.Join(Environment.NewLine, URIList.ToArray());
            Utilities.CopyToClipboard(URI.ToString());
            Utilities.LaunchHyperlink("http://regexr.com/");
        }
        
        // IP address pivoting
        [ContextAction("Search for OSINT...", "IP address")]
        public static void DoCheckIP(Session[] arrSessions) 
        {
        }    

        // Check the current IP address to ASN
        [ContextAction(" -> ASN", "IP address")]
        public static void DoCheckASN(Session[] arrSessions) 
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                Utilities.LaunchHyperlink("https://api.iptoasn.com/v1/as/ip/" + arrSessions[x].oFlags["x-hostIP"]);
            }
        }

        // Check the current IP address against Google
        [ContextAction(" -> Google", "IP address")]
        public static void DoCheckIPGoogle(Session[] arrSessions)
        {
        for (int x = 0; x < arrSessions.Length; x++)
            {
                Utilities.LaunchHyperlink("https://www.google.com/search?q=" + "\"\"" + arrSessions[x].oFlags["x-hostIP"] + "\"\"");
            }
        }
    
        // Check the current IP address against RiskIQ
        [ContextAction(" -> RiskIQ", "IP address")]
        public static void DoCheckIPRiskIQ(Session[] arrSessions) 
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                Utilities.LaunchHyperlink("https://community.riskiq.com/search/" + arrSessions[x].oFlags["x-hostIP"] +"");
            }
        }

        // Check the current IP address against URLQuery
        [ContextAction(" -> URLQuery", "IP address")]
        public static void DoOSINTIPURLQuery(Session[] arrSessions)
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                Utilities.LaunchHyperlink("https://urlquery.net/search?q=" + arrSessions[x].oFlags["x-hostIP"]);
            }
        }

        // Check the current IP address against VT
        [ContextAction(" -> VirusTotal", "IP address")]
        public static void DoCheckIPVT(Session[] arrSessions) 
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                Utilities.LaunchHyperlink("https://www.virustotal.com/en/ip-address/" + arrSessions[x].oFlags["x-hostIP"] +"/information/");
            }
        }

        // Hostname pivoting
        [ContextAction("Search for OSINT...", "Hostname")]
        public static void DoOSINTHostname(Session[] arrSessions)
        {
        }
        
        // Check the current hostname against Google
        [ContextAction(" -> Google", "Hostname")]
        public static void DoOSINTHostnameGoogle(Session[] arrSessions)
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                Utilities.LaunchHyperlink("https://www.google.com/search?q=" + "\"\"" + arrSessions[x].hostname + "\"\"");
            }
        }

        // Check the current hostname against RiskIQ
        [ContextAction(" -> RiskIQ", "Hostname")]
        public static void DoCheckHostnameRiskIQ(Session[] arrSessions) 
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                Utilities.LaunchHyperlink("https://community.riskiq.com/search/" + arrSessions[x].hostname +"");
            }
        }
        
        // Check the current hostname against Sucuri
        [ContextAction(" -> Sucuri", "Hostname")]
        public static void DoCheckHostnameSucuri(Session[] arrSessions) 
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                Utilities.LaunchHyperlink("https://sitecheck.sucuri.net/results/" + arrSessions[x].hostname);
            }
        }

        // Check the current hostname against URLQuery
        [ContextAction(" -> URLQuery", "Hostname")]
        public static void DoOSINTHostnameURLQuery(Session[] arrSessions)
        {
        for (int x = 0; x < arrSessions.Length; x++)
            {
                Utilities.LaunchHyperlink("https://urlquery.net/search?q=" + arrSessions[x].hostname);
            }
        }

        // Check the current hostname against VT
        [ContextAction(" -> VirusTotal", "Hostname")]
        public static void DoCheckDomainVT(Session[] arrSessions) 
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                Utilities.LaunchHyperlink("https://virustotal.com/en/domain/" + arrSessions[x].hostname +"/information/");
            }
        }
        
        // Check Alexa rank
        [ContextAction("Check Alexa Rank", "Hostname")]
        public static void DoCheckDomainAlexa(Session[] arrSessions) 
        {
            new Thread(() => 
            {
                Thread.CurrentThread.IsBackground = true;
                try
                {
                    for (int x = 0; x < arrSessions.Length; x++)
                    {
                        var AlexaRank = "";
                        int Num;
                        var currentComments = "";
                        bool popUrl = false;
                        string hostname = arrSessions[x].hostname;
                        int totalSessions = arrSessions.Length;
                         // Progress status
                        FiddlerApplication.UI.SetStatusText("Checking Alexa Rank " + (x + 1) + "/" + totalSessions + " Sessions (" + arrSessions[x].hostname + ") ...");
                        WebRequest request = WebRequest.Create("https://data.alexa.com/data?cli=10&dat=snbamz&url=" + hostname);
                        WebResponse response = request.GetResponse();
                        StreamReader sr = new StreamReader(response.GetResponseStream());
                        string line = "";
                        while ((line = sr.ReadLine()) != null)
                        {
                            if(line.Contains("POPULARITY URL"))
                            {
                                popUrl = true;
                                AlexaRank = Regex.Replace(Regex.Replace(line, "^.*TEXT=\"", ""), "\".*", "");
                                // Check the result is an integer
                                bool isNum = int.TryParse(AlexaRank.ToString (), out Num);
                                if (isNum)
                                {
                                    currentComments = arrSessions[x].oFlags["ui-comments"];
                                    arrSessions[x].oFlags["ui-comments"] = currentComments + " (Alexa Rank: " + AlexaRank +")";
                                    arrSessions[x].RefreshUI();
                                }
                                else
                                {
                                    FiddlerApplication.UI.SetStatusText("EKFiddle: output from Alexa did not match a valid integer!"); 
                                }
                            }
                        }
                        // Did not find the line "popularity url"
                        if (!popUrl)
                        {
                            currentComments = arrSessions[x].oFlags["ui-comments"];
                            arrSessions[x].oFlags["ui-comments"] = currentComments + " (Alexa Rank: Unknown)";
                            arrSessions[x].RefreshUI();
                        }
                        sr.Close();
                        // Sleep for 2 seconds if there is more than 1 host to lookup
                        if (arrSessions.Length > 1 && x < arrSessions.Length -1)
                        {
                            Thread.Sleep(2000);
                        }
                    }
                }
                catch
                {
                    FiddlerApplication.UI.SetStatusText("EKFiddle: an error occured trying to get Alexa Rank");    
                }
                // Clean up Alexa sessions
                FiddlerObject.uiInvoke(EKFiddleTrimAlexaSessions);
                // Update status
                FiddlerApplication.UI.SetStatusText("All done checking Alexa Rank!");
                
            }).Start();
        }

        public static void OnBeforeRequest(Session oSession) 
        {
            // Sample Rule: Color ASPX requests in RED
            // if (oSession.uriContains(".aspx")) { oSession["ui-color"] = "red";   }

            // Sample Rule: Flag POSTs to fiddler2.com in italics
            // if (oSession.HostnameIs("www.fiddler2.com") && oSession.HTTPMethodIs("POST")) {  oSession["ui-italic"] = "yup";  }

            // Sample Rule: Break requests for URLs containing "/sandbox/"
            // if (oSession.uriContains("/sandbox/")) {
            //     oSession.oFlags["x-breakrequest"] = "yup";   // Existence of the x-breakrequest flag creates a breakpoint; the "yup" value is unimportant.
            // }
            
            
            if ((null != gs_ReplaceToken) && (oSession.url.IndexOf(gs_ReplaceToken)>-1))     // Case sensitive
            {
                oSession.url = oSession.url.Replace(gs_ReplaceToken, gs_ReplaceTokenWith); 
            }

            if ((null != gs_OverridenHost) && (oSession.host.ToLower() == gs_OverridenHost))
            {
                oSession["x-overridehost"] = gs_OverrideHostWith; 
            }

            if ((null!=bpRequestURI) && oSession.uriContains(bpRequestURI))
            {
                oSession["x-breakrequest"]="uri";
            }

            if ((null!=bpMethod) && (oSession.HTTPMethodIs(bpMethod)))
            {
                oSession["x-breakrequest"]="method";
            }

            if ((null!=uiBoldURI) && oSession.uriContains(uiBoldURI))
            {
                oSession["ui-bold"]="QuickExec";
            }

            if (m_SimulateModem)
            {
                // Delay sends by 300ms per KB uploaded.
                oSession["request-trickle-delay"] = "300"; 
                // Delay receives by 150ms per KB downloaded.
                oSession["response-trickle-delay"] = "150"; 
            }

            if (m_DisableCaching)
            {
                oSession.oRequest.headers.Remove("If-None-Match");
                oSession.oRequest.headers.Remove("If-Modified-Since");
                oSession.oRequest["Pragma"] = "no-cache";
            }

            // User-Agent Overrides
            if (null != sUA)
            {
                oSession.oRequest["User-Agent"] = sUA; 
            }

            // Accept-Language Overrides
            if (null != sAL)
            {
                oSession.oRequest["Accept-Language"] = sAL;
            }

            if (m_AutoAuth)
            {
                // Automatically respond to any authentication challenges using the 
                // current Fiddler user's credentials. You can change (default)
                // to a domain\\username:password string if preferred.
                //
                // WARNING: This setting poses a security risk if remote 
                // connections are permitted!
                oSession["X-AutoAuth"] = "(default)";
            }

            if (m_AlwaysFresh && (oSession.oRequest.headers.Exists("If-Modified-Since") || oSession.oRequest.headers.Exists("If-None-Match")))
            {
                oSession.utilCreateResponseAndBypassServer();
                oSession.responseCode = 304;
                oSession["ui-backcolor"] = "Lavender";
            }
            
            // Override default proxy, chain to uptream proxy if enabled by user
            if (FiddlerApplication.Prefs.GetStringPref("fiddler.defaultProxy", null) != "0")
            {
                oSession["X-OverrideGateway"] = FiddlerApplication.Prefs.GetStringPref("fiddler.defaultProxy", null);
            }
            
        }

        // This function is called immediately after a set of request headers has
        // been read from the client. This is typically too early to do much useful
        // work, since the body hasn't yet been read, but sometimes it may be useful.
        //
        // For instance, see 
        // http://blogs.msdn.com/b/fiddler/archive/2011/11/05/http-expect-continue-delays-transmitting-post-bodies-by-up-to-350-milliseconds.aspx
        // for one useful thing you can do with this handler.
        //
        // Note: oSession.requestBodyBytes is not available within this function!
        /*
        public static void OnPeekAtRequestHeaders(Session oSession) 
        {
            string sProc = oSession["x-ProcessInfo"].ToLower();
            if (!sProc.StartsWith("mylowercaseappname")) oSession["ui-hide"] = "NotMyApp";
        }
        */

        //
        // If a given session has response streaming enabled, then the OnBeforeResponse function 
        // is actually called AFTER the response was returned to the client.
        //
        // In contrast, this OnPeekAtResponseHeaders function is called before the response headers are 
        // sent to the client (and before the body is read from the server).  Hence this is an opportune time 
        // to disable streaming (oSession.bBufferResponse = true) if there is something in the response headers 
        // which suggests that tampering with the response body is necessary.
        // 
        // Note: oSession.responseBodyBytes is not available within this function!
        //
        public static void OnPeekAtResponseHeaders(Session oSession) 
        {
            //FiddlerApplication.Log.LogFormat("Session {0}: Response header peek shows status is {1}", oSession.id, oSession.responseCode);
            if (m_DisableCaching)
            {
                oSession.oResponse.headers.Remove("Expires");
                oSession.oResponse["Cache-Control"] = "no-cache";
            }

            if ((bpStatus>0) && (oSession.responseCode == bpStatus))
            {
                oSession["x-breakresponse"]="status";
                oSession.bBufferResponse = true;
            }

            if ((null!=bpResponseURI) && oSession.uriContains(bpResponseURI))
            {
                oSession["x-breakresponse"]="uri";
                oSession.bBufferResponse = true;
            }
        }

        public static void OnBeforeResponse(Session oSession)
        {
            if (m_Hide304s && oSession.responseCode == 304)
            {
                oSession["ui-hide"] = "true";
            }
            
            // EKFiddle real-time monitoring
            if (m_EKFiddleRealTime == true)
            {
                try
                {
                    // Re-initialize detectionName variable
                    string detectionName = "";
                    // Get current URI regardless of encoding
                    string currentURI = getCurrentURI(oSession);
                    // ** Check against URI regexes **
                    detectionName = checkURIRegexes(URIRegexesList, currentURI);
                    // ** Check against source code regexes **
                    if (detectionName == "" && (oSession.oResponse.headers.ExistsAndContains("Content-Type","text/html")
                        || oSession.oResponse.headers.ExistsAndContains("Content-Type","text/javascript")
                        || oSession.oResponse.headers.ExistsAndContains("Content-Type","text/plain")
                        || oSession.oResponse.headers.ExistsAndContains("Content-Type","application/javascript")
                        || oSession.oResponse.headers.ExistsAndContains("Content-Type","application/x-javascript"))
                        && oSession.fullUrl != "https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/Regexes/MasterRegexes.txt")
                    {                
                        oSession.utilDecodeRequest(true);
                        oSession.utilDecodeResponse(true);
                        string sourceCode = oSession.GetResponseBodyAsString().Replace('\0', '\uFFFD');
                        detectionName = checkSourceCodeRegexes(sourceCodeRegexesList, sourceCode);
                    }
                    // ** Check against headers regexes **
                    if (detectionName == "")
                    {
                        detectionName = checkHeadersRegexes(headersRegexesList, oSession.oResponse.headers.ToString());
                    }
                    // ** Check against IP regexes **
                    if (detectionName == "")
                    {   
                        detectionName = checkIPRegexes(IPRegexesList,oSession["x-hostIP"]);
                    }
                    ///////////////////////////////////////
                    // Flag session if a match was found
                    ///////////////////////////////////////
                    if (detectionName != "")
                    {                            
                        // Get the infection type
                        string fileType = fileTypeCheck(detectionName, oSession);
                        // Add info
                        EKFiddleAddInfo(oSession, detectionName, fileType);
                        // Play sound
                        System.Media.SystemSounds.Exclamation.Play();
                    }
                }
                catch
                {
                    FiddlerApplication.UI.SetStatusText("EKFiddle: Error with session " + oSession.id);    
                }
            }
        }

        // This function executes just before Fiddler returns an error that it has 
        // itself generated (e.g. "DNS Lookup failure") to the client application.
        // These responses will not run through the OnBeforeResponse function above.
        /*
        static void OnReturningError(Session oSession)
        {
        }
        */

        // This function executes after Fiddler finishes processing a Session, regardless
        // of whether it succeeded or failed. Note that this typically runs AFTER the last
        // update of the Web Sessions UI listitem, so you must manually refresh the Session's
        // UI if you intend to change it.
        /*
        static void OnDone(Session oSession)
        {
        }
        */
       
        public static void OnBoot()
        {          
            EKFiddleSanityCheck();
            EKFiddleVersionCheck();
            EKFiddleRegexesVersionCheck();
        }

        /*
        public static bool OnBeforeShutdown()
        {
            // Return false to cancel shutdown.
            return ((0 == FiddlerApplication.UI.lvSessions.TotalItemCount()) ||
                    (DialogResult.Yes == MessageBox.Show("Allow Fiddler to exit?", "Go Bye-bye?",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2)));
        }
        */

        /*
        public static void OnShutdown()
        {
            MessageBox.Show("Fiddler has shutdown");
        }
        */

        /*
        public static void OnAttach() 
        {
            MessageBox.Show("Fiddler is now the system proxy");
        }
        */

        /*
        public static void OnDetach() 
        {
            MessageBox.Show("Fiddler is no longer the system proxy");
        }
        */
        
        // Get request time (to add a new column)
        public static string getRequestTime(Session oSession)
        {
            return oSession.Timers.ClientBeginRequest.ToString();
        }
        
        // Get method (to add a new column)
        public static string getRequestMethod(Session oSession)
        {
            return oSession.RequestMethod;
        }
        
        public static void arrangeColumns() 
        { 
            // Add and reposition columns
            FiddlerApplication.UI.lvSessions.SetColumnOrderAndWidth("#", 0, 50);
            FiddlerApplication.UI.lvSessions.AddBoundColumn("Time", 1, 130, true, getRequestTime);
            FiddlerObject.UI.lvSessions.AddBoundColumn("Server IP", 2, 100, "X-HostIP");
            FiddlerObject.UI.lvSessions.AddBoundColumn("Server Type", 3, 100, "@response.server");
            FiddlerApplication.UI.lvSessions.SetColumnOrderAndWidth("Protocol", 4, 60);
            FiddlerObject.UI.lvSessions.AddBoundColumn("Method", 5, 60, getRequestMethod);
            FiddlerApplication.UI.lvSessions.SetColumnOrderAndWidth("Result", 6, 50);
            FiddlerApplication.UI.lvSessions.SetColumnOrderAndWidth("Host", 7, 200);
            FiddlerApplication.UI.lvSessions.SetColumnOrderAndWidth("URL", 8, 280);
            FiddlerApplication.UI.lvSessions.SetColumnOrderAndWidth("Body", 9, 60);
            FiddlerApplication.UI.lvSessions.SetColumnOrderAndWidth("Content-Type", 10, 100);
            FiddlerApplication.UI.lvSessions.SetColumnOrderAndWidth("Comments", 11, 220);
            FiddlerApplication.UI.lvSessions.SetColumnOrderAndWidth("Process", 12, 100);
            FiddlerApplication.Prefs.SetStringPref("fiddler.ui.layout.mode", "2");
        }

        // The Main() function runs everytime your FiddlerScript compiles
        public static void Main() 
        {     
            // Set to remove encoding by default
            FiddlerApplication.Prefs.SetStringPref("fiddler.ui.rules.removeencoding", "True");
            
            string today = DateTime.Now.ToShortTimeString();
            FiddlerApplication.UI.SetStatusText("EKFiddle was loaded at: " + today);

            // Uncomment to add a "Server" column containing the response "Server" header, if present
            // FiddlerApplication.UI.lvSessions.AddBoundColumn("Server", 0, 500, "@response.server");
            
            // Add and reposition columns for Advanced UI mode
            if (FiddlerApplication.Prefs.GetStringPref("fiddler.advancedUI", null) == "True")
            {
                arrangeColumns();
            }
            
            // Uncomment to add a global hotkey (Win+G) that invokes the ExecAction method below...
            // FiddlerApplication.UI.RegisterCustomHotkey(HotkeyModifiers.Windows, Keys.G, "screenshot"); 
        }
        
        public static void EKFiddleSanityCheck()
        {
            // Check if EKFiddle folder and regexes exist
            if (!System.IO.Directory.Exists(EKFiddlePath) || !System.IO.File.Exists(@EKFiddleRegexesPath + "MasterRegexes.txt") || !System.IO.File.Exists(@EKFiddleRegexesPath + "CustomRegexes.txt"))
            {   // Prompt user to install EKFiddle
                EKFiddleInstallation();
            }
        }
        
        public static void EKFiddleVersionCheck()
        {    
            // Set EKFiddle local version in 'Preferences'
            string EKFiddleVersion = "0.8.6.1";
            FiddlerApplication.Prefs.SetStringPref("fiddler.ekfiddleversion", EKFiddleVersion);
            // Update Fiddler's window title
            FiddlerApplication.UI.Text= "Progress Telerik Fiddler Web Debugger" + " - " + "EKFiddle v." + EKFiddleVersion;       
            // Check for EKFiddle updates
            try
            {
                WebClient EKFiddleVersionClient = new WebClient();
                Stream EKFiddleVersionInfoStream = EKFiddleVersionClient.OpenRead("https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/EKFiddleVersion.info");
                StreamReader EKFiddleVersionInfoReader = new StreamReader(EKFiddleVersionInfoStream);
                string EKFiddleLatestVersion = EKFiddleVersionInfoReader.ReadToEnd();
                EKFiddleVersionInfoReader.Close();

                var version1 = new Version(EKFiddleVersion);
                var version2 = new Version(EKFiddleLatestVersion);

                var result = version1.CompareTo(version2);
                if (result < 0)
                {   // A new version is available
                    // Read what's new
                    WebClient EKFiddleWhatsNewClient = new WebClient();
                    Stream EKFiddleWhatsNewStream = EKFiddleWhatsNewClient.OpenRead("https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/whatsnew.txt");
                    StreamReader EKFiddleWhatsNewReader = new StreamReader(EKFiddleWhatsNewStream);
                    string EKFiddleWhatsNew = EKFiddleWhatsNewReader.ReadToEnd();
                    EKFiddleVersionInfoReader.Close();
                    // Show dialog
                    DialogResult dialogEKFiddleUpdate = MessageBox.Show(EKFiddleWhatsNew + "\n" + "\n" + "Would you like to download it now?", "EKFiddle update from version " + version1 + " to " +  version2, MessageBoxButtons.YesNo, MessageBoxIcon.Information);
                    if(dialogEKFiddleUpdate == DialogResult.Yes)
                    {
                        // Download CustomRules.js
                        WebClient CustomRulesWebClient = new WebClient();
                        CustomRulesWebClient.DownloadFile("https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/CustomRules.cs", @FiddlerScriptsPath + "CustomRules.cs");
                        // Update Fiddler's title with new version number
                        FiddlerApplication.UI.Text="Progress Telerik Fiddler Web Debugger" + " | " + "@EKFiddle v." + EKFiddleLatestVersion;  
                        // Dialog to let user know the update installed successfully
                        MessageBox.Show("EKFiddle has been updated to version " + EKFiddleLatestVersion + "!!", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            }
            catch
            {
                MessageBox.Show("Failed to check for EKFiddle version updates!", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        public static bool EKFiddleRegexesVersionCheck()
        {  
            try
            {    // Check for regexes updates    
                if (EKFiddleRegexesInstalled() == false)
                {   // Prompt user to re-install EKFiddle if the regexes do not exist
                    MessageBox.Show("Regexes are missing and require EKFiddle to be re-installed." + "\n" + "\n" + "Click OK to proceed.", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    EKFiddleInstallation();
                }
                else
                {   
                    // Check local version
                    string RegexesLocalVersion = "";
                    foreach (var line in File.ReadAllLines(@EKFiddleRegexesPath + "MasterRegexes.txt"))
                    {
                        if (line.Contains("## Last updated: "))
                        {
                            RegexesLocalVersion = line.Replace("## Last updated: ", "");
                        }
                    }
                    // Check GitHub version
                    WebClient RegexesVersionClient = new WebClient();
                    Stream RegexesVersionInfoStream = RegexesVersionClient.OpenRead("https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/Regexes/RegexesVersion.info");
                    StreamReader RegexesVersionInfoReader = new StreamReader(RegexesVersionInfoStream);
                    string RegexesLatestVersion = RegexesVersionInfoReader.ReadToEnd();
                    RegexesVersionInfoReader.Close();
                    // Compare both
                    if (RegexesLocalVersion != RegexesLatestVersion)
                    {   // Prompt to download latest regexes
                        DialogResult dialogRegexesUpdate = MessageBox.Show("You are running MasterRegexes.txt (open-source rules) version " + RegexesLocalVersion + ". A new version (" + RegexesLatestVersion 
                         + ") is available!" + "\n" + "\n" + "Would you like to download it now?", "EKFiddle Regexes update", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
                        if(dialogRegexesUpdate == DialogResult.Yes)
                        {  
                            WebClient regexesWebClient = new WebClient();
                            regexesWebClient.DownloadFile("https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/Regexes/MasterRegexes.txt", @EKFiddleRegexesPath + "MasterRegexes.txt");
                            // Reload CustomRules
                            FiddlerObject.ReloadScript();
                            // Gather information about Master regexes file
                            var URIRegexCount = 0;
                            var sourceCodeRegexCount = 0;
                            var IPRegexCount = 0;
                            var headersRegexCount = 0;
                            // Read Master regexes file
                            using (var reader = new System.IO.StreamReader(@EKFiddleRegexesPath + "MasterRegexes.txt"))
                            {
                                while (!reader.EndOfStream)
                                {
                                    var line = reader.ReadLine();
                                    // Count number of URI regexes
                                    if (line.StartsWith("URI"))
                                    {
                                        URIRegexCount+=1;
                                    }
                                    // Count number of SourceCode regexes
                                    if (line.StartsWith("SourceCode"))
                                    {
                                        sourceCodeRegexCount+=1;
                                    }
                                    // Count number of IP regexes
                                    if (line.StartsWith("IP"))
                                    {
                                        IPRegexCount+=1;
                                    }
                                    // Count number of Headers regexes
                                    if (line.StartsWith("Headers"))
                                    {
                                        headersRegexCount+=1;
                                    }
                                }
                                reader.Close();
                            }
                            MessageBox.Show("MasterRegexes.txt has been updated to the latest version (" + RegexesLatestVersion + ")!" + 
                            "\n" + "\n" + "Total number of regexes: " + (URIRegexCount + sourceCodeRegexCount + IPRegexCount + headersRegexCount) + "\n" +
                            "-> URI: " + URIRegexCount + "\n" + "-> Source Code: " + sourceCodeRegexCount + "\n" + "-> IP: " + IPRegexCount + "\n" + "-> Headers: " + headersRegexCount, 
                            "EKFiddle Regexes update", MessageBoxButtons.OK, MessageBoxIcon.Information);
                            return true;
                        }
                        else
                        {
                            return false;
                        }
                    }
                    else
                    {
                        return true;    
                    }
                }
            }
            catch
            {
                MessageBox.Show("Failed to check for EKFiddle regexes updates!", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }
            return false;
        }
        
        // Check if EKFiddle's regexes are installed properly
        public static bool EKFiddleRegexesInstalled()
        {
            if (!System.IO.File.Exists(@EKFiddleRegexesPath + "MasterRegexes.txt") || !System.IO.File.Exists(@EKFiddleRegexesPath + "CustomRegexes.txt"))
            {   // Regexes are not installed properly
                return false;
            }
            else
            {   // Regexes are installed properly
                return true;
            }
        }
        
        // EKFiddle global variables
        
        // Regex thread default
        public static bool isRegexThreadRunning = false;
        
        // Check Operating System
        public static string checkOS()
        {
            if(Environment.OSVersion.ToString().Contains("Microsoft"))
            {   // This is a Windows OS
                string OSName = "Windows";
                return OSName;
            }
            else if (Environment.OSVersion.ToString().Contains("Unix") && !Directory.Exists("/Applications"))
            {   // This is Unix OS but not Mac OS
                string OSName = "Linux";
                return OSName;
            }
            else if (Environment.OSVersion.ToString().Contains("Unix") && Directory.Exists("/Applications"))
            {   // This is Mac OS
                string OSName = "Mac";
                return OSName;
            }
            else
            {   // Unknown OS
                MessageBox.Show("Could not determine OS!!!");
                string OSName = "";
                return OSName;
            }
        }
        
        // Set Fiddler path based on Operating System
        public static string setFiddlerScriptsPath()
        {
            // Check OS first
            checkOS();

            if(OSName == "Windows")
            {   // This is a Windows OS
                string FiddlerScriptsPath = Path.GetPathRoot(Environment.SystemDirectory) + "Users\\" + Environment.UserName + "\\Documents\\Fiddler2\\Scripts\\";
                return FiddlerScriptsPath;

            }
            else if (OSName == "Linux")
            {   // This is Unix OS but not Mac OS
                string FiddlerScriptsPath = "/home/" + Environment.UserName + "/Fiddler2/Scripts/";
                return FiddlerScriptsPath;
            }
            else if (OSName == "Mac")
            {   // This is Mac OS
                string FiddlerScriptsPath = "/Users/" + Environment.UserName + "/Fiddler2/Scripts/";
                return FiddlerScriptsPath;
            }
            else
            {   // Unknown OS
                string FiddlerScriptsPath = "";
                return FiddlerScriptsPath;
            }
        }
        
        // Set installation folder for EKFiddle based on Operating System
        public static string setEKFiddlePath()
        {
            // Check OS first
            checkOS();

            if(OSName == "Windows")
            {   // This is a Windows OS
                string EKFiddlePath = Path.GetPathRoot(Environment.SystemDirectory) + "Users\\" + Environment.UserName + "\\Documents\\Fiddler2\\EKFiddle\\";
                return EKFiddlePath;

            }
            else if (OSName == "Linux")
            {   // This is Unix OS but not Mac OS
                string EKFiddlePath = "/home/" + Environment.UserName + "/Fiddler2/EKFiddle/";
                return EKFiddlePath;
            }
            else if (OSName == "Mac")
            {   // This is Mac OS
                string EKFiddlePath = "/Users/" + Environment.UserName + "/Fiddler2/EKFiddle/";
                return EKFiddlePath;
            }
            else
            {   // Unknown OS
                string EKFiddlePath = "";
                return EKFiddlePath;
            }
        }
        
        // Set Regexes folder for EKFiddle based on Operating System
        public static string setEKFiddleRegexesPath()
        {
            // Check OS first
            checkOS();

            if(OSName == "Windows")
            {   // This is a Windows OS
                string EKFiddleRegexesPath = Path.GetPathRoot(Environment.SystemDirectory) + "Users\\" + Environment.UserName + "\\Documents\\Fiddler2\\EKFiddle\\Regexes\\";
                return EKFiddleRegexesPath;

            }
            else if (OSName == "Linux")
            {   // This is Unix OS but not Mac OS
                string EKFiddleRegexesPath = "/home/" + Environment.UserName + "/Fiddler2/EKFiddle/Regexes/";
                return EKFiddleRegexesPath;
            }
            else if (OSName == "Mac")
            {   // This is Mac OS
                string EKFiddleRegexesPath = "/Users/" + Environment.UserName + "/Fiddler2/EKFiddle/Regexes/";
                return EKFiddleRegexesPath;
            }
            else
            {   // Unknown OS
                string EKFiddleRegexesPath = "";
                return EKFiddleRegexesPath;
            }
        }
        
        // Set traffic captures folder for EKFiddle based on Operating System
        public static string setEKFiddleCapturesPath()
        {
            // Check OS first
            checkOS();

            if(OSName == "Windows")
            {   // This is a Windows OS
                string EKFiddleCapturesPath = Path.GetPathRoot(Environment.SystemDirectory) + "Users\\" + Environment.UserName + "\\Documents\\Fiddler2\\EKFiddle\\Captures\\";
                return EKFiddleCapturesPath;

            }
            else if (OSName == "Linux")
            {   // This is Unix OS but not Mac OS
                string EKFiddleCapturesPath = "/home/" + Environment.UserName + "/Fiddler2/EKFiddle/Captures/";
                return EKFiddleCapturesPath;
            }
            else if (OSName == "Mac")
            {   // This is Mac OS
                string EKFiddleCapturesPath = "/Users/" + Environment.UserName + "/Fiddler2/EKFiddle/Captures/";
                return EKFiddleCapturesPath;
            }
            else
            {   // Unknown OS
                string EKFiddleCapturesPath = "";
                return EKFiddleCapturesPath;
            }
        }
        
        // Set dumped files folder for EKFiddle based on Operating System
        public static string setEKFiddleArtifactsPath()
        {
            // Check OS first
            checkOS();
            
            if(OSName == "Windows")
            {   // This is a Windows OS
                string EKFiddleArtifactsPath   = Path.GetPathRoot(Environment.SystemDirectory) + "Users\\" + Environment.UserName + "\\Documents\\Fiddler2\\EKFiddle\\Artifacts\\";
                return EKFiddleArtifactsPath  ;

            }
            else if (OSName == "Linux")
            {   // This is Unix OS but not Mac OS
                string EKFiddleArtifactsPath   = "/home/" + Environment.UserName + "/Fiddler2/EKFiddle/Artifacts/";
                return EKFiddleArtifactsPath  ;
            }
            else if (OSName == "Mac")
            {   // This is Mac OS
                string EKFiddleArtifactsPath   = "/Users/" + Environment.UserName + "/Fiddler2/EKFiddle/Artifacts/";
                return EKFiddleArtifactsPath  ;
            }
            else
            {   // Unknown OS
                string EKFiddleArtifactsPath   = "";
                return EKFiddleArtifactsPath  ;
            }
        }
        
        // Set OpenVPN folder for EKFiddle based on Operating System
        public static string setEKFiddleOpenVPNPath()
        {
            // Check OS first
            checkOS();
            
            if(OSName == "Windows")
            {   // This is a Windows OS
                if (System.IO.Directory.Exists(@"C:\Program Files\OpenVPN"))
                {   // Path for 64 bit OpenVPN
                    string EKFiddleOpenVPNPath = "C:\\Program Files\\OpenVPN";
                    return EKFiddleOpenVPNPath;
                }
                else if (System.IO.Directory.Exists(@"C:\Program Files (x86)\OpenVPN"))
                {    // Path for 32 bit OpenVPN
                    string EKFiddleOpenVPNPath = "C:\\Program Files (x86)\\OpenVPN";
                    return EKFiddleOpenVPNPath;
                }
                else
                {
                    string EKFiddleOpenVPNPath = "";
                    return EKFiddleOpenVPNPath;
                }
            }
            else if (OSName == "Linux")
            {   // This is Unix OS but not Mac OS
                string EKFiddleOpenVPNPath = "/etc/openvpn";
                return EKFiddleOpenVPNPath;
            }
            else if (OSName == "Mac")
            {   // This is Mac OS
                string EKFiddleOpenVPNPath = "";
                return EKFiddleOpenVPNPath;
            }
            else
            {   // Unknown OS
                string EKFiddleOpenVPNPath = "";
                return EKFiddleOpenVPNPath;
            }
        }

        // Set default text editor in case there isn't one
        public static string setEKFiddleRegexesEditor()
        {
            if (FiddlerApplication.Prefs.GetStringPref("fiddler.config.path.TextEditor", null) == null)
            {
                if (OSName == "Windows")
                {
                    FiddlerApplication.Prefs.SetStringPref("fiddler.config.path.TextEditor", "notepad.exe");
                }
                else if (OSName == "Linux")
                {
                    FiddlerApplication.Prefs.SetStringPref("fiddler.config.path.TextEditor", "gedit");
                }
                else if (OSName == "Mac")
                {
                    FiddlerApplication.Prefs.SetStringPref("fiddler.config.path.TextEditor", "/Applications/TextEdit.app");
                }
                else
                {
                    FiddlerApplication.Prefs.SetStringPref("fiddler.config.path.TextEditor", "notepad.exe");
                }
                string EKFiddleRegexesEditor = FiddlerApplication.Prefs.GetStringPref("fiddler.config.path.TextEditor", null);
                return EKFiddleRegexesEditor;
            }
            else
            {
                string EKFiddleRegexesEditor = FiddlerApplication.Prefs.GetStringPref("fiddler.config.path.TextEditor", null);
                return EKFiddleRegexesEditor;
            }
        }

        // Set default xterm PID
        public static int setDefaultxtermId()
        {
            int xtermProcId = 0;
            return xtermProcId;
        }
        
        public static string setEKFiddleProxy()
        {
            FiddlerApplication.Prefs.SetStringPref("fiddler.defaultProxy", "0");
            return EKFiddleProxy;
        }

        // Connect-the-dots
        public static void connectDots(int payloadSessionId, string currentHostname, string currentURI, List<int> maliciousSessionsList)
        {        
            try
                {
                    string currentHostnameInHex;
                    string currentHostnameInHexPercent;
                    string currentHostnameChunked;
                    string currentURIInBase64;
                    currentHostnameInHex = hostnameInHex(currentHostname);
                    currentHostnameInHexPercent = hostnameInHexPercent(currentHostname);
                    currentURIInBase64 = URIInBase64(currentURI);
                    // Get the hostname without TLD
                    currentHostnameChunked = hostnameChunked(currentHostname);
                    // Create a new list of session IDs
                    List<int> sequenceList = new List<int>();
                    sequenceList.Add(payloadSessionId);
                    // Select all sessions of interest *before* current session ID
                    FiddlerObject.UI.actSelectSessionsMatchingCriteria(
                    delegate(Session oS)
                    {
                        return (oS.id < payloadSessionId);
                    });
                    var arrSelectedSessions = FiddlerApplication.UI.GetSelectedSessions();
                    FiddlerApplication.UI.SetStatusText("Connecting the dots...");
                    // Loop through sessions before current ID
                    for (int x = arrSelectedSessions.Length; x --> 0;)
                    {
                        // Define current source code and path in URI
                        // Decode session
                        arrSelectedSessions[x].utilDecodeRequest(true);
                        arrSelectedSessions[x].utilDecodeResponse(true);
                        var sourceCode = "";
                        try
                        {    // Some traffic captures (i.e. PCAPs) are corrupt. This allows us to proceed gracefully
                            sourceCode = arrSelectedSessions[x].GetResponseBodyAsString().Replace('\0', '\uFFFD');
                        }
                        catch
                        {
                            FiddlerApplication.UI.SetStatusText("EKFiddle: Could not decode session's Response Body");    
                        }
                        var foundMatch = false;
                        // Exclude/include certain kinds of sessions in sequence to focus on most relevant ones
                        if (!arrSelectedSessions[x].uriContains("urs.microsoft.com/") && !arrSelectedSessions[x].uriContains("http://api.bing.com/")
                            && !arrSelectedSessions[x].uriContains("https://www.google.") && !arrSelectedSessions[x].uriContains("/favicon.ico")
                            && !arrSelectedSessions[x].oResponse.headers.ExistsAndContains("Content-Type", "text/css")
                            && (arrSelectedSessions[x].oResponse.headers.ExistsAndContains("Content-Type", "text")
                                || arrSelectedSessions[x].oResponse.headers.ExistsAndContains("Content-Type", "application")
                                || !arrSelectedSessions[x].oResponse.headers.Exists("Content-Type"))
                            )
                        {
                            // Search within headers
                            if (arrSelectedSessions[x].oResponse.headers.ExistsAndContains("Location", currentHostname))
                            {
                                foundMatch = true;
                            }
                            // Search within domain name
                            if (foundMatch == false && arrSelectedSessions[x].hostname == currentHostname)
                            {
                                foundMatch = true;
                            }
                            // Search within source code if session's body size is > 0
                            if (foundMatch == false && arrSelectedSessions[x].responseBodyBytes.Length > 0)
                            {
                                if (sourceCode.IndexOf(currentHostname, 0, StringComparison.CurrentCultureIgnoreCase) != -1 
                                 || sourceCode.IndexOf(currentHostnameInHex, 0, StringComparison.CurrentCultureIgnoreCase) != -1
                                 || sourceCode.IndexOf(currentHostnameInHexPercent, 0, StringComparison.CurrentCultureIgnoreCase) != -1
                                 || sourceCode.IndexOf(currentHostnameChunked, 0, StringComparison.CurrentCultureIgnoreCase) != -1
                                 || sourceCode.IndexOf(currentURIInBase64, 0, StringComparison.CurrentCultureIgnoreCase) != -1)
                                {
                                    foundMatch = true;
                                }
                            }
                            if (foundMatch == true)
                            {
                                // Add to sequence list
                                sequenceList.Add(arrSelectedSessions[x].id);
                                // Assign new current domain name/URI to look for next
                                currentHostname = arrSelectedSessions[x].hostname;
                                currentHostnameInHex = hostnameInHex(currentHostname);
                                currentHostnameInHexPercent = hostnameInHexPercent(currentHostname);
                                currentHostnameChunked = hostnameChunked(currentHostname);
                                currentURIInBase64 = URIInBase64(arrSelectedSessions[x].fullUrl);
                            }
                        }
                    }
                    // Second pass to add the sequence numbers
                    var totalSequenceSessions = sequenceList.Count;
                    var currentSequencePos = totalSequenceSessions;
                    // Select all sessions of interest including current session ID
                    FiddlerObject.UI.actSelectSessionsMatchingCriteria(
                    delegate(Session oS)
                    {
                        return (oS.id <= payloadSessionId);
                    });
                    arrSelectedSessions = FiddlerApplication.UI.GetSelectedSessions();
                    // Loop through selected sessions
                    foreach (var sequenceSessionId in sequenceList)
                    {
                        bool alreadyExists = maliciousSessionsList.Contains(sequenceSessionId);
                        if (alreadyExists == false)
                        {
                            maliciousSessionsList.Add(sequenceSessionId);
                        }
                        //  in reverse order
                        for (int x = arrSelectedSessions.Length; x --> 0;)
                        {   
                            // Identify the match
                            if (arrSelectedSessions[x].id == sequenceSessionId)
                            {                
                                if (arrSelectedSessions[x].oFlags["ui-comments"] == null || arrSelectedSessions[x].oFlags["ui-comments"] == "")
                                {
                                    arrSelectedSessions[x].oFlags["ui-comments"] = "(" + currentSequencePos.ToString("D2") + ")";
                                    arrSelectedSessions[x].oFlags["ui-color"] = "black";
                                    arrSelectedSessions[x].oFlags["ui-backcolor"] = "#8bff7e";
                                }
                                else if (arrSelectedSessions[x].oFlags["ui-comments"].StartsWith("[#"))
                                {
                                    arrSelectedSessions[x].oFlags["ui-comments"] = "(" + currentSequencePos.ToString("D2") + ")";
                                    arrSelectedSessions[x].oFlags["ui-color"] = "black";
                                    arrSelectedSessions[x].oFlags["ui-backcolor"] = "#8bff7e";
                                }
                                else if (!arrSelectedSessions[x].oFlags["ui-comments"].StartsWith("("))
                                {
                                    arrSelectedSessions[x].oFlags["ui-comments"] = "(" + currentSequencePos.ToString("D2") + ") " + arrSelectedSessions[x].oFlags["ui-comments"];
                                }
                                // Refresh UI
                                arrSelectedSessions[x].RefreshUI();
                                // Decrease our current position within the list
                                currentSequencePos -= 1;
                            }
                        }
                    }
                    // Clear selection
                    FiddlerApplication.UI.lvSessions.SelectedItems.Clear();
                }
                catch
                {
                    FiddlerApplication.UI.SetStatusText("EKFiddle: Oops, an error occured.");
                }
        }
        
        // Load IP Regexes
        public static List <string> setLoadIPRegexes() 
        {
            List <string> IPRegexesList = new List<string>();
            if (EKFiddleRegexesInstalled() == true)
            {   // Regexes are properly installed
                string[] regexFiles = new string[2];
                regexFiles[0] = "CustomRegexes.txt";
                regexFiles[1] = "MasterRegexes.txt";
                foreach (string s in regexFiles)
                {
                    using (var reader = new System.IO.StreamReader(@EKFiddleRegexesPath + s))
                    {
                        while (!reader.EndOfStream)
                        {
                            var line = reader.ReadLine();
                            if (line.StartsWith("IP"))
                            {   // Add to IP Regex list
                                IPRegexesList.Add(line);
                            }    
                        }
                        reader.Close();
                    }
                }
            }
            return IPRegexesList;
        }
        
        // Load URI Regexes
        public static List <string> setLoadURIRegexes() 
        {
            List <string> URIRegexesList = new List<string>();
            if (EKFiddleRegexesInstalled() == true)
            {   // Regexes are properly installed
                string[] regexFiles = new string[2];
                regexFiles[0] = "CustomRegexes.txt";
                regexFiles[1] = "MasterRegexes.txt";
                foreach (string s in regexFiles)
                {
                    using (var reader = new System.IO.StreamReader(@EKFiddleRegexesPath + s))
                    {
                        while (!reader.EndOfStream)
                        {
                            var line = reader.ReadLine();
                            if (line.StartsWith("URI"))
                            {   // Add to URI Regex list
                                URIRegexesList.Add(line);
                            }    
                        }
                        reader.Close();
                    }
                }
            }
            return URIRegexesList;
        }
        
        // Load source code Regexes
        public static List <string> setLoadSourceCodeRegexes() 
        {
            List <string> sourceCodeRegexesList = new List<string>();
            if (EKFiddleRegexesInstalled() == true)
            {   // Regexes are properly installed
                string[] regexFiles = new string[2];
                regexFiles[0] = "CustomRegexes.txt";
                regexFiles[1] = "MasterRegexes.txt";
                foreach (string s in regexFiles)
                {
                    using (var reader = new System.IO.StreamReader(@EKFiddleRegexesPath + s))
                    {
                        while (!reader.EndOfStream)
                        {
                            var line = reader.ReadLine();
                            if (line.StartsWith("SourceCode"))
                            {   // Add to SourceCode Regex list
                                sourceCodeRegexesList.Add(line);
                            }    
                        }
                        reader.Close();
                    }
                }
            }
            return sourceCodeRegexesList;
        }
        
        // Load headers Regexes
        public static List <string> setLoadHeadersRegexes() 
        {
            List <string> headersRegexesList = new List<string>();
            if (EKFiddleRegexesInstalled() == true)
            {   // Regexes are properly installed
                string[] regexFiles = new string[2];
                regexFiles[0] = "CustomRegexes.txt";
                regexFiles[1] = "MasterRegexes.txt";
                foreach (string s in regexFiles)
                {
                    using (var reader = new System.IO.StreamReader(@EKFiddleRegexesPath + s))
                    {
                        while (!reader.EndOfStream)
                        {
                            var line = reader.ReadLine();
                            if (line.StartsWith("Headers"))
                            {   // Add to Headers Regex list
                                headersRegexesList.Add(line);
                            }    
                        }
                        reader.Close();
                    }
                }
            }
            return headersRegexesList;
        }
        
        public static void EKFiddleStartCrawler()
        {        
        // Check that the OS is Windows
            if (OSName == "Windows")
            {
                // Create file open dialog
                var openCapture = new OpenFileDialog();
                openCapture.Filter = "TXT files (*.txt)|*.txt|All files (*.*)|*.*";
                openCapture.ShowDialog();
                if (openCapture.FileName != "")
                {
                    // Count number of lines (URLs) in text file
                    var urlCount = 0;
                    using (var reader = File.OpenText(openCapture.FileName))
                    {
                        while (reader.ReadLine() != null)
                        {
                            urlCount++;
                        }
                        reader.Close();
                    }
                    // Ask for delay value
                    int delay = Int32.Parse(FiddlerObject.prompt("Please enter the time (in ms) to wait between each URL crawl:" + "\n" + "(default is 20 seconds)", "20000", "Delay"));
                    // Ask for browser info
                    string browser = FiddlerObject.prompt("Please enter the browser you want to use:" + "\n" + "(default is Internet Explorer)" + "\n" + "- Chrome" + "\n" + "- Firefox" + "\n" + "- Edge", "IE", "Browser");
                    // Adapt input name to process name
                    if (browser== "chrome" || browser== "Chrome")
                    {
                        browser = "chrome.exe";
                    }
                    if (browser== "IE" || browser== "ie")
                    {
                        browser = "iexplore.exe";
                    }
                    if (browser== "firefox" || browser== "Firefox" || browser== "ff" || browser== "FF")
                    {
                        browser = "firefox.exe";
                    }
                    if (browser== "edge" || browser== "Edge")
                    {
                        browser = "microsoft-edge";
                    }
                    // Run crawler only if process name is valid
                    if (browser == "chrome.exe" || browser == "iexplore.exe" || browser == "firefox.exe" || browser == "microsoft-edge")
                    {
                        // Turn flag on
                        FiddlerApplication.Prefs.SetBoolPref("fiddler.ekfiddleCrawl", true);
                        // Crawl
                        new Thread(() => 
                        {
                            Thread.CurrentThread.IsBackground = true;
                            // Initialize URL index
                            int urlindex = 1;
                            foreach (var line in File.ReadAllLines(openCapture.FileName))
                            {
                               // Start crawling
                               try
                               {
                                   if (browser == "microsoft-edge")
                                   {
                                          System.Diagnostics.Process.Start(browser + ":" + line); 
                                   }else{
                                       System.Diagnostics.Process.Start(browser, line);
                                   }
                               }catch{
                                   MessageBox.Show("Could not launch " + browser + "!", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                                   break;
                               }
                               FiddlerApplication.UI.SetStatusText("Crawler: " + urlindex + " out of " + urlCount + " URLs. " + "Current URL: " + line);
                               // Delay
                               System.Threading.Thread.Sleep(delay);
                               // Kill browser
                               if (browser == "microsoft-edge")
                               {
                                   // Kill Edge browser
                                   EKFiddleKillEdge();
                               }else{
                                   // Kill other browsers
                                   EKFiddleKillBrowsers(browser);
                               }
                               // Check crawler status
                               if (!FiddlerApplication.Prefs.GetBoolPref("fiddler.ekfiddleCrawl", false))
                               {
                                   // Kill browser
                                   if (browser == "microsoft-edge")
                                   {
                                       // Kill Edge browser
                                       EKFiddleKillEdge();
                                   }else{
                                       // Kill other browsers
                                       EKFiddleKillBrowsers(browser);
                                   }
                                   MessageBox.Show("Crawler has been stopped.", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
                                   break;
                               }
                               // Increment URL index
                               urlindex++;
                            }
                            FiddlerApplication.UI.SetStatusText("All done crawling " + urlCount + " URLs!");
                        }).Start();
                    // Wrong browser input  
                    }else{
                        MessageBox.Show("Not a valid browser name!", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                }
            // Wrong OS    
            }else{
                MessageBox.Show("This feature is only available on Windows! If you are interested in a Linux version, please let me know :)", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }
        
        public static void EKFiddleKillEdge()
        { 
            // Kill Edge browser
            try
            {
                // Kill all Edge processes
                foreach (var process in Process.GetProcessesByName("MicrosoftEdge"))
                {
                    process.Kill();
                }
                // Sleep 2 seconds
                System.Threading.Thread.Sleep(2000);
                // Delete crash recovery tabs
                string recoveryFolder = Path.GetPathRoot(Environment.SystemDirectory) + "Users\\" + Environment.UserName + 
                                        "\\AppData\\Local\\Packages\\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\AC\\MicrosoftEdge\\User\\Default\\Recovery\\Active";
                System.IO.DirectoryInfo di = new DirectoryInfo(recoveryFolder);
                foreach (FileInfo file in di.GetFiles())
                {
                    file.Delete(); 
                }
                // Sleep 2 seconds
                System.Threading.Thread.Sleep(2000);
                }catch{
                    FiddlerApplication.UI.SetStatusText("Failed to stop browser...");
                }
        }
        
        public static void EKFiddleKillBrowsers(string browser)
        {
            try
            {
                foreach (var process in Process.GetProcessesByName(browser.Replace(".exe","")))
                {
                    process.Kill();
                }
                System.Threading.Thread.Sleep(2000);
            }catch{
                FiddlerApplication.UI.SetStatusText("Failed to stop browser...");
            }
        }
        
        public static void EKFiddleTrimAlexaSessions()
        {
            // Clean up sessions generated from Alexa lookup
            FiddlerApplication.UI.actSelectSessionsMatchingCriteria(
            delegate(Session oS)
            {
                oS.RefreshUI();
                return (oS.uriContains("data.alexa.com/data?cli=10&dat=snbamz&url=") || (oS.HTTPMethodIs("CONNECT") && ("data.alexa.com" == oS.host)));
            });
            FiddlerApplication.UI.actRemoveSelectedSessions();
            FiddlerApplication.UI.lvSessions.SelectedItems.Clear();
        }
        
        public static void DoFiddlerTheme(string fiddlerIcon, string fiddlerSaz) 
        {
            // Check OS
            if(OSName == "Windows")
            {
                
                bool failedwnl = false;
                
                // Create themes directory
                System.IO.Directory.CreateDirectory(EKFiddlePath + "Themes");
                
                // Download icons to EKFiddle directory
                try
                {    // Download Fiddler's app icon
                    WebClient myWebClient = new WebClient();
                    myWebClient.DownloadFile("https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/Themes/" + fiddlerIcon, @EKFiddlePath + "Themes" + "\\" + fiddlerIcon);
                }
                catch
                {
                    failedwnl = true;
                    MessageBox.Show("Failed to download Fiddler's app icon!", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }

                try
                {   // Download Fiddler's SAZ icon
                    WebClient myWebClient = new WebClient();
                    myWebClient.DownloadFile("https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/Themes/" + fiddlerSaz, @EKFiddlePath + "Themes" + "\\" + fiddlerSaz);
                }
                catch
                {
                    failedwnl = true;
                    MessageBox.Show("Failed to download Fiddler's SAZ icon!", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
                
                if (failedwnl == false)
                {
                    // Change Fiddler's defaut app icon
                    FiddlerApplication.Prefs.SetStringPref("fiddler.ui.overrideIcon", EKFiddlePath + "Themes" + "\\" + fiddlerIcon);
                    
                    // Change Fiddler's default SAZ icon
                    RegistryKey myKey = Registry.ClassesRoot.OpenSubKey("Fiddler.ArchiveZip\\DefaultIcon", true);
                    if(myKey != null)    {
                       myKey.SetValue("", EKFiddlePath + "Themes" + "\\" + fiddlerSaz, RegistryValueKind.String);
                       myKey.Close();
                    }
                    
                    // Prompt user for reboot
                    MessageBox.Show("Please restart your system to apply those changes!", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    
                }else{
                    MessageBox.Show("Theme was not applied!", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
                
            }else{
                MessageBox.Show("This Operating System is not supported!", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }
        
        // Call functions that set overall variables
        public static string OSName = checkOS();
        public static string FiddlerScriptsPath = setFiddlerScriptsPath();
        public static string EKFiddlePath = setEKFiddlePath();
        public static string EKFiddleRegexesPath = setEKFiddleRegexesPath();
        public static string EKFiddleCapturesPath = setEKFiddleCapturesPath();
        public static string EKFiddleArtifactsPath = setEKFiddleArtifactsPath();
        public static string EKFiddleOpenVPNPath = setEKFiddleOpenVPNPath();
        public static string EKFiddleRegexesEditor = setEKFiddleRegexesEditor();
        public static int xtermProcId = setDefaultxtermId();
        public static string EKFiddleProxy = setEKFiddleProxy();
        public static List <string> IPRegexesList = setLoadIPRegexes();
        public static List <string> URIRegexesList = setLoadURIRegexes();
        public static List <string> sourceCodeRegexesList = setLoadSourceCodeRegexes();
        public static List <string> headersRegexesList = setLoadHeadersRegexes();

        // Install EKFiddle
        public static void EKFiddleInstallation()
        {            
            MessageBox.Show("This will install or update EKFiddle to the latest version.", "EKFiddle installation/update", MessageBoxButtons.OK, MessageBoxIcon.Information);
            // Delete regex files used in previous version of EKFiddle
            try
            {
                File.Delete(@EKFiddleRegexesPath + "HeadersRegexes.txt");
                File.Delete(@EKFiddleRegexesPath + "SourceCodeRegexes.txt");
                File.Delete(@EKFiddleRegexesPath + "URIRegexes.txt");
            }
            catch
            {
                FiddlerApplication.UI.SetStatusText("Previous regex files not found");
            }
            // Create directories
            System.IO.Directory.CreateDirectory(EKFiddlePath);
            System.IO.Directory.CreateDirectory(EKFiddleRegexesPath);
            System.IO.Directory.CreateDirectory(EKFiddleCapturesPath);
            System.IO.Directory.CreateDirectory(EKFiddleArtifactsPath);
            // Download latest regexes
            try
            {
                WebClient myWebClient = new WebClient();
                myWebClient.DownloadFile("https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/Regexes/MasterRegexes.txt", @EKFiddleRegexesPath + "MasterRegexes.txt");
            }
            catch
            {
                MessageBox.Show("Failed to download regexes!", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            // Create custom (blank) regexes file (if it does not already exist)
            if (!System.IO.File.Exists(@EKFiddleRegexesPath + "CustomRegexes.txt"))
            {
                System.IO.StreamWriter customRegexes = new System.IO.StreamWriter(EKFiddleRegexesPath + "CustomRegexes.txt");
                customRegexes.WriteLine("## This is your custom regexes file");
                customRegexes.WriteLine("## Usage: [Type] TAB [Regex name] TAB [Regex] TAB [Ref/comment (optional)]");
                customRegexes.WriteLine("##  where Type can be: IP/URI/SourceCode/Headers");
                customRegexes.WriteLine("## Examples:");
                customRegexes.WriteLine("##  IP" + "\t" + "My_IP_address_rule" + "\t" + "5\\.154\\.191\\.67" + "\t" + "will match a static IP address (5.154.191.67)");
                customRegexes.WriteLine("##  IP" + "\t" + "My_IP_address_rule" + "\t" + "5\\.154\\.191\\.(6[0-9]|70)" + "\t" + "will match an IP range (5.154.191.60 to 5.154.191.70)");
                customRegexes.WriteLine("##  URI" + "\t" + "My_URI_rule" + "\t" + "[a-z0-9]{2}" + "\t" + "simple URI regex");
                customRegexes.WriteLine("##  SourceCode" + "\t" + "My_sourcecode_rule" + "\t" + "vml=1" + "\t" + "will look for the specified string inside the HTML/JS");
                customRegexes.WriteLine("##  Headers" + "\t" + "My_headers_rule" + "\t" + "nginx" + "\t" + "will check for the string inside the response headers");
                customRegexes.Close();
            }
            // Set Advanced UI mode to its default setting (false)
            FiddlerApplication.Prefs.SetStringPref("fiddler.advancedUI", "False");
            // Reload CustomRules
            FiddlerObject.ReloadScript();
            // Dialog showing installation is done
            MessageBox.Show("EKFiddle has been installed successfully!", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        // Check against URL regexes
        public static string checkURIRegexes(List <string> URIRegexesList, string currentURI)
        {
            string detectionName = "";
            foreach (string item in URIRegexesList)
            {
                Regex UrlPattern = new Regex(item.Split('\t')[2]);                            
                string URIRegexName = item.Split('\t')[1];
                MatchCollection matches = UrlPattern.Matches(currentURI);
                if (matches.Count > 0)
                {                            
                    detectionName = URIRegexName + " " + "(URI)";
                    break;
                }
            }
            return detectionName;
        }

        // Check against source code regexes
        public static string checkSourceCodeRegexes(List <string> sourceCodeRegexesList, string sourceCode)
        {
            string detectionName = "";
            // Check against source code patterns
            foreach (string item in sourceCodeRegexesList)
            {
                Regex sourceCodePattern = new Regex(item.Split('\t')[2]);
                string sourceCodeRegexName = item.Split('\t')[1];
                MatchCollection matches = sourceCodePattern.Matches(sourceCode);
                if (matches.Count > 0)
                {                            
                    detectionName = sourceCodeRegexName + " " + "(HTML/JS)";
                    break;
                }
            }
            return detectionName;
        }
        
        // Check against headers regexes
        public static string checkHeadersRegexes(List <string> headersRegexesList, string fullResponseHeaders)
        {
            string detectionName = "";
            foreach (string item in headersRegexesList)
            {
                Regex headerPattern = new Regex(item.Split('\t')[2]);
                string headerRegexName = item.Split('\t')[1];
                MatchCollection matches = headerPattern.Matches(fullResponseHeaders);
                if (matches.Count > 0)
                {                            
                    detectionName = headerRegexName + " " + "(Headers)";
                    break;
                }
            }
            return detectionName;
        }
        
        // Check against IP regexes
        public static string checkIPRegexes(List <string> IPRegexesList, string currentIP)
        {
            string detectionName = "";
            foreach (string item in IPRegexesList)
            {
                Regex IPPattern = new Regex(item.Split('\t')[2]);                            
                string IPRegexName = item.Split('\t')[1];
                MatchCollection matches = IPPattern.Matches(currentIP);
                if (matches.Count > 0)
                {                            
                    detectionName = IPRegexName + " " + "(IP)";
                    break;
                }
            }
            return detectionName;
        }
        
        public static string getCurrentURI(Session oSession)
        {
            // Get current URI regardless of encoding
            byte[] utfBytes = Encoding.UTF8.GetBytes(oSession.fullUrl);
            string hexValue = BitConverter.ToString(utfBytes);
            hexValue = hexValue.Replace("-", "");
            string currentURI = hexToString(hexValue);
            return currentURI;
        }
        
        public static string URIInBase64(string currentURI)
        {
            // Get current URI in base64 format
            byte[] plainTextBytesURI = Encoding.UTF8.GetBytes(currentURI);
            string currentURIInBase64 = System.Convert.ToBase64String(plainTextBytesURI).Replace("=", "");
            return currentURIInBase64;
        }
        
        public static string hostnameInHex(string currentHostname)
        { 
            byte[] ba = Encoding.Default.GetBytes(currentHostname);
            var currentHostnameInHex = BitConverter.ToString(ba);
            currentHostnameInHex = currentHostnameInHex.Insert(0, "\\x");
            currentHostnameInHex = currentHostnameInHex.Replace("-", "\\x");
            return currentHostnameInHex;
        }
        
        public static string hostnameInHexPercent(string currentHostname)
        { 
            byte[] ba = Encoding.Default.GetBytes(currentHostname);
            var currentHostnameInHexPercent = BitConverter.ToString(ba);
            currentHostnameInHexPercent = currentHostnameInHexPercent.Insert(0, "%");
            currentHostnameInHexPercent = currentHostnameInHexPercent.Replace("-", "%");
            return currentHostnameInHexPercent;
        }
        
        public static string URIInHex(string currentURI)
        { 
            Encoding utf8 = Encoding.UTF8;
            byte[] ba = utf8.GetBytes(currentURI);
            var currentURIInHex = BitConverter.ToString(ba);
            currentURIInHex = currentURIInHex.Insert(0, "\\x");
            currentURIInHex = currentURIInHex.Replace("-00", "");
            currentURIInHex = currentURIInHex.Replace("-", "\\x");
            return currentURIInHex;
        }
        
         public static string hexToString(string hexValue)
        {
            string stringValue = "";
            while (hexValue.Length > 0)
            {
                stringValue += System.Convert.ToChar(System.Convert.ToUInt32(hexValue.Substring(0, 2), 16)).ToString();
                hexValue = hexValue.Substring(2, hexValue.Length - 2);
            }
            return stringValue;
        }
        
        public static string hostnameChunked(string currentHostname) 
        {
            Regex rgx = new Regex("\\..*");
            string currentHostnameChunked = rgx.Replace(currentHostname, "");
            currentHostnameChunked = currentHostnameChunked.Insert(0,"|");
            currentHostnameChunked += "|";
            return currentHostnameChunked;
        }
        
        public static string fileTypeCheck(string detectionName, Session oSession) 
        { // Determine session type (landing page, exploit, payload, etc)
            string fileType;
            var sourceCode = oSession.GetResponseBodyAsString().Replace('\0', '\uFFFD');
            string fullResponseHeaders = oSession.oResponse.headers.ToString();
            int responseSize = oSession.responseBodyBytes.Length;
            if (sourceCode != "" && sourceCode.Length > 20)
            {
                if ((Regex.Matches(sourceCode.Substring(0,20), "<html>|<!DOCTYPE HTML|<h[0-9]>", RegexOptions.IgnoreCase).Count > 0)
                 && (detectionName.Contains("EK")))
                {
                    fileType = "(Landing Page)";
                    return fileType;
                }
                else if (sourceCode.Substring(0,13) == "<?xml version")
                {
                    fileType = "(Config)";
                    return fileType;
                }
                else if ((Regex.Matches(sourceCode.Substring(0,3), "CWS|ZWS|FWS").Count > 0
                 || fullResponseHeaders.Contains("application/x-shockwave-flash")) 
                 && responseSize > 5000)
                {
                    fileType = "(Flash Exploit)";
                    return fileType;
                } 
                    else if (fullResponseHeaders.Contains("application/java-archive"))
                    {
                        fileType = "(Java Exploit)";
                        return fileType;
                        
                    }
                    else if (fullResponseHeaders.Contains("application/x-msdownload") 
                     || fullResponseHeaders.Contains("application/octet-stream") || sourceCode.Substring(0,2).Contains("MZ"))
                    {
                        fileType = "(Payload)";
                        return fileType;
                    }
                    else
                    {
                        fileType = "";
                        return fileType;
                    }
            }
            else
            {
                fileType = "";
                return fileType;
            }
        }
        
        // Function to add info and colour sessions
        public static void EKFiddleAddInfo(Session oSession, string detectionName, string fileType)
        {                           
            // Add comments
            bool fileTypeEmpty = string.IsNullOrEmpty(fileType);
            if (fileTypeEmpty)
            {
                oSession.oFlags["ui-comments"] = detectionName;
            }
            else
            {
                oSession.oFlags["ui-comments"] = detectionName + " " + fileType;
            }
            if (detectionName.Contains("Campaign")) 
            {   // Colour Malware campaign
                oSession.oFlags["ui-comments"] = detectionName;
                oSession.oFlags["ui-color"] = "white";
                oSession.oFlags["ui-backcolor"] = "black";
            } 
            else if (fileType.Contains("Landing Page"))
            {   // Colour Landing pages
                oSession.oFlags["ui-color"] = "white";
                oSession.oFlags["ui-backcolor"] = "teal";
            } 
            else if (fileType.Contains("Exploit"))
            {   // Colour Exploits (SWF, etc)
                oSession.oFlags["ui-color"] = "black";
                oSession.oFlags["ui-backcolor"] = "orange";
            } 
            else if (fileType == "(Payload)") 
            {   // Colour Payloads
                oSession.oFlags["ui-color"] = "white";
                oSession.oFlags["ui-backcolor"] = "red";
            } 
            else if (detectionName.Contains("C2")) 
            {   // Colour Payloads
                oSession.oFlags["ui-color"] = "white";
                oSession.oFlags["ui-backcolor"] = "purple";
            } 
            else 
            {   // Default colour
                oSession.oFlags["ui-color"] = "white";
                oSession.oFlags["ui-backcolor"] = "teal";
            }
            // Refresh Fiddler UI
            oSession.RefreshUI();
        }
        
        // Function to clear comments and colours
        [BindUIButton("Clear Markings")]
        public static void DoEKFiddleClearMarkings() 
        {
            
            FiddlerApplication.UI.actSelectAll();
            var oSessions = FiddlerApplication.UI.GetSelectedSessions();
            for (var x = 0; x < oSessions.Length; x++)
            {
                oSessions[x].oFlags["ui-color"] = "black";
                oSessions[x].oFlags["ui-backcolor"] = "#F2FFF0";
                oSessions[x].oFlags["ui-comments"] = "";
                oSessions[x].RefreshUI();
            }
            FiddlerApplication.UI.lvSessions.SelectedItems.Clear();
        }
        
        // Function to run EK / campaign Regexes
        [BindUIButton("Run Regexes")]
        public static void DoEKFiddleRunRegexes() 
        {
            if (EKFiddleRegexesInstalled() == false)
            {   // Prompt user to re-install EKFiddle if the regexes do not exist
                MessageBox.Show("Regexes are missing and require EKFiddle to be re-installed." + "\n" + "\n" + "Click OK to proceed.", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
                EKFiddleInstallation();
            }
            else
            {
                // Only run if there is no active thread
                if (isRegexThreadRunning == false)
                {
                    // Turn flag on
                    isRegexThreadRunning = true;
                    
                    // Reload CustomRegexes and MasterRegexes into different lists
                    List <string> URIRegexesList = setLoadURIRegexes();
                    List <string> sourceCodeRegexesList = setLoadSourceCodeRegexes();
                    List <string> headersRegexesList = setLoadHeadersRegexes();
                    List <string> IPRegexesList = setLoadIPRegexes();
                        
                    // Create a new list for malicious sessions
                    List<int> maliciousSessionsList = new List<int>();
                    // Initialize malicious sessions found variable
                    bool maliciousFound = false;
                    // Initialize payloadSessionId (for connect-the-dots feature)
                    int payloadSessionId = 0;
                    // Initialize payloadHostname
                    string payloadHostname = "";
                    // Initialize payloadURI
                    string payloadURI = "";
                    // Initialize hostname
                    string currentHostname = "";
                        
                    // Select all sessions
                    FiddlerObject.UI.actSelectAll();        
                    var arrSessions = FiddlerApplication.UI.GetSelectedSessions();
                    int totalSessions = arrSessions.Length;

                    // Start new thread
                    new Thread(() => 
                    {
                        Thread.CurrentThread.IsBackground = true;
                        
                        // Loop through all sessions
                        for (int x = 0; x < arrSessions.Length; x++)
                        {
                            try
                            {
                                // Progress status
                                FiddlerApplication.UI.SetStatusText("Checking " + x + "/" + totalSessions + " Sessions (" + arrSessions[x].hostname + ") ...");
                                // Decode session
                                arrSessions[x].utilDecodeRequest(true);
                                arrSessions[x].utilDecodeResponse(true);
                                // Re-initialize detection name variable
                                string detectionName = "";
                                // Assign variables
                                // Get current IP
                                string currentIP = arrSessions[x].oFlags["x-hostIP"];
                                // Get current URI regardless of encoding                    
                                string currentURI = getCurrentURI(arrSessions[x]);
                                // Get session response headers
                                string fullResponseHeaders = arrSessions[x].oResponse.headers.ToString();
                                // Get session body
                                string sourceCode = arrSessions[x].GetResponseBodyAsString().Replace('\0', '\uFFFD');
                                // Get session body size
                                int responseSize = arrSessions[x].responseBodyBytes.Length;
                                // Get Hostname
                                currentHostname = arrSessions[x].hostname;
                                // Begin checking each sesssion against URL patterns, source code and headers.
                                
                                // Check against URL patterns                        
                                if (detectionName == "")
                                {   
                                    detectionName = checkURIRegexes(URIRegexesList,currentURI);
                                }
                                
                                // Check against source code patterns
                                if (detectionName == "" && (arrSessions[x].oResponse.headers.ExistsAndContains("Content-Type","text/html")
                                 || arrSessions[x].oResponse.headers.ExistsAndContains("Content-Type","text/javascript")
                                 || arrSessions[x].oResponse.headers.ExistsAndContains("Content-Type","text/plain")
                                 || arrSessions[x].oResponse.headers.ExistsAndContains("Content-Type","application/javascript")
                                 || arrSessions[x].oResponse.headers.ExistsAndContains("Content-Type","application/x-javascript"))
                                 && arrSessions[x].fullUrl != "https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/Regexes/MasterRegexes.txt")
                                {   
                                    detectionName = checkSourceCodeRegexes(sourceCodeRegexesList, sourceCode);
                                }
                                
                                
                                // Check against headers patterns
                                if (detectionName == "")
                                {   // Check against headers patterns
                                    detectionName = checkHeadersRegexes(headersRegexesList, fullResponseHeaders);
                                }
                                
                                // Check against IP addresses
                                if (detectionName == "")
                                {   
                                    detectionName = checkIPRegexes(IPRegexesList,currentIP);
                                }
                                                        
                                // Add info
                                if (detectionName != "")
                                {   
                                    // Switch malicious found flag to true
                                    maliciousFound = true;
                                    
                                    // Add to malicious sessions list
                                    maliciousSessionsList.Add(arrSessions[x].id);
                                    
                                    // Get the infection type
                                    string fileType = fileTypeCheck(detectionName, arrSessions[x]);
                                    
                                    // Flag payload (for connect-the-dots feature)
                                    if (fileType == "(Payload)" || detectionName.Contains("Drive-by Mining") || detectionName.Contains("TSS Landing"))
                                    {                
                                        // Add payload session ID
                                        payloadSessionId = arrSessions[x].id;
                                        // Add payload hostname
                                        payloadHostname = arrSessions[x].hostname;
                                        // Add payload URI
                                        payloadURI = arrSessions[x].fullUrl;
                                        
                                    }
                                    
                                    // Add info
                                    EKFiddleAddInfo(arrSessions[x], detectionName, fileType);
                                } 
                            }
                            catch
                            {
                                FiddlerApplication.UI.SetStatusText("Error decoding Session# " + arrSessions[x].id);
                            }
                        }
                        
                        if (payloadSessionId != 0)
                        {
                            connectDots(payloadSessionId, payloadHostname, payloadURI, maliciousSessionsList);
                        }
                        
                        if (maliciousFound == true)
                        {              
                            FiddlerApplication.UI.lvSessions.SelectedItems.Clear();
                            maliciousSessionsList.Sort();
                            string maliciousSessionsString = string.Join(", ", maliciousSessionsList.ToArray());
                            FiddlerApplication.UI.SetStatusText("Malicious traffic found at Session(s)#: " + maliciousSessionsString);
                            System.Media.SystemSounds.Exclamation.Play();
                        }
                        else
                        {
                            FiddlerApplication.UI.lvSessions.SelectedItems.Clear();
                            FiddlerApplication.UI.SetStatusText("No malicious traffic found.");
                        }
                        
                        // Switch flag back to allow running the thread again
                        isRegexThreadRunning = false;
                        
                    }).Start();

                }
                else
                {
                    MessageBox.Show("Regexes currently running, please wait until finished.", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            } 
        }  
 
        // Function to update/view Regexes
        [BindUIButton("Update/View Regexes")]
        public static void DoOpenRegexes()
        {        
            if (EKFiddleRegexesInstalled() == false)
            {   // Prompt user to re-install EKFiddle if the regexes do not exist
                MessageBox.Show("Folder and regexes are missing and require EKFiddle to be re-installed." + "\n" + "\n" + "Click OK to proceed.", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
                EKFiddleInstallation();
            }
            else
            {
                // Check for regexes update and return status
                string updateStatus = "";
                if (EKFiddleRegexesVersionCheck() == true)
                {
                    updateStatus = "(latest)";
                }
                else
                {
                    updateStatus = "(an update is available)";
                }
                          
                // Gather information about Master regex file
                var masterRegexCount = 0;
                var fileVersion = "N/A";
                using (var reader = new System.IO.StreamReader(@EKFiddleRegexesPath + "MasterRegexes.txt"))
                {
                    while (!reader.EndOfStream)
                    {
                        var line = reader.ReadLine();
                        // Count number of regexes in master list
                        if (line.StartsWith("URI") || line.StartsWith("SourceCode") || line.StartsWith("IP") || line.StartsWith("Headers"))
                        {
                            masterRegexCount+=1;
                        }
                        // Find master list version
                        if (line.StartsWith("## Last updated: "))
                        {
                            fileVersion = line.Replace("## Last updated: ", "");
                        }
                    }
                    reader.Close();
                }
                // Gather information about Custom regex file
                var customRegexCount = 0;
                DateTime lastModified = System.IO.File.GetLastWriteTime(@EKFiddleRegexesPath + "CustomRegexes.txt");
                using (var reader = new System.IO.StreamReader(@EKFiddleRegexesPath + "CustomRegexes.txt"))
                {
                    while (!reader.EndOfStream)
                    {
                        var line = reader.ReadLine();
                        // Count number of regexes in custom list
                        if (line.StartsWith("URI") || line.StartsWith("SourceCode") || line.StartsWith("IP") || line.StartsWith("Headers"))
                        {
                            customRegexCount+=1;
                        }
                    }
                    reader.Close();
                }
                // Show user dialog
                DialogResult dialogEKFiddleUninstallation = MessageBox.Show("MasterRegexes.txt (open-source rules)" + "\n"
                 + " -> Number of Regexes: " + masterRegexCount + "\n"
                 + " -> Last updated: " + fileVersion + " " + updateStatus + "\n"
                 + "\n"
                 + "CustomRegexes.txt (your own custom rules)" + "\n"
                 + " -> Number of Regexes: " + customRegexCount + "\n"
                 + " -> Last updated: " + lastModified.ToString("yyyy-MM-dd") + "\n"
                 + "\n" + "\n"
                 + "Would you like to open them in your default text editor?", "EKFiddle Regexes", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
                   
                if(dialogEKFiddleUninstallation == DialogResult.Yes)
                {
                    Process.Start(EKFiddleRegexesEditor, @EKFiddleRegexesPath + "MasterRegexes.txt");
                    Process.Start(EKFiddleRegexesEditor, @EKFiddleRegexesPath + "CustomRegexes.txt");
                }
            }
        }
        
        // Function to import PCAP, SAZ captures
        [BindUIButton("Import SAZ/PCAP")]
        public static void DoImportCapture()
        {
            var openCapture = new OpenFileDialog();
            openCapture.InitialDirectory = EKFiddleCapturesPath;
            openCapture.Filter = "PCAP/SAZ files (*.cap;*.pcap;*.pcapng;*.saz)|*.cap;*.pcap;*pcapng;*.saz|All files (*.*)|*.*";
            openCapture.ShowDialog();
            if (openCapture.FileName != "")
            {
                if (openCapture.FileName.Contains("cap"))
                {
                    FiddlerObject.UI.actImportFile(openCapture.FileName);
                }
                if (openCapture.FileName.Contains(".saz"))
                {
                    FiddlerObject.UI.actLoadSessionArchive(openCapture.FileName);
                }
                // Run regexes
                DialogResult dialogEKFiddleRunRegexes = MessageBox.Show("Sucessfully loaded: " + openCapture.SafeFileName + "\n" + "\n" 
                 + "Would you like to run Regexes?", "EKFiddle", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
                if(dialogEKFiddleRunRegexes == DialogResult.Yes)
                {
                    DoEKFiddleRunRegexes();
                }
            }    
        }
        
        // Function to launch Proxy
        [BindUIButton("Proxy")]
        public static void DoEKFiddleProxy() 
        {
            string currentProxy = FiddlerApplication.Prefs.GetStringPref("fiddler.defaultProxy", null);
            string EKFiddleProxy = FiddlerObject.prompt("Change upstream proxy:" + "\n"
             + "-> someProxy:1234 // sends request via HTTP/S proxy" + "\n" + "-> socks=someProxy:1234 // sends request via SOCKS proxy" + "\n" + "-> 0 // system's default proxy"
            ,currentProxy, "EKFiddle Proxy/Upstream Gateway");
            if (EKFiddleProxy == "" || EKFiddleProxy == "0")
            {    
                FiddlerApplication.Prefs.SetStringPref("fiddler.defaultProxy", EKFiddleProxy);
                MessageBox.Show("Proxy has been reset to system's default.", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }else{
                FiddlerApplication.Prefs.SetStringPref("fiddler.defaultProxy", EKFiddleProxy);
                MessageBox.Show("Proxy is now set to: " + EKFiddleProxy + ".", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }
        
        // Function to launch VPN
        [BindUIButton("VPN")]
        public static void DoEKFiddleVPN() 
        {
            if (string.IsNullOrEmpty(EKFiddleOpenVPNPath) && OSName == "Windows")
            {    // OpenVPN is not installed, tell the user to install it
                MessageBox.Show("Please install OpenVPN first (in the default path)!!", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                FiddlerObject.ReloadScript();
                return;
            }
            
            // OpenVPN is installed
            var openVPN = new OpenFileDialog();
            if(OSName == "Windows")
            {
                openVPN.InitialDirectory = EKFiddleOpenVPNPath + "\\config";
            }
            else if (OSName == "Linux")
            { 
                openVPN.InitialDirectory = EKFiddleOpenVPNPath;
            }
            openVPN.Filter = ".ovpn files (*.ovpn)|*.ovpn|All files (*.*)|*.*";
            openVPN.ShowDialog();
            if (openVPN.FileName != "")
            {   // Start VPN
                if(OSName == "Windows")
                {   // OpenVPN on Windows
                    // Kill any previous VPN connection (Windows only)
                    System.Diagnostics.Process[] cmdProcesses = System.Diagnostics.Process.GetProcessesByName("cmd");
                    foreach (System.Diagnostics.Process CurrentProcess in cmdProcesses)
                    {
                        if (CurrentProcess.MainWindowTitle.Contains("OpenVPN"))
                        {
                            CurrentProcess.Kill();
                            // Kill openvpn
                            foreach (var process in Process.GetProcessesByName("openvpn"))
                            {
                                process.Kill();
                            }
                        }
                    }
                    // Start OpenVPN with parameters on Windows
                    try
                    {
                        Process.Start(new ProcessStartInfo {
                            FileName = "cmd.exe",
                            Arguments = "/K " + "\"\"" + EKFiddleOpenVPNPath + "\\bin\\openvpn.exe" + "\"" + " " + "\"" + openVPN.FileName + "\"\"",
                            Verb = "runas",
                            UseShellExecute = true,
                            });
                    }
                    catch
                    {
                        FiddlerApplication.UI.SetStatusText("Error or user cancelled action");
                    }
                }
                else if (OSName == "Linux")
                {   // OpenVPN on Linux
                    if (xtermProcId != 0)
                    {   // Kill any existing xterm
                        try
                        {
                            Process currentxtermId = Process.GetProcessById(xtermProcId);
                            currentxtermId.Kill();
                        }
                        catch
                        {
                            FiddlerApplication.UI.SetStatusText("Error killing xterm");
                        }
                    }
                    // Start OpenVPN with parameters on Linux
                    Process vpn = new System.Diagnostics.Process ();
                    vpn.StartInfo.FileName = "/bin/bash";
                    vpn.StartInfo.Arguments = "-c \" " + "xterm -xrm 'XTerm.vt100.allowTitleOps: false' -T \'EKFiddleVPN:\'" + openVPN.SafeFileName + " -e 'sudo pkill openvpn; sudo openvpn " + openVPN.FileName + "; bash'" + " \"";
                    vpn.StartInfo.UseShellExecute = false; 
                    vpn.StartInfo.RedirectStandardOutput = true;
                    vpn.Start ();
                    // Capture PID of new xterm
                    xtermProcId = vpn.Id;
                }
                else
                {
                    MessageBox.Show("Your Operating System is not supported.", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
        }
        
                // Function to save current traffic
        [BindUIButton("UI mode")]
        public static void DoEKFiddleAdvancedUI() 
        {
            if (FiddlerApplication.Prefs.GetStringPref("fiddler.advancedUI", null) == "False")
            {
                DialogResult dialogEKFiddleUI = MessageBox.Show("Would you like to enable Advanced UI mode? (Windows only)" + 
                " It adds a few extra columns and changes the default view to Wide Layout." + "\n" + "\n" +
                "This setting can be turned off by clicking on the UI button again.", "EKFiddle", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
                if(dialogEKFiddleUI == DialogResult.Yes)
                {
                    arrangeColumns();
                    FiddlerApplication.Prefs.SetStringPref("fiddler.advancedUI", "True");
                    MessageBox.Show("Advanced UI has been turned ON. Please restart Fiddler to fully apply those changes.", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            else
            {
                DialogResult dialogEKFiddleUI = MessageBox.Show("Would you like to disable Advanced UI mode?" + 
                 "\n" + "\n" +
                 "This setting can be turned on again by clicking on the UI mode button.", "EKFiddle", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
                if(dialogEKFiddleUI == DialogResult.Yes)
                {    
                    FiddlerApplication.Prefs.SetStringPref("fiddler.advancedUI", "False");
                    FiddlerApplication.Prefs.SetStringPref("fiddler.ui.layout.mode", "0");
                    MessageBox.Show("Advanced UI has been turned OFF. Please restart Fiddler to apply the changes.", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
        }
        
        // Function to save current traffic
        [BindUIButton("QuickSave")]
        public static void DoEKFiddleSave() 
        {
            FiddlerApplication.UI.actSelectAll();
            FiddlerObject.UI.actSaveSessionsToZip(EKFiddleCapturesPath + "QuickSave-" + DateTime.Now.ToString("MM-dd-yyyy-HH-mm-ss") + ".saz");
        }
        // These static variables are used for simple breakpointing & other QuickExec rules 
        [BindPref("fiddlerscript.ephemeral.bpRequestURI")]
        public static string bpRequestURI = null;

        [BindPref("fiddlerscript.ephemeral.bpResponseURI")]
        public static string bpResponseURI = null;

        [BindPref("fiddlerscript.ephemeral.bpMethod")]
        public static string bpMethod = null;

        static int bpStatus = -1;
        static string uiBoldURI = null;
        static string gs_ReplaceToken = null;
        static string gs_ReplaceTokenWith = null;
        static string gs_OverridenHost = null;
        static string gs_OverrideHostWith = null;

        // The OnExecAction function is called by either the QuickExec box in the Fiddler window,
        // or by the ExecAction.exe command line utility.
        public static bool OnExecAction(string[] sParams)
        {
            FiddlerApplication.UI.SetStatusText("ExecAction: " + sParams[0]);
            string sAction = sParams[0].ToLower();
            switch (sAction) 
            {
            case "pcap": // shortcut to import a PCAP
                DoImportCapture();
                return true;
            case "saz": // shortcut to import a SAZ
                DoImportCapture();
                return true;
            case "regexes": // shortcut to open Regexes
                DoOpenRegexes();
                return true;
            case "ekfiddle": // shortcut to run Regexes
                DoEKFiddleRunRegexes();
                return true;
            case "reset": // shortcut to clear sessions of comments, colours, etc
                DoEKFiddleClearMarkings();
                return true;
            case "bold":
                if (sParams.Length<2) {uiBoldURI=null; FiddlerApplication.UI.SetStatusText("Bolding cleared"); return false;}
                uiBoldURI = sParams[1]; FiddlerApplication.UI.SetStatusText("Bolding requests for " + uiBoldURI);
                return true;
            case "bp":
                MessageBox.Show("bpu = breakpoint request for uri\nbpm = breakpoint request method\nbps=breakpoint response status\nbpafter = breakpoint response for URI");
                return true;
            case "bps":
                if (sParams.Length<2) {bpStatus=-1; FiddlerApplication.UI.SetStatusText("Response Status breakpoint cleared"); return false;}
                bpStatus = Int32.Parse(sParams[1]); FiddlerApplication.UI.SetStatusText("Response status breakpoint for " + sParams[1]);
                return true;
            case "bpv":
            case "bpm":
                if (sParams.Length<2) {bpMethod=null; FiddlerApplication.UI.SetStatusText("Request Method breakpoint cleared"); return false;}
                bpMethod = sParams[1].ToUpper(); FiddlerApplication.UI.SetStatusText("Request Method breakpoint for " + bpMethod);
                return true;
            case "bpu":
                if (sParams.Length<2) {bpRequestURI=null; FiddlerApplication.UI.SetStatusText("RequestURI breakpoint cleared"); return false;}
                bpRequestURI = sParams[1]; 
                FiddlerApplication.UI.SetStatusText("RequestURI breakpoint for "+sParams[1]);
                return true;
            case "bpa":
            case "bpafter":
                if (sParams.Length<2) {bpResponseURI=null; FiddlerApplication.UI.SetStatusText("ResponseURI breakpoint cleared"); return false;}
                bpResponseURI = sParams[1]; 
                FiddlerApplication.UI.SetStatusText("ResponseURI breakpoint for "+sParams[1]);
                return true;
            case "overridehost":
                if (sParams.Length<3) {gs_OverridenHost=null; FiddlerApplication.UI.SetStatusText("Host Override cleared"); return false;}
                gs_OverridenHost = sParams[1].ToLower();
                gs_OverrideHostWith = sParams[2];
                FiddlerApplication.UI.SetStatusText("Connecting to [" + gs_OverrideHostWith + "] for requests to [" + gs_OverridenHost + "]");
                return true;
            case "urlreplace":
                if (sParams.Length<3) {gs_ReplaceToken=null; FiddlerApplication.UI.SetStatusText("URL Replacement cleared"); return false;}
                gs_ReplaceToken = sParams[1];
                gs_ReplaceTokenWith = sParams[2].Replace(" ", "%20");  // Simple helper
                FiddlerApplication.UI.SetStatusText("Replacing [" + gs_ReplaceToken + "] in URIs with [" + gs_ReplaceTokenWith + "]");
                return true;
            case "allbut":
            case "keeponly":
                if (sParams.Length<2) { FiddlerApplication.UI.SetStatusText("Please specify Content-Type to retain during wipe."); return false;}
                FiddlerApplication.UI.actSelectSessionsWithResponseHeaderValue("Content-Type", sParams[1]);
                FiddlerApplication.UI.actRemoveUnselectedSessions();
                FiddlerApplication.UI.lvSessions.SelectedItems.Clear();
                FiddlerApplication.UI.SetStatusText("Removed all but Content-Type: " + sParams[1]);
                return true;
            case "stop":
                FiddlerApplication.UI.actDetachProxy();
                return true;    
            case "start":
                FiddlerApplication.UI.actAttachProxy();
                return true;
            case "clear":
                FiddlerApplication.UI.actRemoveAllSessions();
                return true;
            case "g":
            case "go":
                FiddlerApplication.UI.actResumeAllSessions();
                return true;
            case "goto":
                if (sParams.Length != 2) return false;
                Utilities.LaunchHyperlink("http://www.google.com/search?hl=en&btnI=I%27m+Feeling+Lucky&q=" + Utilities.UrlEncode(sParams[1]));
                return true;
            case "help":
                Utilities.LaunchHyperlink("http://fiddler2.com/r/?quickexec");
                return true;
            case "hide":
                FiddlerApplication.UI.actMinimizeToTray();
                return true;
            case "log":
                FiddlerApplication.Log.LogString((sParams.Length<2) ? "User couldn't think of anything to say..." : sParams[1]);
                return true;
            case "nuke":
                FiddlerApplication.UI.actClearWinINETCache();
                FiddlerApplication.UI.actClearWinINETCookies(); 
                return true;
            case "screenshot":
                FiddlerApplication.UI.actCaptureScreenshot(false);
                return true;
            case "show":
                FiddlerApplication.UI.actRestoreWindow();
                return true;
            case "tail":
                if (sParams.Length<2) { FiddlerApplication.UI.SetStatusText("Please specify # of sessions to trim the session list to."); return false;}
                FiddlerApplication.UI.TrimSessionList(int.Parse(sParams[1]));
                return true;
            case "quit":
                FiddlerApplication.UI.actExit();
                return true;
            case "dump":
                FiddlerApplication.UI.actSelectAll();
                FiddlerApplication.UI.actSaveSessionsToZip(CONFIG.GetPath("Captures") + "dump.saz");
                FiddlerApplication.UI.actRemoveAllSessions();
                FiddlerApplication.UI.SetStatusText("Dumped all sessions to " + CONFIG.GetPath("Captures") + "dump.saz");
                return true;

            default:
                if (sAction.StartsWith("http") || sAction.StartsWith("www"))
                {
                    System.Diagnostics.Process.Start(sParams[0]);
                    return true;
                }
                else
                {
                    FiddlerApplication.UI.SetStatusText("Requested ExecAction: '" + sAction + "' not found. Type HELP to learn more.");
                    return false;
                }
            }
        }
    }
}