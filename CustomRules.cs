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

// EKFiddle
// This is a modified version of the default CustomRules.cs file.
// Its purpose is to provide a framework to analyze exploit kits.
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
        public static void DoLinksMenu(string sText, string sAction)
        {
            Utilities.LaunchHyperlink(sAction);
        }

        [RulesOption("Hide 304s")]
        [BindPref("fiddlerscript.rules.Hide304s")]
        public static bool m_Hide304s = false;

        // Cause Fiddler to override the Accept-Language header with one of the defined values
        [RulesOption("Request &Japanese Content")]
        public static bool m_Japanese = false;

        // Automatic Authentication
        [RulesOption("&Automatically Authenticate")]
        [BindPref("fiddlerscript.rules.AutoAuth")]
        public static bool m_AutoAuth = false;

        // Cause Fiddler to override the User-Agent header with one of the defined values
        [RulesString("&User-Agents", true)] 
        [BindPref("fiddlerscript.ephemeral.UserAgentString")]
        [RulesStringValue(0, "Netscape &3", "Mozilla/3.0 (Win95; I)")]
        [RulesStringValue(1, "WinPhone8.1", "Mozilla/5.0 (Mobile; Windows Phone 8.1; Android 4.0; ARM; Trident/7.0; Touch; rv:11.0; IEMobile/11.0; NOKIA; Lumia 520) like iPhone OS 7_0_3 Mac OS X AppleWebKit/537 (KHTML, like Gecko) Mobile Safari/537")]
        [RulesStringValue(2, "&Safari5 (Win7)", "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.21.1 (KHTML, like Gecko) Version/5.0.5 Safari/533.21.1")]
        [RulesStringValue(3, "Safari9 (Mac)", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11) AppleWebKit/601.1.56 (KHTML, like Gecko) Version/9.0 Safari/601.1.56")]
        [RulesStringValue(4, "iPad", "Mozilla/5.0 (iPad; CPU OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12F5027d Safari/600.1.4")]
        [RulesStringValue(5, "iPhone6", "Mozilla/5.0 (iPhone; CPU iPhone OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12F70 Safari/600.1.4")]
        [RulesStringValue(6, "IE &6 (XPSP2)", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)")]
        [RulesStringValue(7, "IE &7 (Vista)", "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; SLCC1)")]
        [RulesStringValue(8, "IE 8 (Win2k3 x64)", "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; WOW64; Trident/4.0)")]
        [RulesStringValue(9, "IE &8 (Win7)", "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)")]
        [RulesStringValue(10, "IE 9 (Win7)", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)")]
        [RulesStringValue(11, "IE 10 (Win8)", "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0)")]
        [RulesStringValue(12, "IE 11 (Surface2)", "Mozilla/5.0 (Windows NT 6.3; ARM; Trident/7.0; Touch; rv:11.0) like Gecko")]
        [RulesStringValue(13, "IE 11 (Win8.1)", "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko")]
        [RulesStringValue(14, "Edge (Win10)", "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.11082")]
        [RulesStringValue(15, "&Opera", "Opera/9.80 (Windows NT 6.2; WOW64) Presto/2.12.388 Version/12.17")]
        [RulesStringValue(16, "&Firefox 3.6", "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.2.7) Gecko/20100625 Firefox/3.6.7")]
        [RulesStringValue(17, "&Firefox 43", "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0")]
        [RulesStringValue(18, "&Firefox Phone", "Mozilla/5.0 (Mobile; rv:18.0) Gecko/18.0 Firefox/18.0")]
        [RulesStringValue(19, "&Firefox (Mac)", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0")]
        [RulesStringValue(20, "Chrome (Win)", "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.48 Safari/537.36")]
        [RulesStringValue(21, "Chrome (Android)", "Mozilla/5.0 (Linux; Android 5.1.1; Nexus 5 Build/LMY48B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.78 Mobile Safari/537.36")]
        [RulesStringValue(22, "ChromeBook", "Mozilla/5.0 (X11; CrOS x86_64 6680.52.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.74 Safari/537.36")]
        [RulesStringValue(23, "GoogleBot Crawler", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")]
        [RulesStringValue(24, "Kindle Fire (Silk)", "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_3; en-us; Silk/1.0.22.79_10013310) AppleWebKit/533.16 (KHTML, like Gecko) Version/5.0 Safari/533.16 Silk-Accelerated=true")]
        [RulesStringValue(25, "&Custom...", "%CUSTOM%")]
        public static string sUA = null;

        // Cause Fiddler to delay HTTP traffic to simulate typical 56k modem conditions
        [RulesOption("Simulate &Modem Speeds", "Per&formance")]
        public static bool m_SimulateModem = false;

        // Removes HTTP-caching related headers and specifies "no-cache" on requests and responses
        [RulesOption("&Disable Caching", "Per&formance")]
        public static bool m_DisableCaching = false;

        [RulesOption("Cache Always &Fresh", "Per&formance")]
        public static bool m_AlwaysFresh = false;

        // Force a manual reload of the script file.  Resets all
        // RulesOption variables to their defaults.
        [ToolsAction("Reset Script")]
        public static void DoManualReload()
        {
            FiddlerObject.ReloadScript();
        }

        // Install/Update EKFiddle
        [ToolsAction("Install/Update EKFiddle", "&EKFiddle")]
        public static void DoCallInstallEKFiddle()
        {
            EKFiddleInstallation();
        }

        // Re-arrange columns
        [ToolsAction("Advanced UI on/off", "&EKFiddle")]
        public static void DoArrangeColumns()
        {
            EKFiddleFixUI();
        }
        
        // VPN
        [ToolsAction("VPN", "&EKFiddle")]
        public static void DoVPN()
        {
            EKFiddleVPN();
        }

        // Import traffic capture
        [ToolsAction("Import SAZ/PCAP", "&EKFiddle")]
        public static void DoCallImportCapture()
        {
            DoImportCapture();
        }

         // View/Edit Regexes
        [ToolsAction("View/Edit Regexes", "&EKFiddle")]
        public static void DoCallOpenRegexes()
        {
            DoOpenRegexes();
        }

        // Run Regexes
        [ToolsAction("Run Regexes", "&EKFiddle")]
        public static void DoCallEKFiddleRunRegexes() 
        {
            EKFiddleRunRegexes();
        }
        
        // Run clear markings
        [ToolsAction("Clear Markings", "&EKFiddle")]
        public static void DoCallEKFiddleClearMarkings() 
        {
            EKFiddleClearMarkings();
        }
                
        // 'About' EKFiddle
        [ToolsAction("EKFiddle GitHub page", "&EKFiddle")]
        public static void DoCallEKFiddleGit()
        {                         
            Utilities.LaunchHyperlink("https://github.com/malwareinfosec/EKFiddle");
        }
        
        // Uninstall EKFiddle
        [ToolsAction("Uninstall EKFiddle", "&EKFiddle")]
        public static void DoCallEKFiddleUninstall()
        {                         
            if (System.IO.Directory.Exists(EKFiddlePath))
            {
                DialogResult dialogEKFiddleUninstallation = MessageBox.Show("Are you sure you want to uninstall EKFiddle? " + "\n" + "(This will remove all saved captures and regexes.)", "EKFiddle", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if(dialogEKFiddleUninstallation == DialogResult.Yes)
                {
                    Directory.Delete(EKFiddlePath, true);
                    MessageBox.Show("The EKFiddle folder has been removed." + "\n" + "\n" + "To completely uninstall EKFiddle, please delete the CustomRules.cs file and restart Fiddler.", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            else
            {
                MessageBox.Show("EKFiddle is not currently installed.", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
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
                connectDots(arrSessions[0].id, arrSessions[0].hostname, maliciousSessionsList);
            }
        }
        
        // Extract IOCs
        [ContextAction("Extract IOCs")]
        public static void DoExtractIOCs(Session[] arrSessions)
        {
            List<string> IOCsList = new List<string>();
            IOCsList.Add("Time,Method,IP address,Hostname,Response Body MD5,Response Body SHA256,Comments");
            for (int x = 0; x < arrSessions.Length; x++)
            {
                var currentMethod = arrSessions[x].oRequest.headers.HTTPMethod;
                var currentIP = arrSessions[x].oFlags["x-hostIP"];
                var currentDomain = arrSessions[x].host;
                var currentMD5 = arrSessions[x].GetResponseBodyHash("md5").Replace("-","");
                var currentSHA256 = arrSessions[x].GetResponseBodyHash("sha256").Replace("-","");
                var currentComments = arrSessions[x].oFlags["ui-comments"];
                if (currentComments == null)
                {
                    currentComments = "N/A";
                }
                var currentTime = arrSessions[x].Timers.ClientBeginRequest.ToString();
                IOCsList.Add(currentTime + "," + currentMethod + "," + currentIP + "," + currentDomain + "," + currentMD5 + "," + currentSHA256 + "," + currentComments);
            }
             
            var IOCs = string.Join(Environment.NewLine, IOCsList.ToArray());
            Utilities.CopyToClipboard(IOCs);
            MessageBox.Show("IOCs have been copied to the clipboard.", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
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
        
        [ContextAction("Calculate MD5 Hash", "Response Body")]
        public static void doMD5Hash( Session[] arrSessions) {
        // Initialize a new list
            List<string> HashList = new List<string>();
            for (int x = 0; x < arrSessions.Length; x++)
            {
                if (arrSessions[x].bHasResponse) {
                    HashList.Add(arrSessions[x].GetResponseBodyHash("md5").Replace("-",""));
                }
            }
            var HashJoined = string.Join(Environment.NewLine, HashList.ToArray());
            Utilities.CopyToClipboard(HashJoined);
            MessageBox.Show(HashJoined, "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        
        [ContextAction("Calculate SHA256 Hash", "Response Body")]
        public static void doSHA256Hash( Session[] arrSessions) {
        // Initialize a new list
            List<string> HashList = new List<string>();
            for (int x = 0; x < arrSessions.Length; x++)
            {
                if (arrSessions[x].bHasResponse) {
                    HashList.Add(arrSessions[x].GetResponseBodyHash("sha256").Replace("-",""));
                }
            }
            var HashJoined = string.Join(Environment.NewLine, HashList.ToArray());
            Utilities.CopyToClipboard(HashJoined);
            MessageBox.Show(HashJoined, "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        
        // Save the current session body response to disk
        [ContextAction("Extract to Disk", "Response Body")]
        public static void DoSaveBody(Session[] arrSessions)
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                arrSessions[x].SaveResponseBody(EKFiddleArtifactsPath   + arrSessions[x].SuggestedFilename);
            }
            FiddlerApplication.UI.actUpdateInspector(true,true);
            Process.Start(@EKFiddleArtifactsPath);
        }
        
        // Check the current hash in Hybrid Analysis
        [ContextAction("Hybrid Analysis lookup", "Response Body")]
        public static void DoCheckHA(Session[] arrSessions) 
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                if (arrSessions[x].bHasResponse) {
                    Utilities.LaunchHyperlink(String.Format("https://www.reverse.it/sample/{0}",arrSessions[x].GetResponseBodyHash("sha256").Replace("-","")));
                }
            }
        }
        
        // Check the current hash against VT
        [ContextAction("VirusTotal lookup", "Response Body")]
        public static void DoCheckHashVT(Session[] arrSessions) 
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                if (arrSessions[x].bHasResponse) {
                    Utilities.LaunchHyperlink(String.Format("https://www.virustotal.com/en/file/{0}/analysis/",arrSessions[x].GetResponseBodyHash("sha256").Replace("-","")));   
                }
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
        
        // Open current URL in Internet Explorer
        [ContextAction("Open in Internet Explorer", "URI")]
        public static void DoOpeninIE(Session[] arrSessions)
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                System.Diagnostics.Process.Start("iexplore.exe", arrSessions[x].url);
            }
        }
        
        // Open current URL in Chrome
        [ContextAction("Open in Chrome", "URI")]
        public static void DoOpeninChrome(Session[] arrSessions)
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                System.Diagnostics.Process.Start("chrome.exe", arrSessions[x].url);
            }
        }
        
        // Open current URL in Firefox
        [ContextAction("Open in Firefox", "URI")]
        public static void DoOpeninFF(Session[] arrSessions)
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                System.Diagnostics.Process.Start("firefox.exe", arrSessions[x].url);
            }
        }
        
        // Open current URL in Edge
        [ContextAction("Open in Edge", "URI")]
        public static void DoOpeninEdge(Session[] arrSessions)
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                System.Diagnostics.Process.Start("microsoft-edge:", arrSessions[x].url);
            }
        }
        
        // Check the current IP address against Google
        [ContextAction("Google Search", "IP address")]
        public static void DoCheckIPGoogle(Session[] arrSessions)
        {
        for (int x = 0; x < arrSessions.Length; x++)
            {
                Utilities.LaunchHyperlink("https://www.google.com/search?q=" + "\"\"" + arrSessions[x].oFlags["x-hostIP"] + "\"\"");
            }
        }

    
        // Check the current IP address against RiskIQ
        [ContextAction("RiskIQ", "IP address")]
        public static void DoCheckIPRiskIQ(Session[] arrSessions) 
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                Utilities.LaunchHyperlink("https://community.riskiq.com/search/" + arrSessions[x].oFlags["x-hostIP"] +"");
            }
        }

        // Check the current IP address against URLQuery
        [ContextAction("URLQuery", "IP address")]
        public static void DoOSINTIPURLQuery(Session[] arrSessions)
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                Utilities.LaunchHyperlink("https://urlquery.net/search?q=" + arrSessions[x].oFlags["x-hostIP"]);
            }
        }

        // Check the current IP address against VT
        [ContextAction("VirusTotal", "IP address")]
        public static void DoCheckIPVT(Session[] arrSessions) 
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                Utilities.LaunchHyperlink("https://www.virustotal.com/en/ip-address/" + arrSessions[x].oFlags["x-hostIP"] +"/information/");
            }
        }

        // Check the current hostname against Google
        [ContextAction("Google Search", "Hostname")]
        public static void DoOSINTHostnameGoogle(Session[] arrSessions)
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                Utilities.LaunchHyperlink("https://www.google.com/search?q=" + "\"\"" + arrSessions[x].hostname + "\"\"");
            }
        }

        // Check the current hostname against RiskIQ
        [ContextAction("RiskIQ", "Hostname")]
        public static void DoCheckHostnameRiskIQ(Session[] arrSessions) 
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                Utilities.LaunchHyperlink("https://community.riskiq.com/search/" + arrSessions[x].hostname +"");
            }
        }  

        // Check the current hostname against URLQuery
        [ContextAction("URLQuery", "Hostname")]
        public static void DoOSINTHostnameURLQuery(Session[] arrSessions)
        {
        for (int x = 0; x < arrSessions.Length; x++)
            {
                Utilities.LaunchHyperlink("https://urlquery.net/search?q=" + arrSessions[x].hostname);
            }
        }

        // Check the current hostname against VT
        [ContextAction("VirusTotal", "Hostname")]
        public static void DoCheckDomainVT(Session[] arrSessions) 
        {
            for (int x = 0; x < arrSessions.Length; x++)
            {
                Utilities.LaunchHyperlink("https://virustotal.com/en/domain/" + arrSessions[x].hostname +"/information/");
            }
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

            if (m_Japanese)
            {
                oSession.oRequest["Accept-Language"] = "ja";
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
            // Check if EKFiddle needs to be installed
            if (!System.IO.Directory.Exists(EKFiddlePath))
            {   // Prompt for installation
                EKFiddleInstallation();
            }
            else
            {    // Set local version and check for core and regex updates
                // Set EKFiddle local version in 'Preferences'
                string EKFiddleVersion = "0.5.4";
                FiddlerApplication.Prefs.SetStringPref("fiddler.ekfiddleversion", EKFiddleVersion);
                // Change Fiddler's window title
                FiddlerApplication.UI.Text="EKFiddle v." + EKFiddleVersion +" (Fiddler)";
                
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
                        DialogResult dialogEKFiddleUpdate = MessageBox.Show("You are running EKFiddle version " + EKFiddleVersion + ". A new version (" + EKFiddleLatestVersion 
                        + ") is available!" + "\n" + "\n" + "Would you like to download it now?", "EKFiddle core update", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
                        if(dialogEKFiddleUpdate == DialogResult.Yes)
                        {
                            // Download CustomRules.js
                            WebClient CustomRulesWebClient = new WebClient();
                            CustomRulesWebClient.DownloadFile("https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/CustomRules.cs", @FiddlerScriptsPath + "CustomRules.cs");
                            // Dialog to prompt user to restart Fiddler
                            MessageBox.Show("EKFiddle has been updated to version " + EKFiddleLatestVersion + "!!", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        }
                    }
                    // Check for regexes updates
                    if (!System.IO.File.Exists(@EKFiddleRegexesPath + "MasterRegexes.txt") || !System.IO.File.Exists(@EKFiddleRegexesPath + "CustomRegexes.txt"))
                    {   // Prompt for installation/update
                        MessageBox.Show("EKFiddle needs to be updated.", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
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
                            DialogResult dialogRegexesUpdate = MessageBox.Show("You are running Regexes version " + RegexesLocalVersion + ". A new version (" + RegexesLatestVersion 
                        + ") is available!" + "\n" + "\n" + "Would you like to download it now?", "EKFiddle Regexes update", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
                            if(dialogRegexesUpdate == DialogResult.Yes)
                            {  
                                WebClient regexesWebClient = new WebClient();
                                regexesWebClient.DownloadFile("https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/Regexes/MasterRegexes.txt", @EKFiddleRegexesPath + "MasterRegexes.txt");
                                MessageBox.Show("Regexes have been updated to version " + RegexesLatestVersion + "!!", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
                            }
                        }
                    }
                }
                catch
                {
                   MessageBox.Show("Failed to check for updates!", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
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
        }

        // The Main() function runs everytime your FiddlerScript compiles
        public static void Main() 
        {     
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
        
        // EKFiddle global variables
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
                    FiddlerApplication.Prefs.SetStringPref("fiddler.config.path.TextEditor", "/Applications    extEdit.app");
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

        // Connect-the-dots
        public static void connectDots(int payloadSessionId, string currentHostname, List<int> maliciousSessionsList)
        {        
            try
                {
                    string currentHostnameInHex;
                    string currentHostnameInHexPercent;
                    string currentHostnameChunked;
                    currentHostnameInHex = hostnameInHex(currentHostname);
                    currentHostnameInHexPercent = hostnameInHexPercent(currentHostname);
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
                    FiddlerApplication.UI.SetStatusText("EKFiddle: Connecting the dots...");
                    // Loop through sessions before current ID
                    for (int x = arrSelectedSessions.Length; x --> 0;)
                    {
                        // Define current source code and path in URI
                        // Decode session
                        arrSelectedSessions[x].utilDecodeRequest(true);
                        arrSelectedSessions[x].utilDecodeResponse(true);
                        var sourceCode = arrSelectedSessions[x].GetResponseBodyAsString().Replace('\0', '\uFFFD');
                        Regex rgx = new Regex(".*\\/");
                        string urlPath = rgx.Replace(arrSelectedSessions[x].PathAndQuery, " ");
                        var foundMatch = false;
                        // Exclude urs.microsoft.com and Bing telemetry
                        if (!arrSelectedSessions[x].uriContains("urs.microsoft.com") && !arrSelectedSessions[x].uriContains("api.bing.com"))
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
                                 || sourceCode.IndexOf(currentHostnameChunked, 0, StringComparison.CurrentCultureIgnoreCase) != -1)
                                {
                                    foundMatch = true;
                                }
                            }
                            if (foundMatch == true)
                            {
                                // Add to sequence list
                                sequenceList.Add(arrSelectedSessions[x].id);
                                // Assign new current domain name (standard and in hexadecimal notation) to look for next
                                currentHostname = arrSelectedSessions[x].hostname;
                                currentHostnameInHex = hostnameInHex(currentHostname);
                                currentHostnameInHexPercent = hostnameInHexPercent(currentHostname);
                                currentHostnameChunked = hostnameChunked(currentHostname);
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
                        maliciousSessionsList.Add(sequenceSessionId);
                        //  in reverse order
                        for (int x = arrSelectedSessions.Length; x --> 0;)
                        {   
                            // Identify the match
                            if (arrSelectedSessions[x].id == sequenceSessionId)
                            {                
                                if (arrSelectedSessions[x].oFlags["ui-comments"] == null || arrSelectedSessions[x].oFlags["ui-comments"] == "")
                                {
                                    arrSelectedSessions[x].oFlags["ui-comments"] = "(" + currentSequencePos.ToString("D" + 2) + ")";
                                    arrSelectedSessions[x].oFlags["ui-color"] = "black";
                                    arrSelectedSessions[x].oFlags["ui-backcolor"] = "#8bff7e";
                                }
                                else if (arrSelectedSessions[x].oFlags["ui-comments"].StartsWith("[#"))
                                {
                                    arrSelectedSessions[x].oFlags["ui-comments"] = "(" + currentSequencePos.ToString("D" + 2) + ")";
                                    arrSelectedSessions[x].oFlags["ui-color"] = "black";
                                    arrSelectedSessions[x].oFlags["ui-backcolor"] = "#8bff7e";
                                }
                                else
                                {
                                    arrSelectedSessions[x].oFlags["ui-comments"] = "(" + currentSequencePos.ToString("D" + 2) + ") " + arrSelectedSessions[x].oFlags["ui-comments"];
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
    
        
        
        // Call functions      
        public static string OSName = checkOS();
        public static string FiddlerScriptsPath = setFiddlerScriptsPath();
        public static string EKFiddlePath = setEKFiddlePath();
        public static string EKFiddleRegexesPath = setEKFiddleRegexesPath();
        public static string EKFiddleCapturesPath = setEKFiddleCapturesPath();
        public static string EKFiddleArtifactsPath = setEKFiddleArtifactsPath();
        public static string EKFiddleOpenVPNPath = setEKFiddleOpenVPNPath();
        public static string EKFiddleRegexesEditor = setEKFiddleRegexesEditor();
        public static int xtermProcId = setDefaultxtermId();

        // Install EKFiddle
        public static void EKFiddleInstallation()
        {            
            DialogResult dialogEKFiddleInstallation = MessageBox.Show("This will install or update EKFiddle. Please backup your local Regexes before proceeding!!" + "\n" 
             + "\n" + "Are you sure you would like to continue?", "EKFiddle", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if(dialogEKFiddleInstallation == DialogResult.Yes)
            {
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
            // Create custom (blank) regex file
            System.IO.StreamWriter customRegexes = new System.IO.StreamWriter(EKFiddleRegexesPath + "CustomRegexes.txt");
            customRegexes.WriteLine("## This is your custom regexes file");
            customRegexes.WriteLine("## Usage: [Type] TAB [Regex name] TAB [Regex] TAB [Ref/comment (optional)]");
            customRegexes.WriteLine("##  where Type can be: Headers/SourceCode/URI");
            customRegexes.WriteLine("## Examples:");
            customRegexes.WriteLine("##  URI" + "\t" + "myRegex" + "\t" + "[a-z0-9]{2}" + "\t" + "This is a test");
            customRegexes.WriteLine("##  SourceCode" + "\t" + "myOtherRegex" + "\t" + "vml=1" + "\t" + "This is another test");
            customRegexes.Close();
            // Dialog showing installation is done
            MessageBox.Show("EKFiddle has been installed/updated successfully!", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
            // Reload CustomRules
            FiddlerObject.ReloadScript();
            }
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
        
        public static string fileTypeCheck(string sourceCode, string fullResponseHeaders, int responseSize) 
        { // Determine session type (landing page, exploit, payload, etc)
            string fileType;
            if (sourceCode != "" && sourceCode.Length > 20)
            {
                if (Regex.Matches(sourceCode.Substring(0,20), "<html>|<!DOCTYPE HTML|<h[0-9]>", RegexOptions.IgnoreCase).Count > 0)
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
                    else if (sourceCode.Substring(0,3).Contains("PK"))
                    {
                        fileType = "(Silverlight Exploit)";
                        return fileType;
                    } 
                    else if (sourceCode.Substring(0,4).Contains("PNG"))
                    {
                        fileType = "(Stegano)";
                        return fileType;
                    } 
                    else if (fullResponseHeaders.Contains("application/x-msdownload") 
                     || fullResponseHeaders.Contains("application/octet-stream") || sourceCode.Substring(0,2).Contains("MZ"))
                    {
                        fileType = "(Malware Payload)";
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
                
                
        // Function to toggle advanced UI on/off
        [BindUIButton("Advanced UI on/off")]
        public static void EKFiddleFixUI() 
        {
            if (FiddlerApplication.Prefs.GetStringPref("fiddler.advancedUI", null) == "True")
            {
                FiddlerApplication.Prefs.SetStringPref("fiddler.advancedUI", "False");
                MessageBox.Show("Advanced UI has been turned OFF. Please restart Fiddler to apply the changes.", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                arrangeColumns();
                FiddlerApplication.Prefs.SetStringPref("fiddler.advancedUI", "True");
                MessageBox.Show("Advanced UI has been turned ON. Those changes will remain the next time you start Fiddler.", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            FiddlerObject.ReloadScript();
        }
        
        // Function to clear comments and colours
        [BindUIButton("Clear Markings")]
        public static void EKFiddleClearMarkings() 
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
        public static void EKFiddleRunRegexes() 
        {
            if (!System.IO.Directory.Exists(EKFiddlePath) || !System.IO.File.Exists(@EKFiddleRegexesPath + "MasterRegexes.txt") || !System.IO.File.Exists(@EKFiddleRegexesPath + "CustomRegexes.txt"))
            {   // Prompt user to finish installating EKFiddle if the path does not exist yet
                MessageBox.Show("EKFiddle is not installed properly or some Regexes files are missing." + "\n" + "\n" + "Please finish the installation of EKFiddle:"
                + "\n" + "Tools -> EKFiddle -> Install/Update EKFiddle.", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            else
            {
                // Read CustomRegexes and MasterRegexes into different lists
                List<string> headersRegexList = new List<string>();
                List<string> sourceCodeRegexList = new List<string>();
                List<string> URIRegexList = new List<string>();
                
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
                            {
                                // Add to Headers Regex list
                                headersRegexList.Add(line);
                            }
                            if (line.StartsWith("SourceCode"))
                            {
                                // Add to Source Code Regex list
                                sourceCodeRegexList.Add(line);
                            }
                            if (line.StartsWith("URI"))
                            {
                                // Add to URI Regex list
                                URIRegexList.Add(line);
                            }    
                        }
                        reader.Close();
                    }
                }
                
                // Create a new list for malicious sessions
                List<int> maliciousSessionsList = new List<int>();
                // Initialize malicious sessions found variable
                bool maliciousFound = false;
                // Initialize payloadSessionId (for connect-the-dots feature)
                int payloadSessionId = 0;
                // Initialize hostname
                string currentHostname = "";
                // Loop through each sessions
                FiddlerObject.UI.actSelectAll();        
                var arrSessions = FiddlerApplication.UI.GetSelectedSessions();
                for (int x = 0; x < arrSessions.Length; x++)
                {
                    try
                    {
                        // Decode session
                        arrSessions[x].utilDecodeRequest(true);
                        arrSessions[x].utilDecodeResponse(true);
                        // Re-initialize variables
                        String URIRegexName = "";
                        String headerRegexName = "";
                        String sourceCodeRegexName = "";
                        String EKName = "";
                        String fileType = "";
                        // Assign variables
                        // Get current URI regardless of encoding
                        byte[] utfBytes = Encoding.UTF8.GetBytes(arrSessions[x].fullUrl);
                        string hexValue = BitConverter.ToString(utfBytes);
                        hexValue = hexValue.Replace("-", "");
                        String currentURI = hexToString(hexValue);
                        // Get session response headers
                        String fullResponseHeaders = arrSessions[x].oResponse.headers.ToString();
                        // Get session body
                        String sourceCode = arrSessions[x].GetResponseBodyAsString().Replace('\0', '\uFFFD');
                        // Get session body size
                        int responseSize = arrSessions[x].responseBodyBytes.Length;
                        // Begin checking each sesssion against URL patterns, source code and headers.
                        
                        //
                        if (EKName == "")
                        {   // Check against EK URL patterns                
                            foreach (string item in URIRegexList)
                            {
                                Regex UrlPattern = new Regex(item.Split('\t')[2]);                            
                                URIRegexName = item.Split('\t')[1];
                                MatchCollection matches = UrlPattern.Matches(currentURI);
                                if (matches.Count > 0)
                                {                            
                                    EKName = URIRegexName;
                                    break;
                                }
                            }
                        }
                        
                        //
                        if (EKName == "" && (arrSessions[x].oResponse.headers.ExistsAndContains("Content-Type","text/html")
                         || arrSessions[x].oResponse.headers.ExistsAndContains("Content-Type","text/javascript")))
                        {   // Check against source code patterns
                            foreach (string item in sourceCodeRegexList)
                            {
                                Regex sourceCodePattern = new Regex(item.Split('\t')[2]);
                                sourceCodeRegexName = item.Split('\t')[1];
                                MatchCollection matches = sourceCodePattern.Matches(sourceCode);
                                if (matches.Count > 0)
                                {                            
                                    EKName = sourceCodeRegexName;
                                    break;
                                }
                            }
                        }
                        
                        //
                        if (EKName == "")
                        {   // Check against headers patterns
                            foreach (string item in headersRegexList)
                            {
                                Regex headerPattern = new Regex(item.Split('\t')[2]);
                                headerRegexName = item.Split('\t')[1];
                                MatchCollection matches = headerPattern.Matches(fullResponseHeaders);
                                if (matches.Count > 0)
                                {                            
                                    EKName = headerRegexName;
                                    break;
                                }
                            }
                        }
                                                
                        // Add info
                        if (EKName != "")
                        {   
                            // Switch malicious found flag to true
                            maliciousFound = true;
                            
                            // Get file type by calling function
                            fileType = fileTypeCheck(sourceCode, fullResponseHeaders, responseSize);
                    
                            // Flag payload (for connect-the-dots feature)
                            if (fileType == "(Malware Payload)")
                            {
                                payloadSessionId = arrSessions[x].id;
                                // Get Hostname
                                currentHostname = arrSessions[x].hostname;
                            }
                    
                            // Add coments
                            arrSessions[x].oFlags["ui-comments"] = EKName + " " + fileType;
                            if (EKName.Contains("Campaign")) 
                            {   // Colour Malware campaign
                                arrSessions[x].oFlags["ui-comments"] = EKName;
                                arrSessions[x].oFlags["ui-color"] = "white";
                                arrSessions[x].oFlags["ui-backcolor"] = "black";
                            } 
                            else if (fileType.Contains("Landing Page"))
                            {   // Colour Landing pages
                                arrSessions[x].oFlags["ui-color"] = "white";
                                arrSessions[x].oFlags["ui-backcolor"] = "teal";
                            } 
                            else if (fileType.Contains("Exploit"))
                            {   // Colour Exploits (SWF, etc)
                                arrSessions[x].oFlags["ui-color"] = "black";
                                arrSessions[x].oFlags["ui-backcolor"] = "orange";
                            } 
                            else if (fileType == "(Malware Payload)") 
                            {   // Colour Malware payloads
                                arrSessions[x].oFlags["ui-color"] = "white";
                                arrSessions[x].oFlags["ui-backcolor"] = "red";
                            } 
                            else if (EKName.Contains("C2")) 
                            {   // Colour Malware payloads
                                arrSessions[x].oFlags["ui-color"] = "white";
                                arrSessions[x].oFlags["ui-backcolor"] = "purple";
                            } 
                            else 
                            {   // Default colour
                                arrSessions[x].oFlags["ui-color"] = "white";
                                arrSessions[x].oFlags["ui-backcolor"] = "teal";
                            }
                            // Refresh Fiddler UI
                            arrSessions[x].RefreshUI();
                            // Add session number to list
                            //maliciousSessionsList.Add(x+1);
                        } 
                    }
                    catch
                    {
                        FiddlerApplication.UI.SetStatusText("Error decoding session# " + arrSessions[x].id);
                    }
                }
                
                if (payloadSessionId != 0)
                {
                    connectDots(payloadSessionId, currentHostname, maliciousSessionsList);
                }
                
                if (maliciousFound == true)
                {              
                    FiddlerApplication.UI.lvSessions.SelectedItems.Clear();
                    maliciousSessionsList.Sort();
                    string maliciousSessionsString = string.Join(", ", maliciousSessionsList.ToArray());
                    FiddlerApplication.UI.SetStatusText("Malicious traffic found at Session#: " + maliciousSessionsString);
                }
                else
                {
                    FiddlerApplication.UI.lvSessions.SelectedItems.Clear();
                    FiddlerApplication.UI.SetStatusText("No malicious traffic found.");        
                }
            } 
        }  
 
        // Function to view/edit EK / campaign Regexes
        [BindUIButton("View/Edit Regexes")]
        public static void DoOpenRegexes()
        {
            if (!System.IO.Directory.Exists(EKFiddlePath) || !System.IO.File.Exists(@EKFiddleRegexesPath + "MasterRegexes.txt") || !System.IO.File.Exists(@EKFiddleRegexesPath + "CustomRegexes.txt"))
            {   // Prompt user to finish installating EKFiddle if the path does not exist yet
                MessageBox.Show("EKFiddle is not installed properly or some Regexes files are missing." + "\n" + "\n" + "Please finish the installation of EKFiddle:"
                + "\n" + "Tools -> EKFiddle -> Install/Update EKFiddle.", "EKFiddle", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            else
            {
                // Gather information about Master regex file
                var masteRegexCount = 0;
                var fileVersion = "N/A";
                using (var reader = new System.IO.StreamReader(@EKFiddleRegexesPath + "MasterRegexes.txt"))
                    {
                        while (!reader.EndOfStream)
                        {
                            var line = reader.ReadLine();
                            // Count number of regexes in master list
                            if (line.StartsWith("Headers") || line.StartsWith("SourceCode") || line.StartsWith("URI"))
                            {
                                masteRegexCount+=1;
                            }
                            // Find master list version
                            if (line.StartsWith("## Last updated: "))
                            {
                                fileVersion = line.Replace("## Last updated: ", "");
                            }
                        }
                    }
                // Gather information about custom regex file
                var customRegexCount = 0;
                DateTime lastModified = System.IO.File.GetLastWriteTime(@EKFiddleRegexesPath + "CustomRegexes.txt");
                using (var reader = new System.IO.StreamReader(@EKFiddleRegexesPath + "CustomRegexes.txt"))
                    {
                        while (!reader.EndOfStream)
                        {
                            var line = reader.ReadLine();
                            // Count number of regexes in master list
                            if (line.StartsWith("Headers") || line.StartsWith("SourceCode") || line.StartsWith("URI"))
                            {
                                customRegexCount+=1;
                            }
                        }
                }
                // Show user dialog
                DialogResult dialogEKFiddleUninstallation = MessageBox.Show("###################################" + "\n"
                + "MasterRegexes.txt <- from GitHub" + "\n"
                + "###################################" + "\n"
                + "Number of Regexes: " + masteRegexCount + "\n"
                + "Last updated: " + fileVersion + "\n"
                + "\n"
                + "###################################" + "\n"
                + "CustomRegexes.txt <- your own" + "\n"
                + "###################################" + "\n"
                + "Number of Regexes: " + customRegexCount + "\n"
                + "Last updated: " + lastModified.ToString("yyyy-MM-dd") + "\n"
                + "\n" + "\n"
                + "Click 'Yes' to edit CustomRegexes.txt.", "EKFiddle", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
                
                if(dialogEKFiddleUninstallation == DialogResult.Yes)
                {
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
                DialogResult dialogEKRunRegexes = MessageBox.Show("Sucessfully loaded: " + openCapture.SafeFileName + "\n" + "\n" 
                 + "Would you like to run Regexes?", "EKFiddle", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
                if(dialogEKRunRegexes == DialogResult.Yes)
                {
                    EKFiddleRunRegexes();
                }
            }    
        }
    
        // Function to launch VPN
        [BindUIButton("VPN")]
        public static void EKFiddleVPN() 
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
        [BindUIButton("QuickSave")]
        public static void EKFiddleSave() 
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
                EKFiddleRunRegexes();
                return true;
            case "reset": // shortcut to clear sessions of comments, colours, etc
                EKFiddleClearMarkings();
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
