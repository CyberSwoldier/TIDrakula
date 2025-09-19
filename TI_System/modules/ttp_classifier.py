#!/usr/bin/env python3
"""
TTP Classifier Module for MITRE ATT&CK Framework
File: modules/ttp_classifier.py
"""
import re
from typing import List, Dict, Set, Tuple
import logging

logger = logging.getLogger(__name__)

class TTPClassifier:
    """Classifies text into MITRE ATT&CK TTPs"""
    
    def __init__(self):
        """Initialize the TTP classifier with comprehensive mappings"""
        self._setup_mappings()
        self._setup_actor_patterns()
    
    def _setup_mappings(self):
        """Setup comprehensive TTP pattern mappings"""
        self.mappings = {
            # Initial Access (TA0001)
            r"\bphishing\b": ["Phishing (T1566.002)"],
            r"\bspear\s*phish": ["Spearphishing (T1566.001)"],
            r"\bwhaling\b": ["Whaling (T1566.001)"],
            r"\bsmishing\b|\bsms\s*phish": ["Smishing (T1566.002)"],
            r"\bvishing\b|\bvoice\s*phish": ["Vishing (T1566.004)"],
            r"\bwatering\s*hole\b": ["Drive-by Compromise (T1189)"],
            r"\bmalvertis": ["Malvertising (T1189)"],
            r"\bdrive-?by\s+download\b": ["Drive-by Compromise (T1189)"],
            r"\bsupply\s*chain\b": ["Supply Chain Compromise (T1195)"],
            r"\btrusted\s*relationship\b": ["Trusted Relationship (T1199)"],
            r"\bexternal\s*remote\s*service\b": ["External Remote Services (T1133)"],
            
            # Execution (TA0002)
            r"\bpowershell\b|\bpwsh\b": ["PowerShell (T1059.001)"],
            r"\bcommand[- ]line\b|\bcmd\.exe\b": ["Command-Line Interface (T1059.003)"],
            r"\bwindows\s*management\s*instrumentation\b|\bwmi\b": ["WMI (T1047)"],
            r"\bmacro\b|\bvba\b": ["Malicious Macro (T1137.001)"],
            r"\bscript(?:ing)?\b": ["Scripting (T1059)"],
            r"\bscheduled\s*task\b": ["Scheduled Task (T1053.005)"],
            r"\buser\s*execution\b": ["User Execution (T1204)"],
            
            # Persistence (TA0003)
            r"\bbackdoor\b": ["Backdoor (T1505.003)"],
            r"\bbootkit\b": ["Bootkit (T1542.003)"],
            r"\brootkit\b": ["Rootkit (T1014)"],
            r"\bregistry\s*run\s*key\b": ["Registry Run Keys (T1547.001)"],
            r"\bstartup\s*folder\b": ["Startup Folder (T1547.001)"],
            r"\bweb\s*shell\b": ["Web Shell (T1505.003)"],
            r"\baccount\s*creat": ["Create Account (T1136)"],
            
            # Privilege Escalation (TA0004)
            r"\bprivilege\s*escalation\b": ["Privilege Escalation (TA0004)"],
            r"\buac\s*bypass\b": ["UAC Bypass (T1548.002)"],
            r"\btoken\s*impersonation\b": ["Token Impersonation (T1134)"],
            r"\bdll\s*hijack": ["DLL Hijacking (T1574.001)"],
            r"\bprocess\s*injection\b": ["Process Injection (T1055)"],
            r"\bkernel\s*exploit\b": ["Exploitation for Privilege Escalation (T1068)"],
            
            # Defense Evasion (TA0005)
            r"\bobfuscat": ["Obfuscation (T1027)"],
            r"\banti[- ]?virus\s*(?:evasion|bypass)\b": ["AV Evasion (T1562.001)"],
            r"\bcode\s*sign": ["Code Signing (T1553.002)"],
            r"\bprocess\s*hollow": ["Process Hollowing (T1055.012)"],
            r"\bliving[- ]off[- ]the[- ]land\b|\blotl\b": ["Living off the Land (T1218)"],
            r"\bfileless\b": ["Fileless Malware (T1055)"],
            r"\bdisable\s*security\s*tools\b": ["Impair Defenses (T1562)"],
            
            # Credential Access (TA0006)
            r"\bbrute\s*force\b": ["Brute Force (T1110)"],
            r"\bpassword\s*spray": ["Password Spraying (T1110.003)"],
            r"\bcredential\s*dump": ["Credential Dumping (T1003)"],
            r"\bkeylog": ["Keylogging (T1056.001)"],
            r"\bmfa\s*bypass\b": ["MFA Bypass (T1621)"],
            r"\bpass[- ]the[- ]hash\b": ["Pass the Hash (T1550.002)"],
            r"\bpass[- ]the[- ]ticket\b": ["Pass the Ticket (T1550.003)"],
            r"\bmimikatz\b": ["Credential Dumping (T1003)"],
            
            # Discovery (TA0007)
            r"\bnetwork\s*scan": ["Network Service Scanning (T1046)"],
            r"\bport\s*scan": ["Port Scanning (T1046)"],
            r"\bactive\s*directory\s*enum": ["AD Enumeration (T1087)"],
            r"\bsystem\s*information\s*discovery\b": ["System Information Discovery (T1082)"],
            r"\bfile\s*and\s*directory\s*discovery\b": ["File and Directory Discovery (T1083)"],
            
            # Lateral Movement (TA0008)
            r"\blateral\s*movement\b": ["Lateral Movement (TA0008)"],
            r"\bremote\s*desktop\b|\brdp\b": ["Remote Desktop Protocol (T1021.001)"],
            r"\bssh\b": ["SSH (T1021.004)"],
            r"\bsmb\b": ["SMB/Windows Admin Shares (T1021.002)"],
            r"\bpsexec\b": ["PsExec (T1569.002)"],
            r"\bwmi\s*(?:for\s*)?lateral\b": ["WMI for Lateral Movement (T1047)"],
            
            # Collection (TA0009)
            r"\bdata\s*(?:collection|gathering|harvesting)\b": ["Data Collection (T1005)"],
            r"\bscreen\s*capture\b": ["Screen Capture (T1113)"],
            r"\bclipboard\s*data\b": ["Clipboard Data (T1115)"],
            r"\bemail\s*collection\b": ["Email Collection (T1114)"],
            r"\baudio\s*capture\b": ["Audio Capture (T1123)"],
            r"\bvideo\s*capture\b": ["Video Capture (T1125)"],
            
            # Command and Control (TA0011)
            r"\bc2\b|\bcommand\s*and\s*control\b|\bc&c\b": ["Command and Control (TA0011)"],
            r"\bremote\s*access\s*(?:trojan|tool)\b|\brat\b": ["Remote Access Software (T1219)"],
            r"\bweb\s*service\b": ["Web Service (T1102)"],
            r"\bdns\s*tunnel": ["DNS Tunneling (T1071.004)"],
            r"\btor\b": ["Proxy (T1090)"],
            r"\bdomain\s*fronting\b": ["Domain Fronting (T1090.004)"],
            
            # Exfiltration (TA0010)
            r"\bdata\s*exfiltrat": ["Data Exfiltration (T1041)"],
            r"\bdata\s*theft\b": ["Data Theft (T1005)"],
            r"\bdata\s*breach\b": ["Data Breach (T1005)"],
            r"\bexfiltrat.*cloud\b": ["Exfiltration to Cloud (T1567)"],
            r"\bexfiltrat.*c2\b": ["Exfiltration Over C2 (T1041)"],
            
            # Impact (TA0040)
            r"\bransomware\b": ["Data Encrypted for Impact (T1486)"],
            r"\bdata\s*encrypt": ["Data Encrypted for Impact (T1486)"],
            r"\bdata\s*destruct": ["Data Destruction (T1485)"],
            r"\bwiper\b": ["Disk Wipe (T1561)"],
            r"\bdefacement\b": ["Defacement (T1491)"],
            r"\bdenial[- ]of[- ]service\b|\bddos\b|\bdos\b": ["Network DoS (T1498)"],
            r"\bresource\s*hijacking\b": ["Resource Hijacking (T1496)"],
            r"\bcryptojacking\b|\bcryptomining\b": ["Resource Hijacking (T1496)"],
            
            # Social Engineering
            r"\bsocial\s*engineering\b": ["Social Engineering (T1566 / TA0001)"],
            r"\bpretext": ["Pretexting (T1566.004)"],
            r"\bbait": ["Baiting (T1586.003)"],
            r"\bscam": ["Fraud / Social Engineering (TA0001)"],
            r"\bimpersonat": ["Impersonation (T1656)"],
            r"\bfake\s*(?:persona|profile)\b": ["Fake Online Persona (T1585.001)"],
            r"\bid(?:entity)?\s*theft\b": ["Identity Theft (T1589)"],
            r"\bceo\s*fraud\b|\bbec\b|\bbusiness\s*email\s*compromise\b": ["Business Email Compromise (T1650)"],
            
            # Malware Types
            r"\bmalware\b": ["Malware (TA0002/TA0003)"],
            r"\btrojan\b": ["Trojan (T1204)"],
            r"\bspyware\b": ["Spyware (T1005)"],
            r"\badware\b": ["Adware (T1176)"],
            r"\bbot(?:net)?\b": ["Botnet (T1584.005)"],
            r"\bdownloader\b": ["Downloader (T1105)"],
            r"\bdropper\b": ["Dropper (T1105)"],
            r"\bloader\b": ["Loader (T1055)"],
            r"\binfostealer\b": ["Information Stealer (T1005)"],
            r"\bbanking\s*(?:trojan|malware)\b": ["Banking Malware (T1005)"],
            
            # Exploits
            r"\bexploit\b": ["Exploitation (T1203)"],
            r"\bzero[- ]?day\b|\b0[- ]?day\b": ["Zero-Day Exploit (T1203)"],
            r"\bremote\s*code\s*execution\b|\brce\b": ["RCE (T1203)"],
            r"\bbuffer\s*overflow\b": ["Buffer Overflow (T1203)"],
            r"\bsql\s*injection\b": ["SQL Injection (T1190)"],
            r"\bxss\b|\bcross[- ]site[- ]scripting\b": ["XSS (T1059.007)"],
            r"\bxxe\b|\bxml\s*external\s*entity\b": ["XXE (T1203)"],
            r"\bdeserialization\b": ["Deserialization (T1203)"],
        }
    
    def _setup_actor_patterns(self):
        """Setup threat actor detection patterns"""
        self.actor_patterns = {
            # Russian APTs
            "APT28 (Fancy Bear)": [r"\bapt28\b", r"\bfancy\s*bear\b", r"\bsofacy\b", r"\bstrontium\b", r"\btsar\s*team\b"],
            "APT29 (Cozy Bear)": [r"\bapt29\b", r"\bcozy\s*bear\b", r"\bthe\s*dukes\b", r"\bnobelium\b", r"\bstellarparticle\b"],
            "Sandworm": [r"\bsandworm\b", r"\btelebots\b", r"\bblackenergy\b", r"\bvoodoo\s*bear\b"],
            "Turla": [r"\bturla\b", r"\bsnake\b", r"\buroburos\b", r"\bvenomous\s*bear\b"],
            
            # Chinese APTs
            "APT1": [r"\bapt1\b", r"\bcomment\s*crew\b", r"\bcomment\s*group\b", r"\bshanghai\s*group\b"],
            "APT10": [r"\bapt10\b", r"\bstone\s*panda\b", r"\bmenupass\b", r"\bred\s*apollo\b"],
            "APT41": [r"\bapt41\b", r"\bdouble\s*dragon\b", r"\bbarium\b", r"\bwinnti\b"],
            "Mustang Panda": [r"\bmustang\s*panda\b", r"\bredDelta\b", r"\bbronze\s*president\b"],
            
            # North Korean APTs
            "Lazarus Group": [r"\blazarus\b", r"\bhidden\s*cobra\b", r"\bgods\s*apostles\b", r"\blab