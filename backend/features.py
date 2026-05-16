"""
Feature extraction layer.
Converts ProcessData into a fixed-length numeric vector for the ML classifier.
"""
from __future__ import annotations
from models import ProcessData

OFFICE_APPS     = {"winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","msaccess.exe","mspub.exe"}
BROWSERS        = {"chrome.exe","firefox.exe","msedge.exe","iexplore.exe","opera.exe","brave.exe"}
SCRIPT_HOSTS    = {"wscript.exe","cscript.exe","mshta.exe","powershell.exe","powershell_ise.exe","cmd.exe"}
SYSTEM32_PATHS  = ["\\windows\\system32\\","\\windows\\syswow64\\"]
PROGFILES_PATHS = ["\\program files\\","\\program files (x86)\\"]
TEMP_PATHS      = ["\\temp\\","\\tmp\\"]
SUSPICIOUS_PORTS  = {4444,1337,8888,9001,31337,6666,5555,2222}
COMMON_DEV_PORTS  = {80,443,8080,3000,5000,8000,5432,27017,6379,3306,1433,8888,8443,4200,4000,9229,35729}

DEV_TOOLS = {
    "python.exe","python3.exe","node.exe","electron.exe","code.exe",
    "git.exe","git-remote-https.exe","devenv.exe","rider64.exe",
    "npm.exe","wt.exe","windowsterminal.exe","openconsole.exe",
}
KNOWN_BROWSERS = {"chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","iexplore.exe"}

FEATURE_NAMES = [
    "is_powershell",
    "has_encoded_cmd",
    "has_download_cmd",
    "has_iex",
    "has_ep_bypass",
    "has_hidden_window",
    "is_mshta",
    "is_rundll32",
    "is_regsvr32",
    "is_certutil",
    "is_office_parent",
    "is_browser_parent",
    "is_script_host_parent",
    "from_temp",
    "from_downloads",
    "from_appdata_roaming",
    "from_system32",
    "from_program_files",
    "is_signed",
    "connection_count",
    "has_suspicious_port",
    "has_registry_persist",
    "has_sched_task",
    "is_known_dev_tool",
    "is_known_browser",
    "cmd_is_long",
    "suspicious_flag_count",
    "uses_common_dev_port",
    "has_discovery_cmd",
    "has_lateral_movement_cmd",
    "has_credential_dump_cmd",
]


def extract(proc: ProcessData) -> list[float]:
    name   = proc.name.lower()
    cmd    = proc.command_line.lower()
    path   = proc.path.lower()
    parent = proc.parent_name.lower()

    # Base flags (computed as variables so suspicious_flag_count can reuse them)
    has_encoded_cmd    = float("-enc" in cmd or "-encodedcommand" in cmd)
    has_download_cmd   = float(any(k in cmd for k in ["downloadstring","downloadfile","webclient","invoke-webrequest","wget","curl"]))
    has_iex            = float("iex(" in cmd or "iex " in cmd or "invoke-expression" in cmd)
    has_ep_bypass      = float("-executionpolicy bypass" in cmd or "-ep bypass" in cmd)
    has_hidden_window  = float("-windowstyle hidden" in cmd or "-w hidden" in cmd)
    from_temp          = float(any(p in path for p in TEMP_PATHS))
    from_downloads     = float("\\downloads\\" in path)
    has_registry_persist = float(any(k in cmd for k in ["reg add","currentversion\\run","currentversion\\runonce"]))
    has_sched_task     = float((name in {"schtasks.exe","at.exe"} and "/create" in cmd) or "new-scheduledtask" in cmd)

    # Accumulation: how many independent suspicious signals fire together (0–1 normalized)
    suspicious_flag_count = (
        has_encoded_cmd + has_download_cmd + has_iex + has_ep_bypass +
        has_hidden_window + from_temp + from_downloads +
        has_registry_persist + has_sched_task
    ) / 9.0

    has_discovery_cmd = float(any(k in cmd for k in [
        "whoami", "net user", "net localgroup", "net group", "nltest",
        "ipconfig", "arp -a", "netstat", "systeminfo", "tasklist",
        "get-aduser", "get-adgroup", "get-adcomputer",
    ]))
    has_lateral_movement_cmd = float(any(k in cmd for k in [
        "psexec", "wmic /node", "wmic node", "sc \\\\", "net use \\\\",
        "invoke-wmimethod", "invoke-command", "enter-pssession",
        "new-pssession", "copy-item \\\\" ,
    ]))
    # Exclude critical system processes from self-triggering on their own name in the path
    _CRIT_SYS = {"lsass.exe", "csrss.exe", "wininit.exe", "smss.exe", "winlogon.exe",
                 "services.exe", "spoolsv.exe", "system idle process", "memory compression",
                 "secure system"}
    has_credential_dump_cmd = float(name not in _CRIT_SYS and any(k in cmd for k in [
        "lsass", "ntdsutil", "vssadmin", "reg save", "mimikatz",
        "sekurlsa", "logonpasswords", "comsvcs", "minidump",
        "procdump", "wce ", "fgdump",
    ]))

    return [
        float(name == "powershell.exe"),
        has_encoded_cmd,
        has_download_cmd,
        has_iex,
        has_ep_bypass,
        has_hidden_window,
        float(name == "mshta.exe"),
        float(name == "rundll32.exe"),
        float(name == "regsvr32.exe"),
        float(name == "certutil.exe"),
        float(parent in OFFICE_APPS),
        float(parent in BROWSERS),
        float(parent in SCRIPT_HOSTS),
        from_temp,
        from_downloads,
        float("\\appdata\\roaming\\" in path),
        float(any(p in path for p in SYSTEM32_PATHS)),
        float(any(p in path for p in PROGFILES_PATHS)),
        float(proc.is_signed),
        float(proc.connection_count > 0),
        float(any(p in SUSPICIOUS_PORTS for p in proc.destination_ports)),
        has_registry_persist,
        has_sched_task,
        float(name in DEV_TOOLS),
        float(name in KNOWN_BROWSERS),
        float(len(cmd) > 500),
        suspicious_flag_count,
        float(any(p in COMMON_DEV_PORTS for p in proc.destination_ports)),
        has_discovery_cmd,
        has_lateral_movement_cmd,
        has_credential_dump_cmd,
    ]
