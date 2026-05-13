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
SUSPICIOUS_PORTS = {4444,1337,8888,9001,31337,6666,5555,2222}

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
]


def extract(proc: ProcessData) -> list[float]:
    name   = proc.name.lower()
    cmd    = proc.command_line.lower()
    path   = proc.path.lower()
    parent = proc.parent_name.lower()

    return [
        float(name == "powershell.exe"),
        float("-enc" in cmd or "-encodedcommand" in cmd),
        float(any(k in cmd for k in ["downloadstring","downloadfile","webclient","invoke-webrequest","wget","curl"])),
        float("iex(" in cmd or "iex " in cmd or "invoke-expression" in cmd),
        float("-executionpolicy bypass" in cmd or "-ep bypass" in cmd),
        float("-windowstyle hidden" in cmd or "-w hidden" in cmd),
        float(name == "mshta.exe"),
        float(name == "rundll32.exe"),
        float(name == "regsvr32.exe"),
        float(name == "certutil.exe"),
        float(parent in OFFICE_APPS),
        float(parent in BROWSERS),
        float(parent in SCRIPT_HOSTS),
        float(any(p in path for p in TEMP_PATHS)),
        float("\\downloads\\" in path),
        float("\\appdata\\roaming\\" in path),
        float(any(p in path for p in SYSTEM32_PATHS)),
        float(any(p in path for p in PROGFILES_PATHS)),
        float(proc.is_signed),
        float(min(proc.connection_count, 20)),
        float(any(p in SUSPICIOUS_PORTS for p in proc.destination_ports)),
        float(any(k in cmd for k in ["reg add","currentversion\\run","currentversion\\runonce"])),
        float((name in {"schtasks.exe","at.exe"} and "/create" in cmd) or "new-scheduledtask" in cmd),
    ]
