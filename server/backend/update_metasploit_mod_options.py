import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from typing import Literal

import pexpect
from tqdm import tqdm

from app.settings import settings

NUM_WORKERS = 50

MSF_PROMPT = r"msf.*> "
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
MSF_STARTUP_TIMEOUT = 15
MSF_DEFAULT_TIMEOUT = 10
MODULE_NAMES_MAP = {
    "exploits": "exploit",
    "auxiliary": "auxiliary",
    "payloads": "payload",
    "post": "post",
    "encoders": "encoder",
    "nops": "nop",
    "evasion": "evasion",
}


def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE.sub("", text)


def read_until_prompt(session: pexpect.spawn, timeout: int = 10) -> str:
    output = ""
    while True:
        try:
            chunk = session.read_nonblocking(size=100000, timeout=timeout)
            if isinstance(chunk, bytes):
                chunk = chunk.decode()
            output += chunk
            if re.search(MSF_PROMPT, chunk):
                break
        except pexpect.TIMEOUT:
            break
        except pexpect.EOF:
            break
    return output


def parse_options_table(lines: list[str]) -> dict[str, dict[str, str]]:
    options = {}

    header_idx = None
    for i, line in enumerate(lines):
        if line.strip().startswith("Name") and "Current Setting" in line:
            header_idx = i
            break

    if header_idx is None or header_idx + 2 >= len(lines):
        return options

    header = lines[header_idx]

    name_col = header.find("Name")
    setting_col = header.find("Current Setting")
    required_col = header.find("Required")
    desc_col = header.find("Description")

    if any(col == -1 for col in [name_col, setting_col, required_col, desc_col]):
        return options

    for line in lines[header_idx + 2 :]:
        if not line.strip() or line.strip().startswith("-"):
            continue
        stripped = line.lstrip()
        if stripped.startswith("Payload options") or stripped.startswith(
            "Module options"
        ):
            break
        if stripped.startswith("Exploit target"):
            break

        name = line[name_col:setting_col].strip()
        current_setting = line[setting_col:required_col].strip()
        required = line[required_col:desc_col].strip()
        description = line[desc_col:].strip()

        if name and name != "----" and re.match(r"^[A-Za-z][A-Za-z0-9_]*$", name):
            options[name] = {
                "current_setting": current_setting,
                "required": required.lower() == "yes",
                "description": description,
            }

    return options


def parse_options(output: str) -> tuple[dict, dict]:
    clean_output = strip_ansi(output)
    lines = clean_output.split("\n")

    module_options = {}
    payload_options = {}

    module_start = None
    payload_start = None

    for i, line in enumerate(lines):
        if "Module options" in line:
            module_start = i
        elif "Payload options" in line:
            payload_start = i

    if module_start is not None:
        end = payload_start if payload_start else len(lines)
        module_options = parse_options_table(lines[module_start:end])

    if payload_start is not None:
        end = len(lines)
        for i, line in enumerate(lines[payload_start:]):
            if "Exploit target" in line:
                end = payload_start + i
                break
        payload_options = parse_options_table(lines[payload_start:end])

    return module_options, payload_options


def get_module_info(
    module_name: str, session: pexpect.spawn | None = None
) -> dict[str, dict[str, str]] | None:
    owns_session = session is None
    if owns_session:
        session = pexpect.spawn("msfconsole -q", dimensions=(50, 300))
        session.expect(MSF_PROMPT, timeout=MSF_STARTUP_TIMEOUT)

    try:
        session.sendline(f"use {module_name}")
        session.expect(MSF_PROMPT, timeout=MSF_DEFAULT_TIMEOUT)
        session.sendline("options")
        session.expect(MSF_PROMPT, timeout=MSF_DEFAULT_TIMEOUT)
        output = session.before

        if not output:
            print(f"[-] Could not get options output for {module_name}")
            return None

        module_options, payload_options = parse_options(output.decode())
        return {"Module options": module_options, "Payload options": payload_options}
    finally:
        if owns_session:
            session.terminate()


def parse_module_list(output: str) -> list[str]:
    clean_output = strip_ansi(output)
    lines = clean_output.split("\n")

    modules = []

    header_idx = None
    for i, line in enumerate(lines):
        if "Name" in line and "Disclosure Date" in line:
            header_idx = i
            break

    if header_idx is None or header_idx + 2 >= len(lines):
        return modules

    header = lines[header_idx]

    name_col = header.find("Name")
    date_col = header.find("Disclosure Date")

    if name_col == -1 or date_col == -1:
        return modules

    for line in lines[header_idx + 2 :]:
        if not line.strip() or line.strip().startswith("-"):
            continue

        name = line[name_col:date_col].strip()

        if name and name != "----":
            modules.append(name)

    return modules


def get_all_modules_by_type(
    module_type: Literal[
        "exploits", "payloads", "auxiliary", "post", "encoders", "nops", "evasion"
    ],
    session: pexpect.spawn | None = None,
) -> list[str] | None:
    owns_session = session is None
    if owns_session:
        session = pexpect.spawn("msfconsole -q", dimensions=(50, 300))
        session.expect(MSF_PROMPT, timeout=MSF_STARTUP_TIMEOUT)

    try:
        session.sendline(f"show {module_type}")
        output = read_until_prompt(session, timeout=120)

        if not output:
            print(f"[-] Could not get all {module_type} modules")
            return None

        return parse_module_list(output)
    finally:
        if owns_session:
            session.terminate()


def get_metasploit_version() -> dict[str, str] | None:
    err_msg = "[-] Unable to get current Metasploit version"
    try:
        output = subprocess.run(
            ["/usr/bin/msfconsole", "-q", "-x", "version; exit"], capture_output=True
        )
        output = output.stdout.decode()
    except Exception as e:
        print(str(e))
        return None

    if not output:
        print(err_msg)
        return None

    output = strip_ansi(output)
    regex = re.compile(r"(\w+)\s*:\s*(.+)")
    matches = regex.findall(output)
    if matches:
        return {key.strip(): value.strip() for key, value in matches}
    else:
        print(err_msg)
        return None


def get_dump_version() -> dict[str, str] | None:
    try:
        with open(settings.paths.metasploit_mod_info_path) as f:
            data = json.load(f)

        return {"Framework": data["Framework"], "Console": data["Console"]}

    except Exception as e:
        print(f"[-] Failed to get dump version: {e!s}")


def update_needed() -> bool:
    current = get_metasploit_version()
    dump = get_dump_version()

    if not current:
        return False

    if not dump or "Framework" not in dump or "Console" not in dump:
        return True

    return (
        current["Framework"] != dump["Framework"]
        or current["Console"] != dump["Console"]
    )


def flatten_options(module_info: dict) -> dict[str, str]:
    result = {}
    for section in ("Module options", "Payload options"):
        if module_info.get(section):
            for name, opts in module_info[section].items():
                result[name] = opts["current_setting"]
    return result


def worker_fetch_options(
    modules: list[str],
    results: dict,
    lock: Lock,
    pbar: tqdm,
) -> None:
    session = pexpect.spawn("msfconsole -q", dimensions=(50, 300))
    session.expect(MSF_PROMPT, timeout=MSF_STARTUP_TIMEOUT)

    try:
        for module_name in modules:
            info = get_module_info(module_name, session)
            if info:
                with lock:
                    results[module_name] = flatten_options(info)
            with lock:
                pbar.update(1)
    finally:
        session.terminate()


if __name__ == "__main__":
    if not update_needed():
        print("[*] Metasploit options dump is up to date")
        exit(0)

    print("[*] Updating Metasploit options dump...")
    print("[*] Fetching all module names")

    session = pexpect.spawn("msfconsole -q", dimensions=(50, 300))
    session.expect(MSF_PROMPT, timeout=MSF_STARTUP_TIMEOUT)

    module_names = {}
    try:
        for module_type in (
            "exploits",
            "auxiliary",
            "payloads",
            "post",
            "encoders",
            "nops",
            "evasion",
        ):
            key = MODULE_NAMES_MAP[module_type]
            module_names[key] = get_all_modules_by_type(module_type, session)
            print(f"[+] Got {len(module_names[key])} {key} modules")
    finally:
        session.terminate()

    version = get_metasploit_version()
    if not version:
        print("[-] Failed to get Metasploit version")
        sys.exit(1)

    output: dict[str, str | dict[str, str]] = {
        "Framework": version["Framework"],
        "Console": version["Console"],
    }

    all_modules = []
    for module_type in (
        "exploit",
        "auxiliary",
        "payload",
        "post",
        "encoder",
        "nop",
        "evasion",
    ):
        all_modules.extend(module_names.get(module_type, []))

    print(
        f"[*] Fetching options for {len(all_modules)} modules using {NUM_WORKERS} workers"
    )

    chunk_size = len(all_modules) // NUM_WORKERS + 1
    chunks = [
        all_modules[i : i + chunk_size] for i in range(0, len(all_modules), chunk_size)
    ]

    lock = Lock()
    with tqdm(
        total=len(all_modules), desc="Fetching module options"
    ) as pbar, ThreadPoolExecutor(max_workers=NUM_WORKERS) as executor:
        futures = [
            executor.submit(worker_fetch_options, chunk, output, lock, pbar)
            for chunk in chunks
        ]
        for future in as_completed(futures):
            future.result()

    print(f"[*] Writing to {settings.paths.metasploit_mod_info_path}")
    with open(settings.paths.metasploit_mod_info_path, "w") as f:
        json.dump(output, f, indent=2)

    print("[+] Done!")
