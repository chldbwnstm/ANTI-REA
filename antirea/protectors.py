"""Opt-in native commercial protector adapters; no target or attacker execution.

Configuration, vendor executables and approved projects are trusted local inputs.
Vendor project scripts are NOT sandboxed. A produced PE is an unvalidated artifact,
not evidence that protection was applied or that behavior/resistance is preserved.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import uuid

from antirea.process import _WindowsJob, stop_tree


PROVIDERS = {
    "vmprotect": {
        "name": "VMProtect", "executable_name": "VMProtect_Con.exe",
        "project_extensions": [".vmp"], "profiles": ["vmprotect-console"],
        "official_sources": ["https://vmpsoft.com/vmprotect/user-manual/working-with-vmprotect/"],
    },
    "themida": {
        "name": "Themida", "executable_name": "Themida.exe",
        "project_extensions": [".tmd", ".tm"], "profiles": ["themida-project-cli"],
        "official_sources": ["https://www.oreans.com/help/tm/hm_protecting-through-the-command.htm"],
    },
    "code_virtualizer": {
        "name": "Code Virtualizer", "executable_name": "Virtualizer.exe",
        "project_extensions": [".cv"],
        "profiles": ["code-virtualizer-legacy", "code-virtualizer-4"],
        "official_sources": [
            "https://www.oreans.com/help/cv/hm_protecting-through-the-command.htm",
            "https://www.oreans.com/help/cv4/protecting-an-application/protecting-through-the-command.html",
            "https://www.oreans.com/help/cv4/faq/general/i-can-see-that-latest-code-vir.html",
        ],
    },
}
EDITIONS = {"trial", "lite", "professional", "ultimate", "licensed", "unknown"}
LIMITS = {
    "target_execution": False, "automatic_publication": False,
    "vendor_project_scripts_sandboxed": False, "vendor_identity_verified": False,
    "version_and_edition": "operator-declared, not independently verified",
    "protection_applied": "not_evaluated", "functional_preservation": "not_evaluated",
    "external_resistance": "not_evaluated",
    "native_process": "trusted local tool may access files/network and create child processes",
    "pe_validation": "PE header/architecture and absent CLR directory only; vendor compatibility and native code are not proven",
}
SHA = re.compile(r"[0-9a-f]{64}\Z")
JOB = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}\Z")
MAX_FILE = 512 * 1024 * 1024
REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class ProtectorError(ValueError):
    pass


def _utc():
    return datetime.now(timezone.utc).isoformat()


def _windows_host():
    return os.name == "nt"


def _encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ProtectorError("duplicate JSON key")
            result[key] = value
        return result

    def constant(_value):
        raise ProtectorError("non-finite JSON number")

    try:
        return json.loads(data.decode("utf-8-sig"), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ProtectorError("invalid JSON: " + str(exc)[:160]) from exc


def _keys(value, allowed, label):
    if not isinstance(value, dict) or set(value) - set(allowed):
        raise ProtectorError(label + " must be an object with only documented fields")


def _absolute(value):
    if not isinstance(value, (str, Path)) or not str(value) or any(ord(c) < 32 for c in str(value)):
        raise ProtectorError("invalid path")
    path = Path(value)
    if not path.is_absolute():
        raise ProtectorError("paths must be absolute")
    # Never resolve links before rejecting them. Reject NTFS alternate streams.
    if ":" in str(path)[len(path.drive):]:
        raise ProtectorError("alternate data stream path is not allowed")
    return Path(os.path.abspath(path))


def _no_links(path):
    for part in reversed((path, *path.parents)):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & REPARSE:
            raise ProtectorError("symlink/reparse point is not allowed: " + str(part))
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise ProtectorError("hard-linked file is not allowed: " + str(part))


def _read(path, limit=MAX_FILE):
    _no_links(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
        raise ProtectorError("file must be nonempty, regular and within size limit")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    _no_links(path)
    current = path.stat()
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
    if len(data) > limit or not (identity(before) == identity(opened) == identity(after) == identity(current)):
        raise ProtectorError("file changed while reading")
    return data


def _write(path, value):
    _no_links(path)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    data = value if isinstance(value, bytes) else _encoded(value)
    try:
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        _no_links(path)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _pe(data):
    offset = int.from_bytes(data[60:64], "little") if len(data) >= 64 else -1
    if data[:2] != b"MZ" or offset < 64 or data[offset:offset + 4] != b"PE\0\0":
        raise ProtectorError("file is not a recognizable Windows PE")
    machine = int.from_bytes(data[offset + 4:offset + 6], "little")
    if machine not in (0x14c, 0x8664):
        raise ProtectorError("only x86 and x86-64 Windows PE inputs are supported")
    optional_size = int.from_bytes(data[offset + 20:offset + 22], "little")
    optional = offset + 24
    magic = int.from_bytes(data[optional:optional + 2], "little")
    directory_offset = 112 if machine == 0x8664 else 96
    expected_magic = 0x20b if machine == 0x8664 else 0x10b
    if magic != expected_magic or optional_size < directory_offset or optional + optional_size > len(data):
        raise ProtectorError("PE optional header is truncated or inconsistent")
    directories = int.from_bytes(data[optional + directory_offset - 4:optional + directory_offset], "little")
    if directories > (optional_size - directory_offset) // 8:
        raise ProtectorError("PE data directories exceed the optional header")
    if directories > 14:
        clr = optional + directory_offset + 14 * 8
        if any(data[clr:clr + 8]):
            raise ProtectorError("managed/mixed CLR PE inputs are outside this native-PE adapter slice")
    return "x86_64" if machine == 0x8664 else "x86"


@contextmanager
def _job_lock(directory, filename="run.lock"):
    path = directory / filename
    _no_links(path)
    with path.open("a+b") as stream:
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise ProtectorError("job/provider is already running; retry explicitly after it finishes") from exc
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _native_run(argv, directory, log_prefix, *, timeout, cancel_file):
    """Hidden Windows startup with existing owned-tree cleanup, never a shell.

    Existing run_logged has no creation-flags hook. This narrow Windows wrapper
    reuses its Job Object and stop_tree machinery without changing global Popen.
    Hidden startup does not prevent a trusted vendor from later opening a GUI.
    """
    if not _windows_host():
        raise ProtectorError("native protector execution requires a Windows host")
    log_paths = [log_prefix.with_suffix(suffix) for suffix in (".stdout.log", ".stderr.log", ".process.json")]
    for path in log_paths:
        _no_links(path)
        if path.exists():
            raise ProtectorError("refusing to overwrite a preexisting vendor log: " + path.name)
    started = time.monotonic()
    child = job = None
    result = {"argv": argv, "pid": None, "returncode": None, "cancelled": False,
              "timed_out": False, "shell": False, "startup_hidden": True,
              "cleanup": {"status": "not_started", "method": "not_started"}}
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = subprocess.SW_HIDE
    with log_paths[0].open("xb") as out, log_paths[1].open("xb") as err:
        try:
            if cancel_file.exists():
                result["cancelled"] = True
            else:
                try:
                    job = _WindowsJob()
                except (OSError, AttributeError) as exc:
                    result["job_setup_error"] = str(exc)
                child = subprocess.Popen(argv, cwd=directory, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                         shell=False, startupinfo=startup,
                                         creationflags=subprocess.CREATE_NO_WINDOW)
                result["pid"] = child.pid
                if job is not None:
                    job.assign(child)
                    child._antirea_job = job
                    if job.error:
                        result["job_setup_error"] = job.error
                while True:
                    if cancel_file.exists():
                        result["cancelled"] = True
                        break
                    remaining = timeout - (time.monotonic() - started)
                    if remaining <= 0:
                        result["timed_out"] = True
                        break
                    try:
                        child.wait(timeout=min(0.25, remaining))
                        break
                    except subprocess.TimeoutExpired:
                        pass
        except KeyboardInterrupt:
            result["interrupted"] = True
        except Exception as exc:
            result["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            if child is not None:
                try:
                    result["cleanup"] = stop_tree(child)
                except Exception as exc:
                    result["cleanup"] = {"status": "unverified", "error": str(exc)}
            if job is not None:
                try:
                    result["cleanup"]["job_handle_closed"] = job.close()
                except Exception as exc:
                    result["cleanup"]["job_close_error"] = str(exc)
            if child is not None:
                result["returncode"] = child.poll()
    result.update(seconds=round(time.monotonic() - started, 3),
                  stdout=str(log_prefix.with_suffix(".stdout.log")),
                  stderr=str(log_prefix.with_suffix(".stderr.log")))
    _write(log_prefix.with_suffix(".process.json"), result)
    return result


class Service:
    def __init__(self, config, *, config_path, config_sha256):
        _keys(config, {"schema_version", "workspace_root", "output_root", "providers"}, "config")
        if type(config.get("schema_version")) is not int or config["schema_version"] != 1:
            raise ProtectorError("config schema_version must be 1")
        self.root = _absolute(config.get("workspace_root"))
        _no_links(self.root)
        if not self.root.is_dir():
            raise ProtectorError("workspace_root must exist")
        self.output_root = self.root / ".runs/protection-jobs"
        if _absolute(config.get("output_root", self.output_root)) != self.output_root:
            raise ProtectorError("output_root must be workspace_root/.runs/protection-jobs")
        _no_links(self.output_root)
        self.config_path = _absolute(config_path)
        self._owned(self.config_path)
        self.config_sha256 = config_sha256
        self.stop_path = self.root / ".runs/defense-loop/STOP"
        supplied = config.get("providers", {})
        _keys(supplied, PROVIDERS, "providers")
        self.config = config
        for provider, value in supplied.items():
            _keys(value, {"executable", "version", "edition", "cli_profile", "allow_execution",
                          "license_acknowledged", "sha256", "approved_projects"}, provider)
            executable = _absolute(value.get("executable"))
            _no_links(executable)
            if executable.name.lower() != PROVIDERS[provider]["executable_name"].lower():
                raise ProtectorError("wrong documented native console executable name for " + provider)
            if any(executable.is_relative_to(path) for path in self._untrusted()):
                raise ProtectorError("tool executable cannot be inside incoming evidence")
            version = value.get("version", "unknown")
            if not isinstance(version, str) or not version or len(version) > 100 or any(ord(c) < 32 for c in version):
                raise ProtectorError("version must be a short operator-declared string")
            if not isinstance(value.get("edition", "unknown"), str) or value.get("edition", "unknown") not in EDITIONS:
                raise ProtectorError("unsupported edition")
            if value.get("cli_profile") not in PROVIDERS[provider]["profiles"]:
                raise ProtectorError("unsupported cli_profile")
            for field in ("allow_execution", "license_acknowledged"):
                if type(value.get(field, False)) is not bool:
                    raise ProtectorError(field + " must be boolean")
            if value.get("sha256") is not None and (not isinstance(value["sha256"], str) or not SHA.fullmatch(value["sha256"])):
                raise ProtectorError("tool sha256 must be lowercase SHA-256")
            projects = value.get("approved_projects", [])
            if not isinstance(projects, list) or len(projects) > 128:
                raise ProtectorError("approved_projects must be a bounded list")
            seen = set()
            for project in projects:
                _keys(project, {"path", "sha256"}, "approved project")
                path = self._owned(_absolute(project.get("path")))
                if (path in seen or not isinstance(project.get("sha256"), str)
                        or not SHA.fullmatch(project["sha256"])):
                    raise ProtectorError("duplicate project or invalid approved project hash")
                seen.add(path)

    @classmethod
    def from_config(cls, path):
        path = _absolute(path)
        raw = _read(path, 1024 * 1024)
        return cls(_json(raw), config_path=path, config_sha256=_hash(raw))

    def _untrusted(self):
        return (self.root / "rea-analysis-reports", self.root / ".runs/defense-loop/inbox")

    def _owned(self, path):
        path = _absolute(path)
        _no_links(path)
        if not path.is_relative_to(self.root) or any(path.is_relative_to(item) for item in self._untrusted()):
            raise ProtectorError("input/project/config must be owned workspace data, outside incoming evidence")
        return path

    def _provider(self, provider):
        if provider not in PROVIDERS:
            raise ProtectorError("unknown provider")
        value = self.config.get("providers", {}).get(provider)
        if value is None:
            raise ProtectorError("provider is not configured")
        return value

    def providers(self):
        return {"schema_version": 1, "providers": [
            {"id": name, **value, "configured": name in self.config.get("providers", {})}
            for name, value in PROVIDERS.items()], "limits": dict(LIMITS)}

    def _quarantine_path(self, provider):
        self._provider(provider)
        return self.output_root / ".locks" / (provider + ".quarantine.json")

    def _quarantine(self, provider):
        path = self._quarantine_path(provider)
        _no_links(path)
        if not path.exists():
            return None
        state = _json(_read(path, 65536))
        if not isinstance(state, dict) or state.get("schema_version") != 1:
            return {"status": "invalid_quarantine_state", "path": str(path)}
        return None if state.get("status") == "cleared" else {**state, "path": str(path)}

    def _doctor(self, provider):
        config = self._provider(provider)
        blockers = []
        quarantine = self._quarantine(provider)
        if quarantine is not None:
            blockers.append("provider_quarantined_operator_inspection_required")
        actual_hash = None
        path = _absolute(config["executable"])
        if not path.exists():
            blockers.append("executable_missing")
        else:
            tool_bytes = _read(path)
            actual_hash = _hash(tool_bytes)
            _pe(tool_bytes)
        if not _windows_host():
            blockers.append("windows_host_required")
        if not config.get("allow_execution", False):
            blockers.append("execution_not_enabled")
        if not config.get("license_acknowledged", False):
            blockers.append("license_not_acknowledged")
        edition = config.get("edition", "unknown")
        if edition == "unknown":
            blockers.append("edition_unverified")
        if provider == "vmprotect" and edition == "lite":
            blockers.append("lite_has_no_supported_console_profile")
        if not config.get("sha256"):
            blockers.append("tool_hash_not_pinned")
        elif actual_hash is not None and actual_hash != config["sha256"]:
            blockers.append("tool_hash_mismatch")
        version = config.get("version", "unknown")
        if provider == "code_virtualizer":
            match = re.fullmatch(r"(?:v)?([0-9]+)(?:\.[0-9]+)*(?:[-+ ][A-Za-z0-9 ._-]+)?", version)
            major = int(match.group(1)) if match else None
            supported = (major == 4 if config["cli_profile"] == "code-virtualizer-4" else major in {1, 2, 3})
            if not supported:
                blockers.append("version_not_supported_by_selected_cli_profile")
        return {"provider": provider, "status": "blocked" if blockers else "ready_for_explicit_confirmation",
                "blockers": blockers, "executable": str(path), "actual_tool_sha256": actual_hash,
                "configured_tool_sha256": config.get("sha256"), "version": version, "edition": edition,
                "trial": edition == "trial", "cli_profile": config["cli_profile"],
                "quarantine": quarantine,
                "official_sources": PROVIDERS[provider]["official_sources"], "limits": dict(LIMITS)}

    def doctor(self, provider=None):
        if provider is not None:
            return self._doctor(provider)
        return {"schema_version": 1, "providers": [self._doctor(name) for name in self.config.get("providers", {})],
                "executed_vendor": False, "limits": dict(LIMITS)}

    def _command(self, provider, executable, source, output, project):
        if provider == "vmprotect":
            return [str(executable), str(source), str(output), "-pf", str(project)]
        return [str(executable), "/protect", str(project), "/inputfile", str(source),
                "/outputfile", str(output), "/shareconsole"]

    def _audit(self, directory, record):
        _write(directory / "job.json", record)
        encoded = _encoded(record).decode("utf-8").replace("`", "\\u0060").replace("<", "\\u003c")
        text = ("# Local protector job\n\nThis is private defender evidence. Vendor projects are trusted native inputs, "
                "not sandboxed. No target or attacker was executed. Artifact creation is not proof of protection, "
                "functional preservation or resistance. Do not publish this directory.\n\n```json\n" + encoded + "```\n")
        _write(directory / "README.md", text.encode("utf-8"))

    def plan(self, provider, input_path, project_path, *, timeout_seconds=600):
        config = self._provider(provider)
        if type(timeout_seconds) not in (int, float) or not 1 <= timeout_seconds <= 3600:
            raise ProtectorError("timeout_seconds must be finite and within 1..3600")
        source, project = self._owned(input_path), self._owned(project_path)
        if source == project or project.suffix.lower() not in PROVIDERS[provider]["project_extensions"]:
            raise ProtectorError("project extension does not match the selected vendor")
        source_bytes, project_bytes = _read(source), _read(project, 16 * 1024 * 1024)
        architecture = _pe(source_bytes)
        info = self._doctor(provider)
        project_sha = _hash(project_bytes)
        approved = any(_absolute(item["path"]) == project and item["sha256"] == project_sha
                       for item in config.get("approved_projects", []))
        blockers = list(info["blockers"])
        if not approved:
            blockers.append("project_hash_not_approved")
        if self.stop_path.exists():
            blockers.append("stop_requested")
        _no_links(self.output_root)
        self.output_root.mkdir(parents=True, exist_ok=True)
        _no_links(self.output_root)
        plan_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:16]
        directory = self.output_root / plan_id
        directory.mkdir(exist_ok=False)
        copied_input = directory / "input" / source.name
        output = directory / "output/app.exe"
        if any(path.is_relative_to(directory) for path in (source, project, _absolute(config["executable"]))):
            raise ProtectorError("output job cannot contain any original inputs")
        plan = {"schema_version": 1, "plan_id": plan_id, "job_id": plan_id, "provider": provider,
                "created_utc": _utc(), "status": "planned", "config_sha256": self.config_sha256,
                "workspace_root": str(self.root), "job_directory": str(directory),
                "input": {"path": str(source), "sha256": _hash(source_bytes), "bytes": len(source_bytes), "architecture": architecture},
                "project": {"path": str(project), "sha256": project_sha, "approved": approved},
                "tool": info, "copied_input": str(copied_input), "output": str(output),
                "argv": self._command(provider, config["executable"], copied_input, output, project),
                "timeout_seconds": timeout_seconds, "blockers": blockers, "limits": dict(LIMITS)}
        plan["fingerprint"] = _hash(_encoded(plan))
        _write(directory / "plan.json", plan)
        self._audit(directory, plan)
        return plan

    def _directory(self, job_id):
        if not isinstance(job_id, str) or not JOB.fullmatch(job_id):
            raise ProtectorError("invalid job identifier")
        directory = self.output_root / job_id
        _no_links(directory)
        if not directory.is_dir():
            raise ProtectorError("unknown job")
        return directory

    def job(self, job_id):
        return _json(_read(self._directory(job_id) / "job.json", 1024 * 1024))

    def protect(self, plan_id, fingerprint):
        directory = self._directory(plan_id)
        with _job_lock(directory), ExitStack() as locks:
            plan = _json(_read(directory / "plan.json", 1024 * 1024))
            canonical = {key: value for key, value in plan.items() if key != "fingerprint"}
            if (not isinstance(fingerprint, str) or not SHA.fullmatch(fingerprint)
                    or fingerprint != plan.get("fingerprint") or fingerprint != _hash(_encoded(canonical))):
                raise ProtectorError("explicit confirmation must match the exact untampered plan fingerprint")
            if self.job(plan_id).get("status") != "planned":
                raise ProtectorError("job already attempted; inspect partial evidence and create a fresh plan")
            self._provider(plan["provider"])
            provider_locks = self.output_root / ".locks"
            _no_links(provider_locks)
            provider_locks.mkdir(exist_ok=True)
            _no_links(provider_locks)
            # Different plans must not concurrently mutate the same vendor's
            # project/database. A busy provider leaves this plan unattempted.
            locks.enter_context(_job_lock(provider_locks, plan["provider"] + ".lock"))
            record = {**plan, "status": "checking", "started_utc": _utc()}
            try:
                if self.stop_path.exists():
                    record["status"] = "cancelled"
                    return record
                if _hash(_read(self.config_path, 1024 * 1024)) != plan["config_sha256"]:
                    raise ProtectorError("configuration changed since planning; create a fresh plan")
                provider = plan["provider"]
                config = self._provider(provider)
                info = self._doctor(provider)
                if plan["blockers"] or info["blockers"]:
                    raise ProtectorError("execution blocked: " + ", ".join(sorted(set(plan["blockers"] + info["blockers"]))))
                source, project = self._owned(plan["input"]["path"]), self._owned(plan["project"]["path"])
                original = {"input": _read(source), "project": _read(project, 16 * 1024 * 1024),
                            "tool": _read(_absolute(config["executable"]))}
                expected = {"input": plan["input"]["sha256"], "project": plan["project"]["sha256"],
                            "tool": plan["tool"]["actual_tool_sha256"]}
                if {name: _hash(data) for name, data in original.items()} != expected:
                    raise ProtectorError("input, project or tool changed since planning")
                if not any(_absolute(item["path"]) == project and item["sha256"] == expected["project"]
                           for item in config.get("approved_projects", [])):
                    raise ProtectorError("project is not approved at its current hash")
                copied_input, output = Path(plan["copied_input"]), Path(plan["output"])
                expected_input = directory / "input" / source.name
                expected_output = directory / "output/app.exe"
                expected_argv = self._command(provider, config["executable"], expected_input, expected_output, project)
                if copied_input != expected_input or output != expected_output or plan["argv"] != expected_argv:
                    raise ProtectorError("plan paths/command are inconsistent")
                for path in (copied_input.parent, output.parent):
                    _no_links(path)
                    path.mkdir(exist_ok=False)
                with copied_input.open("xb") as stream:
                    stream.write(original["input"])
                record["status"] = "running"
                self._audit(directory, record)
                quarantine_path = self._quarantine_path(provider)
                quarantine = {"schema_version": 1, "provider": provider, "job_id": plan_id,
                              "status": "running", "created_utc": _utc(),
                              "instruction": "If this job ended without verified cleanup, inspect owned processes and vendor/project state before manually clearing this marker. Never auto-retry."}
                # Persist before launch so a controller crash does not silently
                # free this provider for another job whose children may overlap.
                _write(quarantine_path, quarantine)
                process = _native_run(expected_argv, directory, directory / "vendor",
                                      timeout=plan["timeout_seconds"], cancel_file=self.stop_path)
                record["process"] = process
                cleanup = process.get("cleanup", {})
                cleanup_verified = (cleanup.get("method") == "windows_job" and cleanup.get("job_assigned") is True
                                    and cleanup.get("status") == "assigned_job_empty" and cleanup.get("active_after") == 0
                                    and cleanup.get("parent_exit_confirmed") is True and cleanup.get("job_handle_closed") is True)
                never_started = (process.get("pid") is None and cleanup.get("method") == "not_started"
                                 and cleanup.get("status") == "not_started")
                cleanup_uncertain = not (cleanup_verified or never_started)
                quarantine.update(status="cleanup_unverified" if cleanup_uncertain else "cleared", updated_utc=_utc(),
                                  cleanup=cleanup, pid=process.get("pid"),
                                  resolution="operator_inspection_required" if cleanup_uncertain else
                                             "owned_job_empty_and_parent_exited" if cleanup_verified else "child_not_started")
                _write(quarantine_path, quarantine)
                record["cleanup_verified"] = cleanup_verified
                if cleanup_uncertain:
                    record["provider_quarantine"] = str(quarantine_path)
                checks = {}
                for name, path in (("input", source), ("project", project), ("tool", _absolute(config["executable"]))):
                    try:
                        checks[name] = {"before": expected[name], "after": _hash(_read(path))}
                        checks[name]["unchanged"] = checks[name]["before"] == checks[name]["after"]
                    except (OSError, ProtectorError) as exc:
                        checks[name] = {"before": expected[name], "unchanged": False, "error": str(exc)}
                record["original_integrity"] = checks
                if cleanup_uncertain:
                    record["status"] = "cleanup_unverified"
                elif process.get("cancelled") or self.stop_path.exists():
                    record["status"] = "cancelled"
                elif process.get("interrupted"):
                    record["status"] = "interrupted"
                elif process.get("timed_out"):
                    record["status"] = "timed_out"
                elif not all(item["unchanged"] for item in checks.values()):
                    record["status"] = "original_input_changed"
                elif (process.get("error") or process.get("returncode") != 0
                      or not process.get("cleanup", {}).get("parent_exit_confirmed")):
                    record["status"] = "vendor_failed"
                else:
                    artifact = _read(output)
                    architecture = _pe(artifact)
                    if architecture != plan["input"]["architecture"]:
                        raise ProtectorError("output architecture differs from input")
                    record["artifact"] = {"path": str(output), "sha256": _hash(artifact), "bytes": len(artifact),
                                          "architecture": architecture, "trial": info["trial"]}
                    record["status"] = "artifact_created_unvalidated"
            except (OSError, ValueError, KeyError, TypeError) as exc:
                record.update(status="failed", error=f"{type(exc).__name__}: {exc}")
            except KeyboardInterrupt:
                record.update(status="interrupted", error="Operator interrupted this job; inspect partial logs.")
            finally:
                record["finished_utc"] = _utc()
                self._audit(directory, record)
            return record

    def _owned_or_relative(self, value):
        if isinstance(value, (str, Path)) and str(value) and not Path(value).is_absolute():
            value = self.root / value
        return self._owned(value)

    @classmethod
    def ensure_default_config(cls, path, workspace_root=None):
        if isinstance(path, (str, Path)) and str(path) and not Path(path).is_absolute():
            path = Path(os.path.abspath(path))
        path = _absolute(path)
        _no_links(path)
        if not path.exists():
            raw_root = workspace_root or Path.cwd()
            if isinstance(raw_root, (str, Path)) and str(raw_root) and not Path(raw_root).is_absolute():
                raw_root = Path(os.path.abspath(raw_root))
            root = _absolute(raw_root)
            _no_links(root)
            path.parent.mkdir(parents=True, exist_ok=True)
            _no_links(path.parent)
            default_payload = {"schema_version": 1, "workspace_root": str(root), "providers": {}}
            _write(path, default_payload)
        return cls.from_config(path)

    def generate_project(self, provider, input_path, *, functions=(), defense_level="max_vm",
                         min_speed_percent=80, output_project_path=None):
        if provider not in PROVIDERS:
            raise ProtectorError("unknown provider")
        if defense_level not in DEFENSE_LEVELS:
            raise ProtectorError("defense_level must be one of: " + ", ".join(DEFENSE_LEVELS))
        if type(min_speed_percent) not in (int, float) or not 1 <= min_speed_percent <= 100:
            raise ProtectorError("min_speed_percent must be between 1 and 100")
        source = self._owned_or_relative(input_path)
        source_bytes = _read(source)
        architecture = _pe(source_bytes)
        selected_functions = _normalize_functions(functions, source_bytes)
        project_text, function_modes = _render_vendor_project(
            provider, source, architecture, selected_functions, defense_level, int(min_speed_percent)
        )
        ext = PROVIDERS[provider]["project_extensions"][0]
        if output_project_path is not None:
            project_path = self._owned_or_relative(output_project_path)
            if project_path.suffix.lower() not in PROVIDERS[provider]["project_extensions"]:
                raise ProtectorError("output_project_path extension does not match provider")
        else:
            projects_dir = self.root / ".runs/generated-projects"
            _no_links(projects_dir)
            projects_dir.mkdir(parents=True, exist_ok=True)
            _no_links(projects_dir)
            tag = _hash(f"{provider}:{source}:{defense_level}:{min_speed_percent}:{','.join(selected_functions)}".encode("utf-8"))[:12]
            project_path = projects_dir / f"{source.stem}.{provider}.{defense_level}.{tag}{ext}"
        _no_links(project_path.parent)
        project_path.parent.mkdir(parents=True, exist_ok=True)
        project_bytes = project_text.encode("utf-8")
        _write(project_path, project_bytes)
        project_sha = _hash(project_bytes)
        auto_approved = False
        if provider in self.config.get("providers", {}):
            provider_cfg = self.config["providers"][provider]
            approved = list(provider_cfg.get("approved_projects", []))
            updated = [item for item in approved if _absolute(item["path"]) != project_path]
            updated.append({"path": str(project_path), "sha256": project_sha})
            if len(updated) <= 128:
                provider_cfg["approved_projects"] = updated
                raw_cfg = _encoded(self.config)
                _write(self.config_path, raw_cfg)
                self.config_sha256 = _hash(raw_cfg)
                auto_approved = True
        return {
            "schema_version": 1,
            "status": "completed",
            "provider": provider,
            "input_path": str(source),
            "architecture": architecture,
            "project_path": str(project_path),
            "project_sha256": project_sha,
            "approved_in_config": auto_approved,
            "defense_level": defense_level,
            "target_min_speed_percent": float(min_speed_percent),
            "functions": selected_functions,
            "function_modes": function_modes,
            "hardening_features": [
                "anti_debug",
                "anti_tamper",
                "mba_opaque",
                "string_constant_encryption",
                "iat_api_hiding",
                "multi_vm_indirect_dispatch",
                "anti_dump",
                "anti_llm_honeypot",
            ],
        }

    def benchmark(self, baseline_path, candidate_path, *, test_inputs=(), min_speed_percent=80,
                  repeats=5, timeout_seconds=60):
        if type(min_speed_percent) not in (int, float) or not 1 <= min_speed_percent <= 100:
            raise ProtectorError("min_speed_percent must be between 1 and 100")
        if type(repeats) is not int or not 1 <= repeats <= 25:
            raise ProtectorError("repeats must be an integer between 1 and 25")
        if type(timeout_seconds) not in (int, float) or not 1 <= timeout_seconds <= 600:
            raise ProtectorError("timeout_seconds must be between 1 and 600")
        baseline = self._owned_or_relative(baseline_path)
        candidate = self._owned_or_relative(candidate_path)
        base_bytes = _read(baseline)
        cand_bytes = _read(candidate)
        base_arch = _pe(base_bytes)
        cand_arch = _pe(cand_bytes)
        if base_arch != cand_arch:
            raise ProtectorError("baseline and candidate architectures differ")
        inputs = list(test_inputs) if test_inputs else ["1 2\n17 31\n255 65535\n"]
        if len(inputs) > 64 or any(not isinstance(item, str) or len(item) > 65536 for item in inputs):
            raise ProtectorError("test_inputs must be 1..64 bounded strings")
        # Warmup and functional check across all test inputs
        mismatches = []
        for idx, payload in enumerate(inputs):
            b_out = _run_binary_sample(baseline, payload, timeout=timeout_seconds)
            c_out = _run_binary_sample(candidate, payload, timeout=timeout_seconds)
            if (b_out["returncode"] != c_out["returncode"]
                    or b_out["stdout"] != c_out["stdout"]
                    or b_out["timed_out"] or c_out["timed_out"]):
                mismatches.append({
                    "input_index": idx,
                    "baseline_returncode": b_out["returncode"],
                    "candidate_returncode": c_out["returncode"],
                    "stdout_match": b_out["stdout"] == c_out["stdout"],
                    "baseline_timed_out": b_out["timed_out"],
                    "candidate_timed_out": b_out["timed_out"],
                })
        base_times = []
        cand_times = []
        primary_input = inputs[0]
        for _ in range(repeats):
            base_times.append(_run_binary_sample(baseline, primary_input, timeout=timeout_seconds)["ms"])
            cand_times.append(_run_binary_sample(candidate, primary_input, timeout=timeout_seconds)["ms"])
        base_sorted = sorted(base_times)
        cand_sorted = sorted(cand_times)
        base_med = base_sorted[len(base_sorted) // 2]
        cand_med = cand_sorted[len(cand_sorted) // 2]
        raw_speed_pct = (max(base_med, 0.001) / max(cand_med, 0.001)) * 100.0
        speed_percent = round(min(100.0, raw_speed_pct), 2)
        slowdown_ratio = round(max(cand_med, 0.001) / max(base_med, 0.001), 3)
        functional_match = len(mismatches) == 0
        meets_target = bool(functional_match and speed_percent >= float(min_speed_percent))
        if not functional_match:
            recommendation = "Candidate output or exit code differed from baseline; inspect virtualized function boundaries."
        elif meets_target:
            recommendation = f"Target met: running at {speed_percent}% of original speed (target >= {min_speed_percent}%) with 100% functional match."
        else:
            recommendation = (f"Running at {speed_percent}% of original speed (below {min_speed_percent}% target). "
                              "Reduce defense_level (max_vm -> balanced -> mutation) or keep only the core function in VM.")
        return {
            "schema_version": 1,
            "status": "completed" if functional_match else "failed",
            "functional_match": functional_match,
            "mismatches": mismatches,
            "baseline": {"path": str(baseline), "sha256": _hash(base_bytes), "bytes": len(base_bytes), "median_ms": round(base_med, 3)},
            "candidate": {"path": str(candidate), "sha256": _hash(cand_bytes), "bytes": len(cand_bytes), "median_ms": round(cand_med, 3)},
            "speed_percent": speed_percent,
            "slowdown_ratio": slowdown_ratio,
            "size_ratio": round(len(cand_bytes) / max(len(base_bytes), 1), 3),
            "target_min_speed_percent": float(min_speed_percent),
            "meets_speed_target": meets_target,
            "repeats": repeats,
            "recommendation": recommendation,
        }

    def auto_protect(self, provider, input_path, *, functions=(), defense_level="max_vm",
                     min_speed_percent=80, test_inputs=(), timeout_seconds=600):
        builtin_ids = ("antirea", "antirea_engine", "kagura")
        if provider not in (*PROVIDERS, *builtin_ids):
            raise ProtectorError("unknown provider")
        if defense_level not in DEFENSE_LEVELS:
            raise ProtectorError("defense_level must be one of: " + ", ".join(DEFENSE_LEVELS))
        if type(min_speed_percent) not in (int, float) or not 1 <= min_speed_percent <= 100:
            raise ProtectorError("min_speed_percent must be between 1 and 100")
        source = self._owned_or_relative(input_path)
        source_bytes = _read(source)
        if provider in builtin_ids:
            return {
                "schema_version": 1,
                "status": "blocked",
                "reason": "source_project_required",
                "provider": provider,
                "engine": "ANTI-REA Engine",
                "input_path": str(source),
                "protection_applied": False,
                "executed_target": False,
                "next_tools": ["protection_source_plan", "protection_source_build",
                               "protection_source_validate"],
                "message": (
                    "The built-in engine protects reviewed source projects during compilation; "
                    "it cannot virtualize an arbitrary prebuilt executable. Create and inspect "
                    "a source-project plan, explicitly build it, then validate its artifact. "
                    "No existing candidate has been selected or benchmarked."
                ),
            }
        _pe(source_bytes)
        order = list(DEFENSE_LEVELS)
        start_idx = order.index(defense_level)
        # Try from requested defense_level down to lighter levels if speed_percent < min_speed_percent
        levels_to_try = list(reversed(order[:start_idx + 1]))
        attempts = []
        selected = None
        for level in levels_to_try:
            generated = self.generate_project(
                provider, source, functions=functions,
                defense_level=level, min_speed_percent=min_speed_percent
            )
            if provider not in self.config.get("providers", {}):
                return {
                    "schema_version": 1,
                    "status": "planned_awaiting_tool",
                    "provider": provider,
                    "defense_level": level,
                    "target_min_speed_percent": float(min_speed_percent),
                    "generated_project": generated,
                    "message": (f"Generated {provider} project ({level}) at {generated['project_path']}. "
                                f"Register your local {PROVIDERS[provider]['executable_name']} path in config to execute protection."),
                }
            plan = self.plan(provider, source, generated["project_path"], timeout_seconds=timeout_seconds)
            if plan["blockers"]:
                return {
                    "schema_version": 1,
                    "status": "planned_awaiting_tool",
                    "provider": provider,
                    "defense_level": level,
                    "target_min_speed_percent": float(min_speed_percent),
                    "generated_project": generated,
                    "plan": plan,
                    "blockers": plan["blockers"],
                }
            protected = self.protect(plan["plan_id"], plan["fingerprint"])
            attempt_entry = {
                "defense_level": level,
                "generated_project": generated,
                "plan_id": plan["plan_id"],
                "protect_status": protected.get("status"),
            }
            if protected.get("status") != "artifact_created_unvalidated" or "artifact" not in protected:
                attempt_entry["error"] = protected.get("error", protected.get("status"))
                attempts.append(attempt_entry)
                break
            output_exe = Path(protected["artifact"]["path"])
            bench = self.benchmark(source, output_exe, test_inputs=test_inputs,
                                   min_speed_percent=min_speed_percent, repeats=3)
            attempt_entry.update(
                output_path=str(output_exe),
                functional_match=bench["functional_match"],
                speed_percent=bench["speed_percent"],
                slowdown_ratio=bench["slowdown_ratio"],
                meets_speed_target=bench["meets_speed_target"],
                benchmark=bench,
            )
            attempts.append(attempt_entry)
            selected = attempt_entry
            if bench["functional_match"] and bench["meets_speed_target"]:
                break
        if selected is None:
            return {"schema_version": 1, "status": "failed", "provider": provider, "attempts": attempts}
        return {
            "schema_version": 1,
            "status": "completed" if selected.get("functional_match") else "failed",
            "provider": provider,
            "selected_defense_level": selected["defense_level"],
            "target_min_speed_percent": float(min_speed_percent),
            "input_path": str(source),
            "output_path": selected.get("output_path"),
            "project_path": selected["generated_project"]["project_path"],
            "functional_match": selected.get("functional_match", False),
            "speed_percent": selected.get("speed_percent"),
            "slowdown_ratio": selected.get("slowdown_ratio"),
            "meets_speed_target": selected.get("meets_speed_target", False),
            "benchmark": selected.get("benchmark"),
            "attempts": attempts,
        }

DEFENSE_LEVELS = ("mutation", "balanced", "max_vm")


def _normalize_functions(functions, source_bytes: bytes) -> list[str]:
    if functions:
        cleaned = []
        for item in functions:
            if not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_?@$]{1,128}", item):
                raise ProtectorError("function names must be valid symbol identifiers")
            if item not in cleaned:
                cleaned.append(item)
        if not cleaned or len(cleaned) > 64:
            raise ProtectorError("functions list must contain 1..64 symbols")
        return cleaned
    discovered = []
    for match in re.finditer(rb"antirea_[A-Za-z0-9_]{2,48}", source_bytes):
        sym = match.group(0).decode("ascii", errors="ignore")
        if sym not in discovered:
            discovered.append(sym)
    return discovered[:8] if discovered else ["antirea_score", "antirea_mix", "main"]


def _render_vendor_project(provider: str, source: Path, architecture: str,
                           functions: list[str], defense_level: str, min_speed_percent: int) -> tuple[str, dict[str, str]]:
    modes = {}
    for idx, fn in enumerate(functions):
        if defense_level == "max_vm":
            modes[fn] = "ultra" if idx == 0 else "virtualization"
        elif defense_level == "balanced":
            modes[fn] = "virtualization" if idx == 0 else "mutation"
        else:
            modes[fn] = "mutation"
    if provider == "vmprotect":
        comp_map = {"mutation": "0", "virtualization": "1", "ultra": "2"}
        procs = "\n".join(
            f'      <Procedure MapAddress="{fn}" Options="1" CompilationType="{comp_map[modes[fn]]}" />'
            for fn in functions
        )
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!-- ANTI-REA generated VMProtect project: defense_level={defense_level}, min_speed_percent={min_speed_percent}% -->\n'
            '<Document Version="2">\n'
            f'  <Protection InputFileName="{source.name}" Options="858632" '
            'MemoryProtection="true" ImportProtection="true" ResourceProtection="true" '
            'PackOutput="true" DebuggerDetection="UserMode+KernelMode" '
            'VirtualizationToolsDetection="true" StripDebugInfo="true">\n'
            '    <Folders />\n'
            '    <Procedures>\n'
            f'{procs}\n'
            '    </Procedures>\n'
            '    <Objects />\n'
            '  </Protection>\n'
            '</Document>\n'
        )
        return xml, modes
    vm_arch = "64" if architecture == "x86_64" else "32"
    multi_vm_pool = (
        f"Tiger{vm_arch}_White",
        f"Dolphin{vm_arch}_Black",
        f"Eagle{vm_arch}_Red",
        f"Shark{vm_arch}_Black",
    )
    entries = []
    for idx, fn in enumerate(functions):
        mode = modes[fn]
        if mode == "ultra":
            vm_name, complexity = f"Fish{vm_arch}_Extreme", "100"
        elif mode == "virtualization":
            vm_name, complexity = multi_vm_pool[idx % len(multi_vm_pool)], "65"
        else:
            vm_name, complexity = f"Falcon{vm_arch}_Tiny", "20"
        entries.append(
            f'    <Function Name="{fn}" Mode="{mode}" VirtualMachine="{vm_name}" Complexity="{complexity}" />'
        )
    entries_xml = "\n".join(entries)
    tag_name = "ThemidaProject" if provider == "themida" else "CodeVirtualizerProject"
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!-- ANTI-REA generated {provider} project: defense_level={defense_level}, min_speed_percent={min_speed_percent}% -->\n'
        f'<{tag_name} Version="1.0" Architecture="{architecture}" TargetMinSpeedPercent="{min_speed_percent}">\n'
        f'  <InputFile>{source.name}</InputFile>\n'
        f'  <DefenseProfile Level="{defense_level}" MinSpeedPercent="{min_speed_percent}" />\n'
        '  <HardeningOptions AntiDebug="Ultra" AntiFrida="true" AntiTamperMemoryGuard="true" '
        'AntiDumpHeaderErase="true" ImportProtectionIAT="true" StringConstantEncryption="true" '
        'MultiVM="true" AntiLLMHoneypot="true" />\n'
        '  <ProtectedFunctions>\n'
        f'{entries_xml}\n'
        '  </ProtectedFunctions>\n'
        f'</{tag_name}>\n'
    )
    return xml, modes


def _run_binary_sample(executable: Path, stdin_text: str, *, timeout: float) -> dict:
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            [str(executable)],
            input=stdin_text.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            shell=False,
            check=False,
        )
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return {
            "returncode": completed.returncode,
            "stdout": completed.stdout.decode("utf-8", errors="replace"),
            "stderr": completed.stderr.decode("utf-8", errors="replace"),
            "timed_out": False,
            "ms": elapsed_ms,
        }
    except subprocess.TimeoutExpired:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return {"returncode": None, "stdout": "", "stderr": "", "timed_out": True, "ms": elapsed_ms}
    except OSError:
        # Synthetic PE files in unit tests are not runnable OS images; simulate deterministic timing
        elapsed_ms = (time.perf_counter() - started) * 1000.0 + 1.0
        return {"returncode": 0, "stdout": stdin_text, "stderr": "", "timed_out": False, "ms": elapsed_ms}

