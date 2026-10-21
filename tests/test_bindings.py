"""Bindings checks run only our public arithmetic fixture, never external input.

Real toolchain tests are opt-in: ANTIREA_BINDINGS_REAL=1. Missing tools are skipped
and recorded as unavailable, never validated. No installers/network dependencies.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from antirea.bindings import LANGUAGES, generate_bindings, validate_contract

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "samples/multilang/bindings"
CONTRACT = json.loads((FIXTURE / "contract.json").read_text(encoding="utf-8"))


class ContractTests(unittest.TestCase):
    def test_normalized_detached_and_default_abi(self):
        supplied = copy.deepcopy(CONTRACT)
        supplied.pop("calling_convention")
        normalized = validate_contract(supplied)
        self.assertEqual(normalized, CONTRACT)
        normalized["functions"][0]["name"] = "changed"
        self.assertEqual(supplied["functions"][0]["name"], "mix")

    def test_reject_schema_unknown_fields_and_abi(self):
        for key, value in (("schema_version", True), ("schema_version", 2), ("calling_convention", "stdcall"), ("shell", "bad")):
            contract = {**CONTRACT, key: value}
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                validate_contract(contract)

    def test_reject_library_paths_and_injection(self):
        for value in ("../evil", "x.dll", "C:\\core", 'x";code', "CON", "1lib", "", "é"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_contract({**CONTRACT, "library_name": value})

    def test_reject_invalid_abi_types_duplicates_and_names(self):
        variants = []
        item = copy.deepcopy(CONTRACT); item["functions"][0]["return_type"] = "pointer"; variants.append(item)
        item = copy.deepcopy(CONTRACT); item["functions"][0]["parameters"][0]["type"] = "void"; variants.append(item)
        item = copy.deepcopy(CONTRACT); item["functions"].append(item["functions"][0]); variants.append(item)
        item = copy.deepcopy(CONTRACT); item["functions"][0]["parameters"] *= 2; variants.append(item)
        item = copy.deepcopy(CONTRACT); item["functions"][0]["name"] = "ar_load_library"; variants.append(item)
        item = copy.deepcopy(CONTRACT); item["functions"][0]["name"] = "load_library"; variants.append(item)
        item = copy.deepcopy(CONTRACT); item["functions"][0]["name"] = "jni_path_utf8"; variants.append(item)
        for contract in variants:
            with self.assertRaises(ValueError):
                validate_contract(contract)

    def test_bounded_contract(self):
        for functions in ([], [CONTRACT["functions"][0]] * 129, "not list"):
            with self.assertRaises(ValueError):
                validate_contract({**CONTRACT, "functions": functions})


class GeneratedTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="antirea-bindings-")
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name) / "generated"
        self.result = generate_bindings(CONTRACT, self.output)

    def test_all_languages_are_separate_unvalidated(self):
        self.assertEqual([entry["id"] for entry in self.result["languages"]], list(LANGUAGES))
        self.assertEqual(len(LANGUAGES), 11)
        self.assertTrue(all(entry["status"] == "generated_not_validated" for entry in self.result["languages"]))
        self.assertFalse(self.result["executed"])
        self.assertFalse(self.result["original_language_source_protection"])

    def test_every_recorded_digest_matches(self):
        for name, digest in self.result["files"].items():
            self.assertEqual(hashlib.sha256((self.output / name).read_bytes()).hexdigest(), digest)

    def test_output_is_never_overwritten_or_public(self):
        with self.assertRaises(ValueError):
            generate_bindings(CONTRACT, self.output)
        with self.assertRaises(ValueError):
            generate_bindings(CONTRACT, self.output.parent / "attackerfolder")

    def test_declares_native_core_scope_and_precision(self):
        self.assertIn("do NOT", (self.output / "README.md").read_text())
        self.assertIn("bigint", (self.output / "typescript/index.d.ts").read_text())
        self.assertIn("napi_get_value_bigint_uint64", (self.output / "javascript/addon.c").read_text())
        self.assertIn("Long.toUnsignedString", (self.output / "java/NativeCore.java").read_text())
        self.assertNotIn("System.loadLibrary", (self.output / "java/NativeCore.java").read_text())

    def test_python_validator_rejects_truncation_bool_and_wrong_type(self):
        namespace = {}
        exec(compile((self.output / "python/native_core.py").read_text(), "generated", "exec"), namespace)
        validate = namespace["_integer"]
        for kind, values in (("u32", (-1, 2**32, True, 1.0)), ("i32", (-2**31 - 1, 2**31)),
                             ("u64", (-1, 2**64)), ("i64", (-2**63 - 1, 2**63))):
            for value in values:
                with self.assertRaises(ValueError):
                    validate(value, kind)
        self.assertEqual(validate(2**64 - 1, "u64"), 2**64 - 1)

    def test_csharp_guards_before_pinvoke_not_ambient_lookup(self):
        source = (self.output / "csharp/NativeCore.cs").read_text()
        self.assertIn("private static extern", source)
        self.assertIn("if (handle == IntPtr.Zero) throw", source)
        self.assertIn('if (name != "antirea_contract") return IntPtr.Zero;', source)
        self.assertIn("if (!resolverRegistered)", source)

    def test_common_bridge_does_not_publish_partial_initialization(self):
        source = (self.output / "common/antirea_bridge.c").read_text()
        self.assertIn('ar_symbol(candidate, "mix")', source)
        self.assertIn("goto ar_lookup_failed", source)
        self.assertLess(source.index("candidate_touch ="), source.index("ar_handle = candidate;"))
        self.assertLess(source.index("candidate_touch ="), source.index("ar_p_mix = candidate_mix;"))
        self.assertIn("FreeLibrary(candidate)", source)
        self.assertIn("dlclose(candidate)", source)

    def test_jni_encodes_strict_standard_utf8(self):
        source = (self.output / "java/adapter.c").read_text()
        self.assertIn("GetStringChars(env, path, NULL)", source)
        self.assertNotIn("->GetStringUTFChars", source)
        self.assertIn("if (!code) goto ar_invalid_path", source)
        self.assertIn("code >= 0xd800 && code <= 0xdbff", source)
        self.assertIn("code >= 0xdc00 && code <= 0xdfff", source)
        self.assertIn("ReleaseStringChars(env, path, chars)", source)

    def test_c_valid_python_keyword_exports_generate_valid_python(self):
        contract = {"schema_version": 1, "library_name": "keywords", "functions": [
            {"name": name, "return_type": "u64", "parameters": [{"name": "value", "type": "u64"}]}
            for name in ("class", "def", "async", "None", "True", "lambda")]}
        directory = self.output.parent / "keywords"
        generate_bindings(contract, directory)
        source = (directory / "python/native_core.py").read_text()
        compile(source, "generated-keyword-exports", "exec")
        self.assertIn("getattr(self._library, 'class')", source)

    def test_go_windows_stdlib_loader_has_isolated_handles_and_fail_closed_gates(self):
        source = (self.output / "go/native_core_windows_amd64.go").read_text()
        self.assertTrue(source.startswith("//go:build windows && amd64"))
        self.assertNotIn('import "C"', source)
        self.assertIn("handle syscall.Handle", source)
        self.assertIn("core.proc_mix", source)
        self.assertIn("0x1100", source)
        self.assertIn("absolute local drive library path required", source)
        self.assertIn("syscall.GetProcAddress(core.handle", source)
        self.assertIn("syscall.FreeLibrary(core.handle)", source)
        self.assertIn("core.mu.RLock()", source)
        self.assertIn("core.mu.Lock()", source)
        self.assertIn('panic("native core is closed")', source)
        self.assertIn("return int64(value)", source)
        self.assertIn("uintptr(uint32(p_x))", source)
        self.assertTrue((self.output / "go/native_core.go").read_text().startswith("//go:build !windows"))
        self.assertTrue((self.output / "go/bridge.c").read_text().startswith("//go:build !windows"))


@unittest.skipUnless(os.environ.get("ANTIREA_BINDINGS_REAL") == "1", "opt-in real owned-fixture toolchain checks")
class RealBindingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="antirea-ffi-real-")
        cls.base = Path(cls.temp.name)
        cls.output = cls.base / "bindings"
        generate_bindings(CONTRACT, cls.output)
        cls.env = dict(os.environ)
        cls.evidence = {"schema_version": 1, "scope": "public_unprotected_ffi_fixture_only",
                        "native_protection_validated": False,
                        "languages": {name: {"status": "not_validated"} for name in LANGUAGES}}
        if os.name == "nt":
            toolchain_file = ROOT / ".tools/kagura-toolchain.json"
            if not toolchain_file.exists():
                raise unittest.SkipTest("Windows developer toolchain manifest unavailable")
            toolchain = json.loads(toolchain_file.read_text())
            script = toolchain["developer_shell"].replace("'", "''")
            command = f"& '{script}' -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null; Get-ChildItem Env: | ForEach-Object {{ @{{name=$_.Name;value=$_.Value}} }} | ConvertTo-Json -Compress"
            result = subprocess.run(["powershell", "-NoProfile", "-Command", command], capture_output=True, text=True, timeout=60)
            if result.returncode:
                raise unittest.SkipTest("Windows developer environment unavailable")
            for value in json.loads(result.stdout):
                for existing in list(cls.env):
                    if existing.lower() == value["name"].lower():
                        del cls.env[existing]
                cls.env[value["name"]] = value["value"]
            cls.cc = toolchain["clang"]
            cls.core = cls.base / "ffi_fixture.dll"
            cls.bridge = cls.base / "antirea_bridge.dll"
        else:
            cls.cc = shutil.which("clang") or shutil.which("cc")
            if not cls.cc:
                raise unittest.SkipTest("C compiler unavailable")
            cls.core = cls.base / "libffi_fixture.so"
            cls.bridge = cls.base / "libantirea_bridge.so"
        cls.run_command([cls.cc, "-shared", str(FIXTURE / "fixture.c"), "-o", str(cls.core)])
        cls.run_command([cls.cc, "-shared", str(cls.output / "common/antirea_bridge.c"), "-o", str(cls.bridge)])

    @classmethod
    def tearDownClass(cls):
        evidence_path = os.environ.get("ANTIREA_BINDINGS_EVIDENCE")
        if evidence_path:
            path = Path(evidence_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(cls.evidence, indent=2) + "\n", encoding="utf-8")
        cls.temp.cleanup()

    @classmethod
    def run_command(cls, argv, cwd=None, expected_exit=0):
        command={"argv":[str(item) for item in argv],"cwd":str(cwd or cls.base)}
        cls.evidence.setdefault("commands",[]).append(command)
        try:
            result = subprocess.run(command["argv"], cwd=cwd or cls.base, env=cls.env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                    encoding="utf-8", errors="replace", timeout=90)
        except subprocess.TimeoutExpired:
            command.update(status="timed_out",timeout_seconds=90)
            raise
        command.update(returncode=result.returncode,stdout=result.stdout[:16384],stderr=result.stderr[:16384])
        if expected_exit is not None and result.returncode != expected_exit:
            raise AssertionError(f"Command failed ({result.returncode}): {argv}\n{result.stdout}\n{result.stderr}")
        return result.stdout.strip()

    def available(self, language, program):
        path = shutil.which(program)
        if not path:
            self.evidence["languages"][language] = {"status": "unavailable", "reason": f"{program} not installed"}
            self.skipTest(f"{program} unavailable")
        return path

    def passed(self, language, output):
        self.assertEqual(output, "OK")
        self.evidence["languages"][language] = {"status": "compile_and_execution_validated", "fixture": "public ABI boundary fixture"}

    def test_c_and_cpp(self):
        for language, extension in (("c", ".c"), ("cpp", ".cpp")):
            source = self.base / ("main" + extension)
            include = self.output / ("c/native_core.h" if language == "c" else "cpp/native_core.hpp")
            source.write_text('#include <stdio.h>\n#include "' + str(include).replace("\\", "/") + '"\nint main(int n,char **v) { if(n!=2 || ar_load_library(v[1])) return 2; if(ar_mix(UINT32_MAX,UINT32_MAX)!=UINT64_MAX || ar_echoI64(INT64_MIN)!=INT64_MIN || ar_echoU32(UINT32_MAX)!=UINT32_MAX || ar_echoI32(INT32_MIN)!=INT32_MIN) return 3; ar_touch(); puts("OK"); return 0; }', encoding="utf-8")
            exe = self.base / (language + ".exe")
            self.run_command([self.cc, str(source), str(self.output / "common/antirea_bridge.c"), "-o", str(exe)])
            self.passed(language, self.run_command([exe, self.core]))

    def test_common_bridge_failed_lookup_is_transactional_and_retryable(self):
        missing_source = self.base / "retry_missing.c"
        missing = self.base / ("retry_missing.dll" if os.name == "nt" else "retry_missing.so")
        missing_source.write_text('#include <stdint.h>\n#ifdef _WIN32\n#define API __declspec(dllexport)\n#else\n#define API __attribute__((visibility("default")))\n#endif\nAPI uint64_t mix(uint32_t x,uint32_t y){return 999;}\n')
        self.run_command([self.cc, "-shared", missing_source, "-o", missing])
        source = self.base / "retry_bridge.c"
        bridge = str(self.output / "common/antirea_bridge.c").replace("\\", "/")
        pointer_checks = " || ".join("ar_p_" + entry["name"] for entry in CONTRACT["functions"])
        source.write_text('''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
''' + '#include "' + bridge + '"\n' + '''int main(int count,char **args) {
    if(count!=4) return 20;
#ifdef _WIN32
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    if(GetModuleHandleA(args[2])) return 21;
#endif
    if(ar_load_library(args[2])==0) return 22;
    if(strstr(ar_last_error(),"missing symbol: echoU32")==NULL) return 23;
    if(ar_handle || ar_ready || ''' + pointer_checks + ''') return 24;
#ifdef _WIN32
    if(GetModuleHandleA(args[2])) return 25;
#endif
    puts("FAILED_STATE_CLEAN"); fflush(stdout);
    if(strcmp(args[1],"call")==0) {
        ar_mix(1,2);
        puts("STALE_CALL_RETURNED"); return 26;
    }
    if(ar_load_library(args[3])!=0) return 27;
    if(ar_mix(UINT32_MAX,UINT32_MAX)!=UINT64_MAX) return 28;
    if(ar_echoI32(INT32_MIN)!=INT32_MIN) return 29;
    if(ar_load_library(args[3])==0) return 30;
    if(ar_mix(UINT32_MAX,UINT32_MAX)!=UINT64_MAX) return 31;
    puts("RETRY_OK"); return 0;
}
''', encoding="utf-8")
        executable = self.base / "retry_bridge.exe"
        command = [self.cc, source, "-o", executable]
        if os.name != "nt":
            command.append("-ldl")
        self.run_command(command)
        output = self.run_command([executable, "retry", missing, self.core])
        self.assertEqual(output, "FAILED_STATE_CLEAN\nRETRY_OK")
        failed = self.run_command([executable, "call", missing, self.core], expected_exit=None)
        self.assertNotEqual(self.evidence["commands"][-1]["returncode"], 0)
        self.assertEqual(failed, "FAILED_STATE_CLEAN")
        self.evidence["common_bridge_transaction"] = {"status": "passed", "partial_pointers_unpublished": True,
            "failed_library_unloaded": os.name == "nt", "retry_passed": True,
            "call_after_failed_load": "process_aborts_before_any_stale_function_call",
            "successful_reinitialization": "rejected_without_disturbing_existing_functions"}

    def test_python(self):
        source = self.base / "python_test.py"
        source.write_text('import sys\nsys.path.insert(0, ' + repr(str(self.output / "python")) + ')\nfrom native_core import NativeCore\nc=NativeCore(' + repr(str(self.core)) + ')\nassert c.call_mix(2**32-1,2**32-1)==2**64-1\nassert c.call_echoI64(-2**63)==-2**63\nassert c.call_echoU64(2**64-1)==2**64-1\nassert c.call_class(2**64-1)==2**64-1\nc.call_touch()\nprint("OK")\n', encoding="utf-8")
        self.passed("python", self.run_command([self.available("python", "python"), source]))

    def test_rust(self):
        compiler = self.available("rust", "rustc")
        obj = self.base / "static_bridge.o"
        archive = self.base / ("antirea_bridge.lib" if os.name == "nt" else "libantirea_bridge.a")
        self.run_command([self.cc, "-c", str(self.output / "common/antirea_bridge.c"), "-o", str(obj)])
        ar = str(Path(self.cc).with_name("llvm-ar.exe")) if os.name == "nt" else (shutil.which("llvm-ar") or shutil.which("ar"))
        self.run_command([ar, "rcs", str(archive), str(obj)])
        source = self.base / "rust_test.rs"
        source.write_text('#[path=' + json.dumps(str(self.output / "rust/native_core.rs").replace("\\", "/")) + '] mod core;\nfn main(){ let path=std::env::args().nth(1).unwrap(); let c=core::NativeCore::load(std::path::Path::new(&path)).unwrap(); assert_eq!(c.call_mix(u32::MAX,u32::MAX),u64::MAX); assert_eq!(c.call_echoI64(i64::MIN),i64::MIN); c.call_touch(); println!("OK"); }', encoding="utf-8")
        exe = self.base / "rust_test.exe"
        args = [compiler, "--edition=2024", str(source), "-L", str(self.base), "-o", str(exe)]
        if os.name != "nt":
            args += ["-l", "dl"]
        self.run_command(args)
        self.passed("rust", self.run_command([exe, self.core]))

    def test_csharp(self):
        dotnet = self.available("csharp", "dotnet")
        target = self.base / "csharp"
        target.mkdir()
        shutil.copyfile(self.output / "csharp/NativeCore.cs", target / "NativeCore.cs")
        (target / "fixture.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>')
        (target / "NuGet.Config").write_text('<configuration><packageSources><clear /></packageSources></configuration>')
        (target / "Program.cs").write_text('using System; class Program { static void Main(string[] a) { NativeCore.Initialize(a[0]); if(NativeCore.call_mix(uint.MaxValue,uint.MaxValue)!=ulong.MaxValue || NativeCore.call_echoI64(long.MinValue)!=long.MinValue) throw new Exception(); NativeCore.call_touch(); Console.WriteLine("OK"); } }')
        self.run_command([dotnet, "build", str(target / "fixture.csproj"), "--nologo", "--configfile", str(target / "NuGet.Config")])
        self.passed("csharp", self.run_command([dotnet, target / "bin/Debug/net10.0/fixture.dll", self.core]))

    @unittest.skipUnless(os.name == "nt", "kernel32 resolver regression is Windows-specific")
    def test_csharp_failed_load_retry_and_unrelated_import(self):
        dotnet = self.available("csharp", "dotnet")
        target = self.base / "csharp_retry"
        target.mkdir()
        shutil.copyfile(self.output / "csharp/NativeCore.cs", target / "NativeCore.cs")
        (target / "fixture.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>')
        (target / "NuGet.Config").write_text('<configuration><packageSources><clear /></packageSources></configuration>')
        (target / "Program.cs").write_text('''using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
class Program {
    [DllImport("kernel32.dll", ExactSpelling=true)] static extern uint GetCurrentProcessId();
    [MethodImpl(MethodImplOptions.NoInlining)] static uint OsCall() => GetCurrentProcessId();
    static void Main(string[] a) {
        bool guarded=false;
        try { NativeCore.call_mix(0,0); } catch(InvalidOperationException) { guarded=true; }
        if(!guarded) throw new Exception("pre-initialization call accepted");
        if(a[0]=="retry") {
            bool rejected=false;
            try { NativeCore.Initialize(a[2]); } catch(DllNotFoundException) { rejected=true; }
            if(!rejected) throw new Exception("missing DLL accepted");
        }
        NativeCore.Initialize(a[1]);
        if(NativeCore.call_mix(uint.MaxValue,uint.MaxValue)!=ulong.MaxValue) throw new Exception("ABI");
        if(OsCall()==0) throw new Exception("OS import");
        bool repeated=false;
        try { NativeCore.Initialize(a[1]); } catch(InvalidOperationException) { repeated=true; }
        if(!repeated || NativeCore.call_mix(uint.MaxValue,uint.MaxValue)!=ulong.MaxValue) throw new Exception("repeat");
        Console.WriteLine("OK");
    }
}''', encoding="utf-8")
        self.run_command([dotnet, "build", target / "fixture.csproj", "--nologo", "--configfile", target / "NuGet.Config"])
        executable = target / "bin/Debug/net10.0/fixture.dll"
        for mode in ("normal", "retry"):
            self.assertEqual(self.run_command([dotnet, executable, mode, self.core, target / "missing.dll"]), "OK")
        self.evidence["csharp_resolver_regressions"] = {"status": "passed", "unrelated_import_after_initialize": True,
            "failed_load_retry": True, "pre_initialization_call_rejected": True,
            "successful_reinitialization_rejected": True}

    def test_java(self):
        javac = self.available("java", "javac")
        java = self.available("java", "java")
        include = Path(javac).resolve().parents[1] / "include"
        if not (include / "jni.h").exists():
            self.evidence["languages"]["java"] = {"status": "unavailable", "reason": "JNI development headers absent"}
            self.skipTest("JNI headers absent")
        adapter = self.base / ("antirea_jni.dll" if os.name == "nt" else "libantirea_jni.so")
        self.run_command([self.cc, "-shared", "-I" + str(include), "-I" + str(include / ("win32" if os.name == "nt" else "linux")),
                          str(self.output / "java/adapter.c"), str(self.output / "common/antirea_bridge.c"), "-o", str(adapter)])
        source = self.base / "JavaTest.java"
        source.write_text('public class JavaTest { public static void main(String[] a) { NativeCore.initialize(a[0],a[1]); if(NativeCore.call_mix(0xffffffffL,0xffffffffL)!=-1L || NativeCore.call_echoU64(-1L)!=-1L || NativeCore.call_echoI64(Long.MIN_VALUE)!=Long.MIN_VALUE) throw new RuntimeException(); NativeCore.call_touch(); System.out.println("OK"); } }')
        self.run_command([javac, "-d", str(self.base), str(self.output / "java/NativeCore.java"), str(source)])
        self.passed("java", self.run_command([java, "-cp", self.base, "JavaTest", adapter, self.core]))

    def test_jni_unicode_paths_and_invalid_utf16(self):
        javac = self.available("java", "javac")
        java = self.available("java", "java")
        include = Path(javac).resolve().parents[1] / "include"
        self.assertTrue((include / "jni.h").is_file(), "installed JDK must provide JNI headers")
        target = self.base / "jni_unicode"
        target.mkdir()
        directory = target / "owned-한-é-😀"
        directory.mkdir()
        library = directory / self.core.name
        shutil.copyfile(self.core, library)
        before = hashlib.sha256(library.read_bytes()).hexdigest()
        self.assertEqual(before, hashlib.sha256(self.core.read_bytes()).hexdigest())
        adapter = target / ("strict_jni.dll" if os.name == "nt" else "strict_jni.so")
        self.run_command([self.cc, "-shared", "-I" + str(include),
                          "-I" + str(include / ("win32" if os.name == "nt" else "linux")),
                          self.output / "java/adapter.c", self.output / "common/antirea_bridge.c", "-o", adapter])
        # Construct supplementary characters inside the JVM. Some Windows Java
        # launchers pass command-line arguments through the legacy code page.
        source = target / "StrictPathTest.java"
        source.write_text('''import java.nio.file.Path;
import java.nio.file.Files;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
public final class StrictPathTest {
    public static String prepare(String adapter,String parent,String filename) throws Exception {
        String leaf="owned-"+(char)0xd55c+"-"+(char)0xe9+"-"+new String(Character.toChars(0x1f600));
        String path=Path.of(parent,leaf,filename).toString();
        if(!Files.isRegularFile(Path.of(path))) throw new Exception("missing exact Unicode fixture");
        if(!path.codePoints().anyMatch(p->p>0xffff)) throw new Exception("non-BMP path was lost");
        System.load(adapter);
        Method method=NativeCore.class.getDeclaredMethod("nativeLoad",String.class);
        method.setAccessible(true);
        String[] suffixes={String.valueOf((char)0)+"ignored",String.valueOf((char)0xd800),
            String.valueOf((char)0xdc00),new String(new char[]{0xd800,'A'}),
            new String(new char[]{0xd800,0xd800}),new String(new char[]{0xdc00,0xd800})};
        for(String suffix:suffixes) {
            try {method.invoke(null,path+suffix);throw new Exception("invalid UTF-16/NUL accepted");}
            catch(InvocationTargetException error) {
                if(!(error.getCause() instanceof IllegalArgumentException)) throw error;
            }
        }
        return path;
    }
    public static void main(String[] a) throws Exception {
        String path=prepare(a[0],a[1],a[2]);
        NativeCore.initialize(a[0],path);
        if(NativeCore.call_mix(0xffffffffL,0xffffffffL)!=-1L || NativeCore.call_echoI64(Long.MIN_VALUE)!=Long.MIN_VALUE)
            throw new Exception("ABI");
        System.out.println("OK");
    }
}''', encoding="utf-8")
        self.run_command([javac, "-proc:none", "-encoding", "UTF-8", "-d", target,
                          self.output / "java/NativeCore.java", source])
        self.assertEqual(self.run_command([java, "-cp", target, "StrictPathTest", adapter, target, self.core.name]), "OK")
        self.evidence["jni_utf16_regressions"] = {"status": "passed", "java": "passed", "kotlin": "not_run",
            "unicode_path": "BMP 2-byte + BMP 3-byte + supplementary 4-byte UTF-8",
            "invalid_inputs_rejected": 6, "rejection": "IllegalArgumentException before library loading",
            "repeated_rejection_then_valid_load": True, "library_sha256": before}
        from antirea.jvm_frontend import _compiler
        kotlin = _compiler("kotlin")
        if kotlin["blockers"]:
            self.evidence["jni_utf16_regressions"]["kotlin"] = {"status": "unavailable", "reason": kotlin["blockers"]}
            self.skipTest("portable Kotlin compiler unavailable for JNI regression")
        kotlin_source = target / "StrictKotlin.kt"
        kotlin_source.write_text('''fun main(a:Array<String>) {
    val path=StrictPathTest.prepare(a[0],a[1],a[2])
    KotlinCore.initialize(a[0],path)
    check(KotlinCore.call_mix(UInt.MAX_VALUE,UInt.MAX_VALUE)==ULong.MAX_VALUE)
    check(KotlinCore.call_echoI64(Long.MIN_VALUE)==Long.MIN_VALUE)
    println("OK")
}''', encoding="utf-8")
        classpath = os.pathsep.join([str(target), kotlin["kotlin_stdlib"], kotlin["kotlin_annotations"]])
        classes = target / "kotlin-classes"
        self.run_command([kotlin["java"], "-cp", kotlin["kotlin_compiler"], "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler",
                          "-jvm-target", "21", "-no-stdlib", "-no-reflect", "-classpath", classpath,
                          "-d", classes, self.output / "kotlin/NativeCore.kt", kotlin_source])
        self.assertEqual(self.run_command([java, "-cp", str(classes) + os.pathsep + classpath,
                                          "StrictKotlinKt", adapter, target, self.core.name]), "OK")
        self.assertEqual(hashlib.sha256(library.read_bytes()).hexdigest(), before)
        self.evidence["jni_utf16_regressions"].update(kotlin="passed", hashes_unchanged=True)

    def test_javascript(self):
        node = self.available("javascript", "node")
        version = self.run_command([node, "--version"]).removeprefix("v")
        cache = Path(os.environ.get("LOCALAPPDATA", "")) / "node-gyp/Cache" / version
        headers, import_lib = cache / "include/node", cache / "x64/node.lib"
        if not (headers / "node_api.h").exists() or (os.name == "nt" and not import_lib.exists()):
            self.evidence["languages"]["javascript"] = {"status": "unavailable", "reason": "installed Node-API headers/import library absent"}
            self.skipTest("Node-API development files absent; no download attempted")
        addon = self.output / "javascript/antirea.node"
        args = [self.cc, "-shared", "-I" + str(headers), str(self.output / "javascript/addon.c"),
                str(self.output / "common/antirea_bridge.c"), "-o", str(addon)]
        if os.name == "nt":
            args.append(str(import_lib))
        self.run_command(args)
        source = self.base / "node_test.js"
        source.write_text("const a=require(" + json.dumps(str(self.output / "javascript")) + ").load(" + json.dumps(str(self.core)) + ");\nif(a.call_mix(4294967295,4294967295)!==18446744073709551615n || a.call_echoI64(-9223372036854775808n)!==-9223372036854775808n) throw Error('wrong');\nfor(const bad of [-1n,18446744073709551616n,1]){let failed=false;try{a.call_echoU64(bad)}catch(e){failed=true}if(!failed)throw Error('range');}\na.call_touch();console.log('OK');", encoding="utf-8")
        self.passed("javascript", self.run_command([node, source]))

    def test_go(self):
        compiler, env = self.go_compiler_environment()
        target = self.base / "go_driver"
        target.mkdir()
        (target / "go.mod").write_text('module antirea/fixture\n\ngo 1.20\nrequire antirea/nativecore v0.0.0\nreplace antirea/nativecore => ../bindings/go\n')
        cleanup = 'defer c.Close();' if os.name == "nt" else ''
        (target / "main.go").write_text('package main\nimport("fmt";"os";core "antirea/nativecore")\nfunc main(){c,e:=core.Load(os.Args[1]);if e!=nil{panic(e)};' + cleanup
            + 'if c.Call_mix(4294967295,4294967295)!=18446744073709551615 || c.Call_echoI64(-9223372036854775808)!=-9223372036854775808 || c.Call_echoI32(-2147483648)!=-2147483648 || c.Call_echoU32(4294967295)!=4294967295 || c.Call_echoU64(18446744073709551615)!=18446744073709551615 || c.Call_class(18446744073709551615)!=18446744073709551615{panic("wrong")};c.Call_touch();fmt.Println("OK")}')
        previous = dict(self.env)
        self.env.clear(); self.env.update(env)
        try:
            self.passed("go", self.run_command([compiler, "run", "-buildvcs=false", ".", str(self.core)], cwd=target))
            self.evidence["languages"]["go"].update(backend="windows_amd64_stdlib_dll" if os.name == "nt" else "cgo",
                cgo_enabled=self.env["CGO_ENABLED"], exact_u64_max=True, exact_i64_min=True, exact_u32_max=True, exact_i32_min=True, void_call=True)
        finally:
            self.env.clear(); self.env.update(previous)

    def go_compiler_environment(self):
        if os.name == "nt":
            from antirea.go_frontend import _compiler, _environment
            if not hasattr(self, "_go_toolchain"):
                self._go_toolchain = _compiler()
            toolchain = self._go_toolchain
            env = _environment(toolchain, self.base)
            # This fixture imports only local generated bindings, with no module downloads.
            env["GO111MODULE"] = "on"
            self.evidence["go_compiler"] = {"path": toolchain["go"], "version": toolchain["version"],
                "sha256": toolchain["input_hashes"][toolchain["go"]], "system_path_modified": False}
            return toolchain["go"], env
        env = {key: value for key, value in self.env.items() if not key.upper().startswith("GO")}
        for name in ("cache", "path"):
            (self.base / "go-private" / name).mkdir(parents=True, exist_ok=True)
        env.update(CGO_ENABLED="1", CC=self.cc, GOENV="off", GOWORK="off", GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local", GOTELEMETRY="off",
            GOCACHE=str(self.base / "go-private/cache"), GOPATH=str(self.base / "go-private/path"))
        return self.available("go", "go"), env

    @unittest.skipUnless(os.name == "nt", "Windows/amd64 stdlib loader checks")
    def test_go_windows_handle_isolation_close_and_missing_exports(self):
        compiler, env = self.go_compiler_environment()
        other_c, other_dll = self.base / "ffi_other.c", self.base / "ffi_other.dll"
        original = (FIXTURE / "fixture.c").read_text()
        other_c.write_text(original.replace('return ((uint64_t)x << 32) | y;', 'return (((uint64_t)x << 32) | y) ^ UINT64_C(1);'))
        self.run_command([self.cc,"-shared",other_c,"-o",other_dll])
        missing_c, missing_dll = self.base / "ffi_missing.c", self.base / "ffi_missing.dll"
        missing_c.write_text('#include <stdint.h>\n__declspec(dllexport) uint64_t mix(uint32_t x,uint32_t y){return 0;}\n')
        self.run_command([self.cc,"-shared",missing_c,"-o",missing_dll])
        target = self.base / "go_isolation"; target.mkdir()
        (target/"go.mod").write_text('module antirea/isolation\n\ngo 1.20\nrequire antirea/nativecore v0.0.0\nreplace antirea/nativecore => ../bindings/go\n')
        (target/"main.go").write_text('''package main
import("fmt";"os";core "antirea/nativecore")
func main(){
    if _,e:=core.Load("relative.dll");e==nil{panic("relative accepted")}
    if _,e:=core.Load(`\\\\server\\share\\app.dll`);e==nil{panic("UNC accepted")}
    if _,e:=core.Load(`\\\\?\\C:\\app.dll`);e==nil{panic("device path accepted")}
    if _,e:=core.Load(os.Args[3]);e==nil{panic("missing export accepted")}
    a,e:=core.Load(os.Args[1]);if e!=nil{panic(e)}
    b,e:=core.Load(os.Args[2]);if e!=nil{panic(e)};defer b.Close()
    if a.Call_mix(1,2)!=4294967298 || b.Call_mix(1,2)!=4294967299 {panic("instance cross-talk")}
    if e:=a.Close();e!=nil{panic(e)};if e:=a.Close();e!=nil{panic(e)}
    caught:=false;func(){defer func(){if recover()!=nil{caught=true}}();a.Call_touch()}()
    if !caught{panic("closed call accepted")}
    if b.Call_mix(1,2)!=4294967299{panic("closing other instance corrupted handle")}
    b.Call_touch();fmt.Println("OK")
}''')
        previous = dict(self.env); self.env.clear(); self.env.update(env)
        try:
            self.assertEqual(self.run_command([compiler,"run","-buildvcs=false",".",self.core,other_dll,missing_dll],cwd=target),"OK")
        finally:
            self.env.clear();self.env.update(previous)
        self.evidence["go_windows_lifecycle"]={"status":"passed","separate_library_instances":2,
            "relative_unc_device_rejected":True,"missing_export_rejected":True,"closed_call_rejected":True,"double_close_idempotent":True}

    @unittest.skipUnless(os.name == "nt", "Windows/amd64 protected Go binding checks")
    def test_go_protected_integer_binding(self):
        """Explicit immutable Go source build, independent of the plain FFI fixture."""
        value=os.environ.get("ANTIREA_BINDINGS_GO_REPORT")
        if not value:
            self.skipTest("owned Go build report path not supplied")
        from antirea.go_frontend import TYPES as GO_TYPES
        from antirea.dotnet_frontend import reference_cases
        from antirea import native_build
        import ctypes
        path=native_build._no_links(Path(value))
        self.assertTrue(path.is_relative_to(ROOT/".runs"));self.assertNotIn("rea-analysis-reports",path.parts)
        raw=path.read_bytes();report=json.loads(raw)
        self.assertEqual(report["backend"],"go_typed_native");self.assertEqual(report["status"],"artifact_created_unvalidated")
        artifacts=report["artifacts"]
        for artifact in artifacts.values():
            library=native_build._no_links(Path(artifact["path"]));self.assertTrue(library.is_relative_to(path.parent))
            self.assertEqual(hashlib.sha256(library.read_bytes()).hexdigest(),artifact["sha256"])
        compiler,env=self.go_compiler_environment()
        output=self.base/"protected_go_bindings";generate_bindings(report["contract"],output)
        target=self.base/"go_protected";target.mkdir()
        (target/"go.mod").write_text('module antirea/goprotected\n\ngo 1.20\nrequire antirea/nativecore v0.0.0\nreplace antirea/nativecore => ../protected_go_bindings/go\n')
        source=['package main','import("fmt";"os";core "antirea/nativecore")','func main(){c,e:=core.Load(os.Args[1]);if e!=nil{panic(e)};defer c.Close()']
        baseline=ctypes.CDLL(artifacts["baseline"]["path"],winmode=0x1100)
        ct={"int32":ctypes.c_int32,"uint32":ctypes.c_uint32,"int64":ctypes.c_int64,"uint64":ctypes.c_uint64}
        expected,entries=[],[]
        for index,method in enumerate(m for m in report["methods"] if m["is_root"]):
            cases,counts=reference_cases([GO_TYPES[t][3] for t in method["parameters"]],32,9029+index)
            function=getattr(baseline,method["export"]);function.argtypes=[ct[t] for t in method["parameters"]];function.restype=ct[method["return_type"]]
            for row in cases:
                expected.append(str(function(*row)))
                source.append('fmt.Println(c.Call_'+method["export"]+'('+','.join(f'{kind}({v})' for kind,v in zip(method["parameters"],row))+'))')
            entries.append({"export":method["export"],"total":len(cases),**counts})
        source.append('}');(target/"main.go").write_text('\n'.join(source))
        previous=dict(self.env);self.env.clear();self.env.update(env)
        try:
            actual=self.run_command([compiler,"run","-buildvcs=false",".",artifacts["protected"]["path"]],cwd=target).splitlines()
        finally:
            self.env.clear();self.env.update(previous)
        self.assertEqual(actual,expected)
        self.assertEqual(path.read_bytes(),raw)
        for artifact in artifacts.values(): self.assertEqual(hashlib.sha256(Path(artifact["path"]).read_bytes()).hexdigest(),artifact["sha256"])
        self.evidence["go_protected_integration"]={"status":"passed","scope":"protected_go_source_native_binding_integration",
            "build_report":str(path),"build_report_sha256":hashlib.sha256(raw).hexdigest(),
            "baseline_sha256":artifacts["baseline"]["sha256"],"protected_sha256":artifacts["protected"]["sha256"],
            "methods":entries,"total":len(expected),"matched":len(actual),"hashes_unchanged":True,
            "original_go_reference":"separate source-validation evidence; this test only checks the Go caller/DLL ABI",
            "external_attack_evaluation":"not_performed"}

    def test_swift(self):
        compiler, flags, env = self.swift_compiler_environment()
        target = self.base / "swift_driver"
        target.mkdir()
        source, obj, exe = target / "main.swift", target / "bridge.o", target / "swift_test.exe"
        source.write_text('let core = try NativeCore(libraryPath: CommandLine.arguments[1])\nprecondition(core.call_mix(UInt32.max,UInt32.max) == UInt64.max)\nprecondition(core.call_echoI64(Int64.min) == Int64.min)\nprecondition(core.call_echoU64(UInt64.max) == UInt64.max)\nprecondition(core.call_echoI32(Int32.min) == Int32.min)\nprecondition(core.call_echoU32(UInt32.max) == UInt32.max)\nprecondition(core.call_class(UInt64.max) == UInt64.max)\ncore.call_touch()\nprint("OK")\n')
        self.run_command([self.cc, "-c", str(self.output / "common/antirea_bridge.c"), "-o", str(obj)])
        previous = dict(self.env); self.env.clear(); self.env.update(env)
        try:
            self.run_command([compiler, *flags, "-I", str(self.output / "swift"), str(self.output / "swift/NativeCore.swift"), str(source), str(obj), "-o", str(exe)])
            self.passed("swift", self.run_command([exe, self.core]))
        finally:
            self.env.clear(); self.env.update(previous)
        self.evidence["languages"]["swift"].update(exact_u64_max=True,exact_i64_min=True,exact_u32_max=True,exact_i32_min=True,void_call=True)

    def swift_compiler_environment(self):
        """Use portable compiler/SDK and only child-local runtime search paths."""
        denied={"SDKROOT","DEVELOPER_DIR","CL","_CL_","LINK","CPATH","C_INCLUDE_PATH",
                "CPLUS_INCLUDE_PATH","LIBRARY_PATH","LD_PRELOAD","DYLD_INSERT_LIBRARIES"}
        env={k:v for k,v in self.env.items() if k.upper() not in denied and not k.upper().startswith("SWIFT_")}
        cache=self.base/"swift-module-cache";cache.mkdir(exist_ok=True)
        flags=["-language-mode","6","-O","-module-name","AntireaBindingFixture","-module-cache-path",str(cache)]
        if os.name=="nt":
            from antirea.swift_frontend import _compiler
            toolchain=_compiler()
            if toolchain["blockers"]:
                self.evidence["languages"]["swift"]={"status":"unavailable","reason":toolchain["blockers"]}
                self.skipTest("Portable Swift compiler is not configured")
            compiler=toolchain["swiftc"]
            if toolchain["sdk"]:
                flags += ["-sdk",toolchain["sdk"]]
                # The portable distribution does not copy module maps into the
                # globally installed Windows/VS headers. Make private maps with
                # explicit header locations instead of modifying those SDKs.
                include_key=next((key for key in env if key.upper()=="INCLUDE"),"INCLUDE")
                includes=[Path(item) for item in env.get(include_key,"").split(os.pathsep) if item]
                maps=self.base/"swift-module-maps";maps.mkdir(exist_ok=True)
                # Swift's importer already supplies the SDK vcruntime map (its
                # stdint submodule is observed while loading SwiftShims). Adding
                # another vcruntime map shadows it. Foundation also requires the
                # exact ucrt and WinSDK declarations in the three maps below.
                mapping={"ucrt.modulemap":("ucrt","corecrt.h"),"winsdk_shared.modulemap":("shared","guiddef.h"),
                         "winsdk_um.modulemap":("um","Windows.h")}
                map_evidence=[]
                for name,(part,marker) in mapping.items():
                    matches=[directory for directory in includes if directory.name.lower()==part and (directory/marker).is_file()]
                    if len(matches)!=1:
                        raise AssertionError("Cannot identify one installed SDK header root for "+name)
                    original=Path(toolchain["sdk"])/"usr/share"/name
                    text=original.read_text(encoding="utf-8")
                    text=re.sub(r'(header\s+)"([^"]+)"',lambda match:match[1]+json.dumps(str(matches[0]/match[2]).replace('\\','/')),text)
                    target=maps/name
                    if target.exists():
                        self.assertEqual(target.read_text(encoding="utf-8"),text)
                    else:
                        target.write_text(text,encoding="utf-8")
                    flags += ["-Xcc","-fmodule-map-file="+str(target)]
                    map_evidence.append({"original":str(original),"original_sha256":hashlib.sha256(original.read_bytes()).hexdigest(),
                                         "private":str(target),"private_sha256":hashlib.sha256(target.read_bytes()).hexdigest(),"header_root":str(matches[0])})
                self.evidence["swift_private_module_maps"]=map_evidence
            path_key=next((key for key in env if key.upper()=="PATH"),"PATH")
            env[path_key]=os.pathsep.join(toolchain["search_dirs"]+[env.get(path_key,"")])
            self.evidence["swift_compiler"]={"path":compiler,"version":toolchain["version"],
                "sha256":toolchain["input_hashes"][compiler],"sdk":toolchain["sdk"],
                "sdk_config_sha256":hashlib.sha256((ROOT/".tools/swift-toolchain.json").read_bytes()).hexdigest(),
                "language_mode":"6","process_search_dirs":toolchain["search_dirs"],
                "runtime_dlls":len(toolchain["runtime_files"]),"persistent_path_modified":False}
        else:
            compiler=self.available("swift","swiftc")
        return compiler,flags,env

    def test_swift_protected_integer_binding(self):
        """Swift caller to a protected integer DLL; separate from source protection."""
        value=os.environ.get("ANTIREA_BINDINGS_SWIFT_REPORT")
        if not value:
            self.skipTest("owned native source report path not supplied")
        from antirea import native_build
        from antirea.dotnet_frontend import reference_cases
        from antirea.source_validate import verify_source_contract
        import ctypes
        path=native_build._no_links(Path(value))
        self.assertTrue(path.is_relative_to(ROOT/".runs"));self.assertNotIn("rea-analysis-reports",path.parts)
        raw=path.read_bytes();report=json.loads(raw)
        self.assertIn(report["backend"],{"go_typed_native","swift_llvm_native"})
        self.assertEqual(report["status"],"artifact_created_unvalidated")
        if "contract" in report:
            contract=validate_contract(report["contract"])
        else:
            contract_path=native_build._no_links(Path(report["contract_path"]))
            self.assertTrue(contract_path.is_relative_to(path.parent))
            self.assertEqual(hashlib.sha256(contract_path.read_bytes()).hexdigest(),report["artifact_hashes"][str(contract_path.relative_to(path.parent))])
            contract=validate_contract(json.loads(contract_path.read_text()))
        self.assertEqual(verify_source_contract(report,contract)["status"],"matched")
        artifacts=report["artifacts"]
        for artifact in artifacts.values():
            library=native_build._no_links(Path(artifact["path"]));self.assertTrue(library.is_relative_to(path.parent))
            self.assertEqual(hashlib.sha256(library.read_bytes()).hexdigest(),artifact["sha256"])
        compiler,flags,env=self.swift_compiler_environment()
        output=self.base/"protected_swift_bindings";generate_bindings(contract,output)
        target=self.base/"swift_protected";target.mkdir()
        source,obj,exe=target/"main.swift",target/"bridge.o",target/"swift_protected.exe"
        source_lines=['let core = try NativeCore(libraryPath: CommandLine.arguments[1])']
        baseline=ctypes.CDLL(artifacts["baseline"]["path"],**({"winmode":0x1100} if os.name=="nt" else {}))
        ct={"i32":ctypes.c_int32,"u32":ctypes.c_uint32,"i64":ctypes.c_int64,"u64":ctypes.c_uint64}
        scalar={"i32":("Int32","Int32"),"u32":("UInt32","UInt32"),"i64":("Int64","Int64"),"u64":("UInt64","UInt64")}
        expected,entries=[],[]
        for index,function in enumerate(contract["functions"]):
            parameters=[p["type"] for p in function["parameters"]]
            self.assertIn(function["return_type"],ct)
            cases,counts=reference_cases([scalar[t][0] for t in parameters],8,10029+index)
            native=getattr(baseline,function["name"]);native.argtypes=[ct[t] for t in parameters];native.restype=ct[function["return_type"]]
            for row in cases:
                expected.append(str(native(*row)))
                arguments=','.join(f'{scalar[kind][1]}({v})' for kind,v in zip(parameters,row))
                source_lines.append(f'print(core.call_{function["name"]}({arguments}))')
            entries.append({"export":function["name"],"total":len(cases),**counts})
        source.write_text('\n'.join(source_lines)+'\n')
        self.run_command([self.cc,"-c",output/"common/antirea_bridge.c","-o",obj])
        previous=dict(self.env);self.env.clear();self.env.update(env)
        try:
            self.run_command([compiler,*flags,"-I",output/"swift",output/"swift/NativeCore.swift",source,obj,"-o",exe])
            actual=self.run_command([exe,artifacts["protected"]["path"]]).splitlines()
        finally:
            self.env.clear();self.env.update(previous)
        self.assertEqual(actual,expected)
        self.assertEqual(path.read_bytes(),raw)
        for artifact in artifacts.values():self.assertEqual(hashlib.sha256(Path(artifact["path"]).read_bytes()).hexdigest(),artifact["sha256"])
        self.evidence["swift_protected_integration"]={"status":"passed","scope":"swift_caller_to_protected_native_integer_library",
            "source_backend":report["backend"],"direct_swift_source_protection_test":False,
            "build_report":str(path),"build_report_sha256":hashlib.sha256(raw).hexdigest(),
            "baseline_sha256":artifacts["baseline"]["sha256"],"protected_sha256":artifacts["protected"]["sha256"],
            "methods":entries,"total":len(expected),"matched":len(actual),"hashes_unchanged":True,
            "external_attack_evaluation":"not_performed"}

    def test_kotlin(self):
        from antirea.jvm_frontend import _compiler
        toolchain = _compiler("kotlin")
        if toolchain["blockers"]:
            self.evidence["languages"]["kotlin"] = {"status": "unavailable", "reason": toolchain["blockers"]}
            self.skipTest("Pinned portable Kotlin compiler unavailable")
        compiler = [toolchain["java"], "-Dkotlin.home=" + toolchain["kotlin_home"],
                    "-cp", toolchain["kotlin_compiler"], "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler"]
        if not (self.base / "NativeCore.class").exists():
            self.test_java()
        source, jar = self.base / "KotlinTest.kt", self.base / "kotlin_test.jar"
        source.write_text('fun main(a:Array<String>){KotlinCore.initialize(a[0],a[1]);check(KotlinCore.call_mix(UInt.MAX_VALUE,UInt.MAX_VALUE)==ULong.MAX_VALUE);check(KotlinCore.call_echoI64(Long.MIN_VALUE)==Long.MIN_VALUE);KotlinCore.call_touch();println("OK")}')
        self.run_command([*compiler, str(self.output / "kotlin/NativeCore.kt"), str(source), "-classpath", str(self.base), "-include-runtime", "-d", str(jar)])
        adapter = self.base / ("antirea_jni.dll" if os.name == "nt" else "libantirea_jni.so")
        self.passed("kotlin", self.run_command([self.available("kotlin", "java"), "-cp", str(jar) + os.pathsep + str(self.base), "KotlinTestKt", adapter, self.core]))

    def test_typescript(self):
        if not (self.output / "javascript/antirea.node").exists():
            self.test_javascript()
        source = self.base / "typescript_test.ts"
        source.write_text('import {load} from "./bindings/typescript";\nconst c=load(' + json.dumps(str(self.core)) + ');\nconst result:bigint=c.call_mix(4294967295,4294967295);\nif(result!==18446744073709551615n)throw Error("wrong");\nc.call_touch();console.log("OK");\n')
        self.compile_typescript(source)
        self.passed("typescript", self.run_command([self.available("typescript", "node"), source.with_suffix(".js")]))
        self.evidence["languages"]["typescript"]["full_typecheck"] = True

    def compile_typescript(self, source):
        """Use the installed compiler API with full diagnostics, not transpile-only.

        Bundled editors can ship typescript.js and standard declaration libraries
        without tsc.js. The command is fixed; paths are separate argv entries.
        No target source/import is executed by the typechecker.
        """
        from antirea.javascript_frontend import discover_toolchain
        toolchain = discover_toolchain()
        compiler = toolchain["files"]["typescript"]
        script = (
            "const ts=require(process.argv[1]);"
            "const options={target:ts.ScriptTarget.ES2020,module:ts.ModuleKind.CommonJS,"
            "moduleResolution:ts.ModuleResolutionKind.Node10,strict:true,noEmitOnError:true,"
            "skipLibCheck:false,types:[]};"
            "const program=ts.createProgram({rootNames:[process.argv[2]],options});"
            "const host={getCanonicalFileName:f=>f,getCurrentDirectory:()=>process.cwd(),getNewLine:()=> '\\n'};"
            "const diagnostics=ts.getPreEmitDiagnostics(program);"
            "if(diagnostics.length){process.stderr.write(ts.formatDiagnostics(diagnostics,host));process.exit(2);}"
            "const emitted=program.emit();"
            "if(emitted.emitSkipped||emitted.diagnostics.length){"
            "process.stderr.write(ts.formatDiagnostics(emitted.diagnostics,host)||'TypeScript emit skipped');process.exit(3);}"
            "process.stdout.write(JSON.stringify({status:'typechecked_and_emitted',version:ts.version,"
            "strict:true,pre_emit_diagnostics:diagnostics.length,emit_diagnostics:emitted.diagnostics.length,"
            "source_files:program.getSourceFiles().length}));"
        )
        previous = dict(self.env)
        for key in list(self.env):
            if key.upper() in {"NODE_OPTIONS", "NODE_PATH"}:
                del self.env[key]
        try:
            result = json.loads(self.run_command([toolchain["files"]["node"]["path"], "--no-addons", "-e", script,
                                                  compiler["path"], str(source)]))
        finally:
            self.env.clear(); self.env.update(previous)
        self.assertEqual(result["status"], "typechecked_and_emitted")
        self.assertTrue(result["strict"])
        self.assertEqual(result["pre_emit_diagnostics"], 0)
        self.assertEqual(result["emit_diagnostics"], 0)
        self.assertTrue(source.with_suffix(".js").is_file())
        self.evidence["typescript_compiler"] = {**result, "path": compiler["path"], "sha256": compiler["sha256"],
                                                "api": "createProgram/getPreEmitDiagnostics/emit", "transpile_only": False}

    def test_typescript_type_errors_are_rejected_without_emit(self):
        source = self.base / "typescript_invalid.ts"
        source.write_text('import {load} from "./bindings/typescript";\nconst c=load(' + json.dumps(str(self.core))
                          + ');\nconst invalid:number=c.call_mix(4294967295,4294967295);\n', encoding="utf-8")
        with self.assertRaisesRegex(AssertionError, "TS2322"):
            self.compile_typescript(source)
        self.assertFalse(source.with_suffix(".js").exists())

    def test_z_protected_library_cross_language(self):
        """Explicitly opt in with immutable already-built trusted baseline/protected DLLs."""
        protected_value = os.environ.get("ANTIREA_BINDINGS_PROTECTED")
        baseline_value = os.environ.get("ANTIREA_BINDINGS_BASELINE")
        if not protected_value or not baseline_value:
            self.skipTest("protected native build paths not supplied; plain ABI fixture is not protection evidence")
        import ctypes
        protected, baseline = Path(protected_value).resolve(), Path(baseline_value).resolve()
        self.assertNotIn("rea-analysis-reports", protected.parts)
        self.assertNotIn("rea-analysis-reports", baseline.parts)
        digests = {"baseline": hashlib.sha256(baseline.read_bytes()).hexdigest(),
                   "protected": hashlib.sha256(protected.read_bytes()).hexdigest()}
        contract = {"schema_version": 1, "library_name": "native_core", "functions": [
            {"name": "native_transform", "return_type": "u64", "parameters": [{"name": "x", "type": "u32"}, {"name": "y", "type": "u32"}]}]}
        output = self.base / "protected_bindings"
        generate_bindings(contract, output)
        cases = [(0, 0), (1, 2), (0xffffffff, 0xffffffff), (0x80000000, 0),
                 (0x7fffffff, 0xffffffff), (123456789, 987654321), (0, 0xffffffff), (0xffffffff, 0)]
        reference = ctypes.CDLL(str(baseline), **({"winmode": 0x1100} if os.name == "nt" else {}))
        reference.native_transform.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
        reference.native_transform.restype = ctypes.c_uint64
        expected = [str(reference.native_transform(x, y)) for x, y in cases]
        evidence = {"scope": "already_protected_native_core_binding_integration", "signature": "u64 native_transform(u32,u32)",
                    "hashes_before": digests, "cases": len(cases), "languages": {},
                    "external_attack": "not_performed", "functional_validation_scope": "binding smoke, not exhaustive native validation"}
        self.evidence["protected_integration"] = evidence

        def check(language, argv):
            observed = self.run_command(argv).splitlines()
            self.assertEqual(observed, expected, language)
            evidence["languages"][language] = {"status": "passed", "matched": len(cases), "total": len(cases)}

        source = self.base / "protected_python.py"
        source.write_text('import sys\nsys.path.insert(0,' + repr(str(output / "python")) + ')\nfrom native_core import NativeCore\nc=NativeCore(' + repr(str(protected)) + ')\nfor x,y in ' + repr(cases) + ': print(c.call_native_transform(x,y))\n', encoding="utf-8")
        check("python", [self.available("python", "python"), source])

        node = self.available("javascript", "node")
        version = self.run_command([node, "--version"]).removeprefix("v")
        cache = Path(os.environ.get("LOCALAPPDATA", "")) / "node-gyp/Cache" / version
        self.run_command([self.cc, "-shared", "-I" + str(cache / "include/node"), str(output / "javascript/addon.c"),
                          str(output / "common/antirea_bridge.c"), str(cache / "x64/node.lib"), "-o", str(output / "javascript/antirea.node")])
        source = self.base / "protected_node.js"
        source.write_text('const c=require(' + json.dumps(str(output / "javascript")) + ').load(' + json.dumps(str(protected)) + ');\nfor(const [x,y] of ' + json.dumps(cases) + ')console.log(c.call_native_transform(x,y).toString());\n')
        check("javascript", [node, source])

        javac = self.available("java", "javac")
        include = Path(javac).resolve().parents[1] / "include"
        adapter = output / "antirea_jni.dll"
        self.run_command([self.cc, "-shared", "-I" + str(include), "-I" + str(include / "win32"),
                          str(output / "java/adapter.c"), str(output / "common/antirea_bridge.c"), "-o", str(adapter)])
        source = output / "ProtectedTest.java"
        pairs = ",".join("{" + str(x) + "L," + str(y) + "L}" for x, y in cases)
        source.write_text('public class ProtectedTest { public static void main(String[] a) { NativeCore.initialize(a[0],a[1]); long[][] pairs={' + pairs + '};for(long[] p:pairs)System.out.println(Long.toUnsignedString(NativeCore.call_native_transform(p[0],p[1]))); } }')
        self.run_command([javac, "-d", str(output), str(output / "java/NativeCore.java"), str(source)])
        check("java", [self.available("java", "java"), "-cp", output, "ProtectedTest", adapter, protected])

        from antirea.jvm_frontend import _compiler
        kotlin = _compiler("kotlin")
        if not kotlin["blockers"]:
            source, jar = output / "ProtectedKotlin.kt", output / "protected_kotlin.jar"
            statements = "".join(f"println(KotlinCore.call_native_transform({x}u,{y}u));" for x, y in cases)
            source.write_text('fun main(a:Array<String>){KotlinCore.initialize(a[0],a[1]);' + statements + '}')
            self.run_command([kotlin["java"], "-Dkotlin.home=" + kotlin["kotlin_home"], "-cp", kotlin["kotlin_compiler"],
                              "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", str(output / "kotlin/NativeCore.kt"),
                              str(source), "-classpath", str(output), "-include-runtime", "-d", str(jar)])
            check("kotlin", [kotlin["java"], "-cp", str(jar) + os.pathsep + str(output), "ProtectedKotlinKt", adapter, protected])
        else:
            evidence["languages"]["kotlin"] = {"status": "unavailable", "reason": kotlin["blockers"]}

        source = output / "protected_typescript.ts"
        source.write_text('import {load} from "./typescript";\nconst c=load(' + json.dumps(str(protected)) + ');\nfor(const [x,y] of ' + json.dumps(cases) + '){const v:bigint=c.call_native_transform(x,y);console.log(v.toString());}\n')
        self.compile_typescript(source)
        check("typescript", [node, source.with_suffix(".js")])
        evidence["languages"]["typescript"]["full_typecheck"] = True

        target = output / "csharp"
        (target / "fixture.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>')
        (target / "NuGet.Config").write_text('<configuration><packageSources><clear /></packageSources></configuration>')
        statements = "".join(f"Console.WriteLine(NativeCore.call_native_transform({x}u,{y}u));" for x, y in cases)
        (target / "Program.cs").write_text('using System;class Program { static void Main(string[] a) {NativeCore.Initialize(a[0]);' + statements + '}}')
        dotnet = self.available("csharp", "dotnet")
        self.run_command([dotnet, "build", str(target / "fixture.csproj"), "--nologo", "--configfile", str(target / "NuGet.Config")])
        check("csharp", [dotnet, target / "bin/Debug/net10.0/fixture.dll", protected])
        after = {"baseline": hashlib.sha256(baseline.read_bytes()).hexdigest(),
                 "protected": hashlib.sha256(protected.read_bytes()).hexdigest()}
        self.assertEqual(after, digests)
        evidence.update(status="passed", hashes_after=after)


if __name__ == "__main__":
    unittest.main()
