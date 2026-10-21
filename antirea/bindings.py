"""Generate native-core FFI bindings, not protection of arbitrary language source.

Generated source is dependency-free except for each language's installed standard
toolchain (Node-API and JNI require their matching development headers). Loading
is explicit and local; neither this module nor generated code installs packages.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat


LANGUAGES = ("c", "cpp", "rust", "swift", "go", "csharp", "java", "kotlin",
             "python", "javascript", "typescript")
TYPES = {"u32": "uint32_t", "i32": "int32_t", "u64": "uint64_t", "i64": "int64_t", "void": "void"}
IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,62}\Z")
RESERVED = set("auto break case char const continue default do double else enum extern float for goto if inline int long register restrict return short signed sizeof static struct switch typedef union unsigned void volatile while _Bool _Complex _Imaginary".split())
BRIDGE_NAMES = {"load_library", "last_error", "symbol", "ready", "error", "handle", "load", "init", "jlong_bits", "jni_path_utf8"}


def validate_contract(contract: dict) -> dict:
    """Return a detached normalized schema-1 cdecl integer-only ABI contract."""
    if not isinstance(contract, dict) or set(contract) - {"schema_version", "library_name", "functions", "calling_convention"}:
        raise ValueError("contract must contain only documented schema-1 fields")
    if type(contract.get("schema_version")) is not int or contract["schema_version"] != 1:
        raise ValueError("schema_version must be 1")
    if contract.get("calling_convention", "cdecl") != "cdecl":
        raise ValueError("only cdecl is supported")

    def identifier(value):
        if not isinstance(value, str) or not IDENTIFIER.fullmatch(value) or value in RESERVED:
            raise ValueError("names must be safe non-reserved ASCII identifiers of 1..63 characters")
        return value

    library = identifier(contract.get("library_name"))
    if library.upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}:
        raise ValueError("reserved platform library name")
    functions = contract.get("functions")
    if not isinstance(functions, list) or not 1 <= len(functions) <= 128:
        raise ValueError("functions must contain 1..128 definitions")
    seen, normalized = set(), []
    for function in functions:
        if not isinstance(function, dict) or set(function) != {"name", "return_type", "parameters"}:
            raise ValueError("invalid function fields")
        name = identifier(function["name"])
        if name in seen or name in BRIDGE_NAMES or name.startswith(("ar_", "p_", "type_", "js_")):
            raise ValueError("duplicate function or reserved generated-bridge name/prefix")
        seen.add(name)
        result = function["return_type"]
        if not isinstance(result, str) or result not in TYPES:
            raise ValueError("unsupported return type")
        parameters = function["parameters"]
        if not isinstance(parameters, list) or len(parameters) > 16:
            raise ValueError("parameters must contain at most 16 entries")
        names, params = set(), []
        for parameter in parameters:
            if not isinstance(parameter, dict) or set(parameter) != {"name", "type"}:
                raise ValueError("invalid parameter fields")
            p_name, p_type = identifier(parameter["name"]), parameter["type"]
            if p_name in names or not isinstance(p_type, str) or p_type not in TYPES or p_type == "void":
                raise ValueError("duplicate parameter or unsupported parameter type")
            names.add(p_name)
            params.append({"name": p_name, "type": p_type})
        normalized.append({"name": name, "return_type": result, "parameters": params})
    return {"schema_version": 1, "library_name": library, "calling_convention": "cdecl", "functions": normalized}


def _params(function, mapping=TYPES, separator=", "):
    return separator.join(mapping[p["type"]] + " p_" + p["name"] for p in function["parameters"])


def _args(function):
    return ", ".join("p_" + p["name"] for p in function["parameters"])


def _return(function):
    return "" if function["return_type"] == "void" else "return "


def _bridge(contract):
    header = """#ifndef ANTIREA_BRIDGE_H
#define ANTIREA_BRIDGE_H
#include <stdint.h>
#ifdef _WIN32
# define AR_CALL __cdecl
# ifdef ANTIREA_BRIDGE_BUILD
#  define AR_EXPORT __declspec(dllexport)
# else
#  define AR_EXPORT
# endif
#else
# define AR_CALL
# define AR_EXPORT __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/* Call once before any worker threads or ar_* function. Absolute UTF-8 path. */
AR_EXPORT int AR_CALL ar_load_library(const char *absolute_path);
AR_EXPORT const char * AR_CALL ar_last_error(void);
"""
    source = """#define ANTIREA_BRIDGE_BUILD
#include "antirea_bridge.h"
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
typedef HMODULE ar_library;
#else
#include <dlfcn.h>
typedef void *ar_library;
#endif
static ar_library ar_handle;
static int ar_ready;
static const char *ar_error = "not initialized";
const char * AR_CALL ar_last_error(void) { return ar_error; }
static void *ar_symbol(ar_library library, const char *name) {
#ifdef _WIN32
    return (void *)GetProcAddress(library, name);
#else
    return dlsym(library, name);
#endif
}
"""
    for f in contract["functions"]:
        params = _params(f) or "void"
        header += f"AR_EXPORT {TYPES[f['return_type']]} AR_CALL ar_{f['name']}({params});\n"
        source += f"typedef {TYPES[f['return_type']]} (AR_CALL *ar_type_{f['name']})({params});\nstatic ar_type_{f['name']} ar_p_{f['name']};\n"
    source += """int AR_CALL ar_load_library(const char *path) {
    if (ar_handle) { ar_error = "library already initialized; use one contract per process"; return -1; }
    if (!path || !path[0]) { ar_error = "absolute library path required"; return -1; }
#ifdef _WIN32
    /* Local drive paths only: no UNC, device namespace or ambient PATH lookup. */
    if (!(((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) &&
          path[1] == ':' && (path[2] == '/' || path[2] == '\\\\'))) {
        ar_error = "absolute local drive path required"; return -1;
    }
    int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
    wchar_t *wide = size ? (wchar_t *)malloc((size_t)size * sizeof(wchar_t)) : NULL;
    if (!wide) { ar_error = "invalid UTF-8 or allocation failure"; return -1; }
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, size);
    ar_library candidate = LoadLibraryExW(wide, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    free(wide);
#else
    if (path[0] != '/') { ar_error = "absolute library path required"; return -1; }
    ar_library candidate = dlopen(path, RTLD_NOW | RTLD_LOCAL);
#endif
    if (!candidate) { ar_error = "native library load failed"; return -1; }
    /* Publish neither the handle nor any function pointer until every lookup succeeds. */
"""
    for f in contract["functions"]:
        source += f'    ar_type_{f["name"]} candidate_{f["name"]} = (ar_type_{f["name"]})ar_symbol(candidate, "{f["name"]}");\n    if (!candidate_{f["name"]}) {{ ar_error = "missing symbol: {f["name"]}"; goto ar_lookup_failed; }}\n'
    source += '    ar_handle = candidate;\n'
    for f in contract["functions"]:
        source += f'    ar_p_{f["name"]} = candidate_{f["name"]};\n'
    source += '''    ar_ready = 1; ar_error = ""; return 0;
ar_lookup_failed:
#ifdef _WIN32
    if (!FreeLibrary(candidate)) {
#else
    if (dlclose(candidate) != 0) {
#endif
        /* A failed release blocks retry; no partially resolved function is callable. */
        ar_handle = candidate;
        ar_error = "failed to release incomplete native library; restart required";
    }
    return -1;
}
'''
    for f in contract["functions"]:
        source += f"{TYPES[f['return_type']]} AR_CALL ar_{f['name']}({_params(f) or 'void'}) {{\n    if (!ar_ready) abort(); /* violated initialization precondition, never fabricated results */\n    {_return(f)}ar_p_{f['name']}({_args(f)});\n}}\n"
    header += "#ifdef __cplusplus\n}\n#endif\n#endif\n"
    return header, source


def _python(contract):
    ctypes_map = {"u32": "ctypes.c_uint32", "i32": "ctypes.c_int32", "u64": "ctypes.c_uint64", "i64": "ctypes.c_int64", "void": "None"}
    text = '''"""Native-core caller only; this does not protect Python source."""
import ctypes
import os
from pathlib import Path

def _integer(value, kind):
    signed, bits = kind[0] == "i", int(kind[1:])
    low, high = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1)
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{kind} requires a Python int in [{low}, {high}]")
    return value

class NativeCore:
    def __init__(self, library_path):
        path = Path(library_path)
        if not path.is_absolute() or (os.name == "nt" and str(path).startswith("\\\\\\\\")):
            raise ValueError("absolute local library path required")
        options = {"winmode": 0x1100} if os.name == "nt" else {}
        self._library = ctypes.CDLL(str(path), **options)
'''
    for f in contract["functions"]:
        text += f"        getattr(self._library, '{f['name']}').argtypes = [{', '.join(ctypes_map[p['type']] for p in f['parameters'])}]\n        getattr(self._library, '{f['name']}').restype = {ctypes_map[f['return_type']]}\n"
    for f in contract["functions"]:
        args = ", ".join(f"_integer(p_{p['name']}, '{p['type']}')" for p in f["parameters"])
        signature = ", ".join(["self"] + ["p_" + p["name"] for p in f["parameters"]])
        text += f"\n    def call_{f['name']}({signature}):\n        return getattr(self._library, '{f['name']}')({args})\n"
    return text


def _rust(contract):
    mapping = {"u32": "u32", "i32": "i32", "u64": "u64", "i64": "i64", "void": "()"}
    text = '''// Native-core FFI only. Statically link the local bridge; no bridge DLL PATH lookup.
use std::ffi::{CString, CStr};
use std::path::Path;
#[link(name = "antirea_bridge", kind = "static")]
unsafe extern "C" {
    fn ar_load_library(path: *const std::ffi::c_char) -> i32;
    fn ar_last_error() -> *const std::ffi::c_char;
'''
    for f in contract["functions"]:
        params = ", ".join(f"p_{p['name']}: {mapping[p['type']]}" for p in f["parameters"])
        text += f"    fn ar_{f['name']}({params}) -> {mapping[f['return_type']]};\n"
    text += '''}
pub struct NativeCore { _private: () }
impl NativeCore {
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.is_absolute() { return Err("absolute library path required".into()); }
        let value = CString::new(path.to_str().ok_or("path must be UTF-8")?).map_err(|e| e.to_string())?;
        let status = unsafe { ar_load_library(value.as_ptr()) };
        if status != 0 { return Err(unsafe { CStr::from_ptr(ar_last_error()).to_string_lossy().into_owned() }); }
        Ok(Self { _private: () })
    }
'''
    for f in contract["functions"]:
        params = ", ".join(["&self"] + [f"p_{p['name']}: {mapping[p['type']]}" for p in f["parameters"]])
        text += f"    pub fn call_{f['name']}({params}) -> {mapping[f['return_type']]} {{ unsafe {{ ar_{f['name']}({_args(f)}) }} }}\n"
    return text + "}\n"


def _csharp(contract):
    mapping = {"u32": "uint", "i32": "int", "u64": "ulong", "i64": "long", "void": "void"}
    text = '''using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

// One generated contract per assembly. Native-core integration, not C# protection.
public static class NativeCore {
    private static IntPtr handle;
    private static bool resolverRegistered;
    public static void Initialize(string absolutePath) {
        if (handle != IntPtr.Zero) throw new InvalidOperationException("Already initialized");
        if (!Path.IsPathFullyQualified(absolutePath) || absolutePath.StartsWith(@"\\\\"))
            throw new ArgumentException("Absolute local path required");
        if (!resolverRegistered) {
            NativeLibrary.SetDllImportResolver(typeof(NativeCore).Assembly, Resolve);
            resolverRegistered = true;
        }
        handle = NativeLibrary.Load(absolutePath, typeof(NativeCore).Assembly,
            DllImportSearchPath.UseDllDirectoryForDependencies | DllImportSearchPath.SafeDirectories);
    }
    private static IntPtr Resolve(string name, Assembly assembly, DllImportSearchPath? flags) {
        if (name != "antirea_contract") return IntPtr.Zero;
        if (handle != IntPtr.Zero) return handle;
        throw new DllNotFoundException("Initialize the explicit local native library first");
    }
'''
    for f in contract["functions"]:
        text += f'    [DllImport("antirea_contract", EntryPoint = "{f["name"]}", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]\n    private static extern {mapping[f["return_type"]]} native_{f["name"]}({_params(f, mapping)});\n'
        text += f'    public static {mapping[f["return_type"]]} call_{f["name"]}({_params(f, mapping)}) {{\n        if (handle == IntPtr.Zero) throw new InvalidOperationException("Initialize the explicit local native library first");\n        {_return(f)}native_{f["name"]}({_args(f)});\n    }}\n'
    return text + "}\n"


def _java(contract):
    mapping = {"u32": "long", "i32": "int", "u64": "long", "i64": "long", "void": "void"}
    jni = {"u32": "jlong", "i32": "jint", "u64": "jlong", "i64": "jlong", "void": "void"}
    text = '''import java.nio.file.Path;
// Unsigned 64-bit values use Java long raw bits; use Long.toUnsignedString.
public final class NativeCore {
    private NativeCore() {}
    public static void initialize(String adapterPath, String libraryPath) {
        if (!Path.of(adapterPath).isAbsolute() || !Path.of(libraryPath).isAbsolute())
            throw new IllegalArgumentException("Absolute local paths required");
        System.load(adapterPath);
        nativeLoad(libraryPath);
    }
    private static native void nativeLoad(String path);
'''
    source = '''#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include "../common/antirea_bridge.h"
static jlong ar_jlong_bits(uint64_t value) { jlong result; memcpy(&result, &value, 8); return result; }
/* JNI's GetStringUTFChars is Modified UTF-8, not the bridge's standard UTF-8.
 * Reject malformed UTF-16 and interior NUL instead of replacing/truncating it. */
static char *ar_jni_path_utf8(JNIEnv *env, jstring path) {
    jsize length = (*env)->GetStringLength(env, path);
    const jchar *chars = (*env)->GetStringChars(env, path, NULL);
    if (!chars) return NULL;
    if ((size_t)length > (SIZE_MAX - 1) / 3) {
        (*env)->ReleaseStringChars(env, path, chars);
        (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/OutOfMemoryError"), "path too large");
        return NULL;
    }
    char *value = (char *)malloc((size_t)length * 3 + 1);
    if (!value) {
        (*env)->ReleaseStringChars(env, path, chars);
        (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/OutOfMemoryError"), "path allocation failed");
        return NULL;
    }
    size_t out = 0;
    for (jsize i = 0; i < length; ++i) {
        uint32_t code = chars[i];
        if (!code) goto ar_invalid_path;
        if (code >= 0xd800 && code <= 0xdbff) {
            if (i + 1 >= length || chars[i + 1] < 0xdc00 || chars[i + 1] > 0xdfff) goto ar_invalid_path;
            code = 0x10000 + ((code - 0xd800) << 10) + (chars[++i] - 0xdc00);
        } else if (code >= 0xdc00 && code <= 0xdfff) {
            goto ar_invalid_path;
        }
        if (code <= 0x7f) {
            value[out++] = (char)code;
        } else if (code <= 0x7ff) {
            value[out++] = (char)(0xc0 | (code >> 6));
            value[out++] = (char)(0x80 | (code & 0x3f));
        } else if (code <= 0xffff) {
            value[out++] = (char)(0xe0 | (code >> 12));
            value[out++] = (char)(0x80 | ((code >> 6) & 0x3f));
            value[out++] = (char)(0x80 | (code & 0x3f));
        } else {
            value[out++] = (char)(0xf0 | (code >> 18));
            value[out++] = (char)(0x80 | ((code >> 12) & 0x3f));
            value[out++] = (char)(0x80 | ((code >> 6) & 0x3f));
            value[out++] = (char)(0x80 | (code & 0x3f));
        }
    }
    value[out] = '\\0';
    (*env)->ReleaseStringChars(env, path, chars);
    return value;
ar_invalid_path:
    free(value);
    (*env)->ReleaseStringChars(env, path, chars);
    (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/IllegalArgumentException"), "path contains NUL or unpaired UTF-16 surrogate");
    return NULL;
}
JNIEXPORT void JNICALL Java_NativeCore_nativeLoad(JNIEnv *env, jclass cls, jstring path) {
    (void)cls;
    if (!path) { (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/IllegalArgumentException"), "path required"); return; }
    char *value = ar_jni_path_utf8(env, path);
    if (!value) return;
    int status = ar_load_library(value);
    free(value);
    if (status) (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/UnsatisfiedLinkError"), ar_last_error());
}
'''
    for f in contract["functions"]:
        name = f["name"]
        params = _params(f, mapping)
        text += f"    private static native {mapping[f['return_type']]} native_{name}({params});\n    public static {mapping[f['return_type']]} call_{name}({params}) {{\n"
        for p in f["parameters"]:
            if p["type"] == "u32":
                text += f'        if (p_{p["name"]} < 0 || p_{p["name"]} > 0xffffffffL) throw new IllegalArgumentException("u32 out of range");\n'
        text += f"        {_return(f)}native_{name}({_args(f)});\n    }}\n"
        method = ("native_" + name).replace("_", "_1")
        jp = _params(f, jni)
        source += f"JNIEXPORT {jni[f['return_type']]} JNICALL Java_NativeCore_{method}(JNIEnv *env, jclass cls{', ' if jp else ''}{jp}) {{\n    (void)env; (void)cls;\n"
        cast_args = ", ".join(f"({TYPES[p['type']]})p_{p['name']}" for p in f["parameters"])
        call = f"ar_{name}({cast_args})"
        if f["return_type"] == "u64":
            call = f"ar_jlong_bits({call})"
        source += f"    {_return(f)}{call};\n}}\n"
    kotlin_map = {"u32": "UInt", "i32": "Int", "u64": "ULong", "i64": "Long", "void": "Unit"}
    kotlin = "// Compile together with generated NativeCore.java (JNI adapter required).\nobject KotlinCore {\n    fun initialize(adapter: String, library: String) = NativeCore.initialize(adapter, library)\n"
    for f in contract["functions"]:
        params = ", ".join(f"p_{p['name']}: {kotlin_map[p['type']]}" for p in f["parameters"])
        args = ", ".join("p_" + p["name"] + (".toLong()" if p["type"] in {"u32", "u64"} else "") for p in f["parameters"])
        conversion = ".toUInt()" if f["return_type"] == "u32" else ".toULong()" if f["return_type"] == "u64" else ""
        kotlin += f"    fun call_{f['name']}({params}): {kotlin_map[f['return_type']]} = NativeCore.call_{f['name']}({args}){conversion}\n"
    return text + "}\n", source, kotlin + "}\n"


def _node(contract):
    source = '''#include <node_api.h>
#include <math.h>
#include <stdlib.h>
#include "../common/antirea_bridge.h"
#define NAPI_OK(expr) do { if ((expr) != napi_ok) { napi_throw_type_error(env, NULL, "Invalid ABI argument"); return NULL; } } while (0)
static napi_value ar_load(napi_env env, napi_callback_info info) {
    size_t count = 1, length = 0; napi_value args[1];
    NAPI_OK(napi_get_cb_info(env, info, &count, args, NULL, NULL));
    if (count != 1) { napi_throw_type_error(env, NULL, "One absolute path required"); return NULL; }
    NAPI_OK(napi_get_value_string_utf8(env, args[0], NULL, 0, &length));
    if (!length || length > 32768) { napi_throw_range_error(env, NULL, "Path length invalid"); return NULL; }
    char *path = (char *)malloc(length + 1);
    if (!path) { napi_throw_error(env, NULL, "Allocation failure"); return NULL; }
    napi_status read_status = napi_get_value_string_utf8(env, args[0], path, length + 1, &length);
    int status = read_status == napi_ok ? ar_load_library(path) : -1;
    free(path);
    if (status) { napi_throw_error(env, NULL, ar_last_error()); return NULL; }
    napi_value result; NAPI_OK(napi_get_undefined(env, &result)); return result;
}
'''
    for f in contract["functions"]:
        count = len(f["parameters"])
        source += f"static napi_value ar_js_{f['name']}(napi_env env, napi_callback_info info) {{\n    size_t count = {count + 1}; napi_value args[{count + 1}];\n    NAPI_OK(napi_get_cb_info(env, info, &count, args, NULL, NULL));\n    if (count != {count}) {{ napi_throw_type_error(env, NULL, \"Wrong argument count\"); return NULL; }}\n"
        for i, p in enumerate(f["parameters"]):
            name, kind = "p_" + p["name"], p["type"]
            if kind in {"u64", "i64"}:
                api = "uint64" if kind == "u64" else "int64"
                source += f'    {TYPES[kind]} {name}; bool lossless_{i}; NAPI_OK(napi_get_value_bigint_{api}(env, args[{i}], &{name}, &lossless_{i}));\n    if (!lossless_{i}) {{ napi_throw_range_error(env, NULL, "{kind} out of range"); return NULL; }}\n'
            else:
                low, high = (0, 4294967295) if kind == "u32" else (-2147483648, 2147483647)
                source += f'    double value_{i}; NAPI_OK(napi_get_value_double(env, args[{i}], &value_{i}));\n    if (!isfinite(value_{i}) || value_{i} < {low}.0 || value_{i} > {high}.0 || floor(value_{i}) != value_{i}) {{ napi_throw_range_error(env, NULL, "{kind} out of range"); return NULL; }}\n    {TYPES[kind]} {name} = ({TYPES[kind]})value_{i};\n'
        result_type = f["return_type"]
        call = f"ar_{f['name']}({_args(f)})"
        source += (f"    {call};\n" if result_type == "void" else f"    {TYPES[result_type]} value = {call};\n") + "    napi_value result;\n"
        maker = {"u32": "napi_create_uint32", "i32": "napi_create_int32", "u64": "napi_create_bigint_uint64", "i64": "napi_create_bigint_int64"}
        source += "    NAPI_OK(napi_get_undefined(env, &result));\n" if result_type == "void" else f"    NAPI_OK({maker[result_type]}(env, value, &result));\n"
        source += "    return result;\n}\n"
    source += "static napi_value ar_init(napi_env env, napi_value exports) {\n    napi_value fn;\n    NAPI_OK(napi_create_function(env, \"load\", NAPI_AUTO_LENGTH, ar_load, NULL, &fn));\n    NAPI_OK(napi_set_named_property(env, exports, \"load\", fn));\n"
    for f in contract["functions"]:
        source += f'    NAPI_OK(napi_create_function(env, "call_{f["name"]}", NAPI_AUTO_LENGTH, ar_js_{f["name"]}, NULL, &fn));\n    NAPI_OK(napi_set_named_property(env, exports, "call_{f["name"]}", fn));\n'
    source += "    return exports;\n}\nNAPI_MODULE(antirea, ar_init)\n"
    js = ''''use strict';
// No npm dependency. Build ./antirea.node from addon.c and the common bridge.
const path = require('node:path');
const addon = require(path.join(__dirname, 'antirea.node'));
function load(libraryPath) {
  if (typeof libraryPath !== 'string' || !path.isAbsolute(libraryPath) || libraryPath.includes('\\0'))
    throw new TypeError('An explicit absolute local library path is required');
  addon.load(libraryPath);
  return Object.freeze({
'''
    for f in contract["functions"]:
        js += f"    call_{f['name']}: (...args) => addon.call_{f['name']}(...args),\n"
    js += "  });\n}\nmodule.exports = {load};\n"
    tsmap = {"u32": "number", "i32": "number", "u64": "bigint", "i64": "bigint", "void": "void"}
    ts = "// u64/i64 must remain bigint, never Number. Runtime is ../javascript/index.js.\nexport interface NativeCore {\n"
    for f in contract["functions"]:
        params = ", ".join(f"p_{p['name']}: {tsmap[p['type']]}" for p in f["parameters"])
        ts += f"  call_{f['name']}({params}): {tsmap[f['return_type']]};\n"
    ts += "}\nexport declare function load(libraryPath: string): NativeCore;\n"
    return source, js, ts


def _go(contract):
    mapping = {"u32": "uint32", "i32": "int32", "u64": "uint64", "i64": "int64", "void": ""}
    text = '''//go:build !windows

package nativecore
/*
#cgo CFLAGS: -I${SRCDIR}/../common
#cgo linux LDFLAGS: -ldl
#include <stdlib.h>
#include "antirea_bridge.h"
*/
import "C"
import ("fmt"; "path/filepath"; "unsafe")
type NativeCore struct { ready bool }
func Load(path string) (*NativeCore, error) {
    if !filepath.IsAbs(path) { return nil, fmt.Errorf("absolute library path required") }
    value := C.CString(path); defer C.free(unsafe.Pointer(value))
    if C.ar_load_library(value) != 0 { return nil, fmt.Errorf("%s", C.GoString(C.ar_last_error())) }
    return &NativeCore{ready: true}, nil
}
'''
    for f in contract["functions"]:
        params = ", ".join(f"p_{p['name']} {mapping[p['type']]}" for p in f["parameters"])
        args = ", ".join(f"C.{TYPES[p['type']]}(p_{p['name']})" for p in f["parameters"])
        result = mapping[f["return_type"]]
        call = f"C.ar_{f['name']}({args})"
        body = call if not result else f"return {result}({call})"
        text += f'func (core *NativeCore) Call_{f["name"]}({params}) {result} {{\n    if core == nil || !core.ready {{ panic("native core not initialized") }}\n    {body}\n}}\n'
    return text


def _go_windows(contract):
    """Windows/amd64 integer ABI without cgo or a separate C bridge DLL."""
    mapping = {"u32": "uint32", "i32": "int32", "u64": "uint64", "i64": "int64", "void": ""}
    text = '''//go:build windows && amd64

// Native-core caller only. This does not protect Go caller source.
package nativecore

import ("fmt"; "path/filepath"; "runtime"; "sync"; "syscall"; "unsafe")

var loadLibraryExW = syscall.NewLazyDLL("kernel32.dll").NewProc("LoadLibraryExW")

// Handles and resolved functions belong to each instance. Do not copy after use.
// Close explicitly releases the DLL; calls and Close are serialized safely.
type NativeCore struct {
    mu sync.RWMutex
    handle syscall.Handle
'''
    for f in contract["functions"]:
        text += f'    proc_{f["name"]} uintptr\n'
    text += '''}

func Load(path string) (*NativeCore, error) {
    volume := filepath.VolumeName(path)
    if !filepath.IsAbs(path) || len(volume) != 2 || volume[1] != ':' ||
       !((volume[0] >= 'A' && volume[0] <= 'Z') || (volume[0] >= 'a' && volume[0] <= 'z')) {
        return nil, fmt.Errorf("absolute local drive library path required")
    }
    wide, err := syscall.UTF16PtrFromString(filepath.Clean(path))
    if err != nil { return nil, err }
    // kernel32 is a known system DLL. Target dependencies use restricted search
    // flags, never the current directory or ambient PATH.
    if err := loadLibraryExW.Find(); err != nil { return nil, err }
    handle, _, loadErr := loadLibraryExW.Call(uintptr(unsafe.Pointer(wide)), 0, 0x1100)
    runtime.KeepAlive(wide)
    if handle == 0 { return nil, fmt.Errorf("native library load failed: %v", loadErr) }
    core := &NativeCore{handle: syscall.Handle(handle)}
'''
    for f in contract["functions"]:
        text += f'''    core.proc_{f["name"]}, err = syscall.GetProcAddress(core.handle, "{f["name"]}")
    if err != nil {{
        if closeErr := syscall.FreeLibrary(core.handle); closeErr != nil {{
            return nil, fmt.Errorf("missing export {f["name"]}: %v; release failed: %v", err, closeErr)
        }}
        return nil, fmt.Errorf("missing export {f["name"]}: %v", err)
    }}
'''
    text += '''    return core, nil
}

func (core *NativeCore) Close() error {
    if core == nil { return nil }
    core.mu.Lock(); defer core.mu.Unlock()
    if core.handle == 0 { return nil }
    if err := syscall.FreeLibrary(core.handle); err != nil { return err }
    core.handle = 0
    return nil
}
'''
    for f in contract["functions"]:
        params = ", ".join(f"p_{p['name']} {mapping[p['type']]}" for p in f["parameters"])
        args = ", ".join(f"uintptr({'uint32' if p['type'].endswith('32') else 'uint64'}(p_{p['name']}))"
                         for p in f["parameters"])
        call = f"syscall.SyscallN(core.proc_{f['name']}" + (", " + args if args else "") + ")"
        result = mapping[f["return_type"]]
        body = f"{call}" if not result else f"value, _, _ := {call}\n    return {result}(value)"
        text += f'''func (core *NativeCore) Call_{f["name"]}({params}) {result} {{
    if core == nil {{ panic("native core not initialized") }}
    core.mu.RLock(); defer core.mu.RUnlock()
    if core.handle == 0 {{ panic("native core is closed") }}
    // LastError is not a success indicator for ordinary integer C functions.
    {body}
}}
'''
    return text


def _swift(contract):
    mapping = {"u32": "UInt32", "i32": "Int32", "u64": "UInt64", "i64": "Int64", "void": "Void"}
    text = '''import Foundation
import AntireaBridge
// Link the common C bridge; loading uses an explicit absolute local path.
public final class NativeCore {
    public init(libraryPath: String) throws {
        let status = libraryPath.withCString { ar_load_library($0) }
        if status != 0 { throw NSError(domain: "ANTIREA", code: Int(status), userInfo: [NSLocalizedDescriptionKey: String(cString: ar_last_error())]) }
    }
'''
    for f in contract["functions"]:
        params = ", ".join(f"_ p_{p['name']}: {mapping[p['type']]}" for p in f["parameters"])
        text += f"    public func call_{f['name']}({params}) -> {mapping[f['return_type']]} {{ {_return(f)}ar_{f['name']}({_args(f)}) }}\n"
    return text + "}\n"


def _no_links(path):
    for item in (path, *path.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("binding output cannot traverse symlinks/reparse points")


def generate_bindings(contract: dict, output_dir: Path) -> dict:
    """Write a fresh source-only bundle; never compile, execute, download or publish."""
    contract = validate_contract(contract)
    directory = Path(os.path.abspath(output_dir))
    _no_links(directory)
    if directory.exists():
        raise ValueError("output_dir must be new; generated bindings never overwrite existing files")
    if any(part.lower() in {"rea-analysis-reports", "attackerfolder"} for part in directory.parts):
        raise ValueError("bindings are private build inputs, not incoming or public transfer artifacts")
    parts = [part.lower() for part in directory.parts]
    if any(parts[i:i + 2] == ["defense-loop", "inbox"] for i in range(len(parts) - 1)):
        raise ValueError("bindings cannot be written into the untrusted intake inbox")
    header, bridge = _bridge(contract)
    java, jni, kotlin = _java(contract)
    addon, js, ts = _node(contract)
    files = {
        "common/antirea_bridge.h": header, "common/antirea_bridge.c": bridge,
        "c/native_core.h": '#include "../common/antirea_bridge.h"\n',
        "cpp/native_core.hpp": '#pragma once\n#include "../common/antirea_bridge.h"\n// The common header provides extern "C" and exact-width ABI types.\n',
        "rust/native_core.rs": _rust(contract), "swift/NativeCore.swift": _swift(contract),
        "swift/module.modulemap": 'module AntireaBridge { header "../common/antirea_bridge.h" export * }\n',
        "go/native_core.go": _go(contract), "go/native_core_windows_amd64.go": _go_windows(contract),
        "go/bridge.c": '//go:build !windows\n\n#include "../common/antirea_bridge.c"\n',
        "go/go.mod": "module antirea/nativecore\n\ngo 1.20\n",
        "csharp/NativeCore.cs": _csharp(contract), "java/NativeCore.java": java,
        "java/adapter.c": jni, "kotlin/NativeCore.kt": kotlin,
        "python/native_core.py": _python(contract), "javascript/addon.c": addon,
        "javascript/index.js": js, "typescript/index.d.ts": ts,
        "typescript/index.js": "'use strict';\nmodule.exports = require('../javascript/index.js');\n",
        "contract.json": json.dumps(contract, indent=2) + "\n",
    }
    files["README.md"] = """# Generated native-core bindings

These wrappers call a separately built/protected native library. They do NOT
protect arbitrary C#, Python, JavaScript, Rust or other original-language source.
The native implementation, protection evidence, behavior, performance and external
resistance must be validated separately. Generation is not compilation success.

ABI: cdecl, fixed-width integers, no strings/arrays/pointers/objects/exceptions.
Public wrapper names are call_<symbol> (Go: Call_<symbol>); C/C++ use ar_<symbol>.
Load once before starting threads. Keep library and bridge loaded until exit.
Failed initialization can be retried after its provisional native handle is released;
successful initialization remains single-use, not a reload or thread-safe loader API.
The bridge deliberately aborts if called before successful initialization.
Use trusted absolute local library paths. No package or ambient PATH lookup is
used for the requested native core; transitive OS dependencies remain trusted.
No runtime integrity or adversarial-process sandbox guarantee is provided.

## Build/deploy

- C/C++: compile common/antirea_bridge.c with the matching architecture; include
  c/native_core.h or cpp/native_core.hpp and call ar_load_library(absolute_path).
  Linux needs -ldl. On Windows use the installed MSVC developer environment.
- Rust: compile the common bridge into a static antirea_bridge.lib (Windows) or
  libantirea_bridge.a (Unix); rustc consumer.rs -L native=<archive directory>.
  The native core itself is still loaded by its explicit absolute path. Linux
  may additionally need -l dl. No bridge DLL is resolved through ambient PATH.
- Swift: compile common bridge, import with -I swift, and link its object file.
- Go Windows/amd64: standard-library DLL loading and integer calls, no cgo or C compiler.
  Load requires an absolute local-drive path, resolves every export before returning,
  and keeps separate handles per instance. Defer core.Close(); do not copy the instance.
  Other Windows architectures are unsupported. Non-Windows keeps the cgo C bridge
  and requires a matching installed C compiler. No module download is required;
  import antirea/nativecore via local replace.
- C#: compile NativeCore.cs with .NET 6+; call Initialize(absolute_library_path).
  One generated contract per assembly; initialize before any native calls.
- Java: compile NativeCore.java; compile java/adapter.c plus common bridge with
  installed JDK include and include/win32, include/linux or include/darwin.
  initialize(absolute_adapter_path, absolute_core_path) uses System.load, not
  java.library.path. u32 uses nonnegative long; u64 uses long raw bits.
- Kotlin: compile NativeCore.kt against generated Java class/JNI adapter. UInt
  and ULong conversions preserve raw bits; this is not a Kotlin/Native binding.
- Python: import native_core.py and NativeCore(absolute_core_path). ctypes is
  standard library; integer type/range checks reject booleans and truncation.
- JavaScript: build javascript/addon.c plus common bridge into antirea.node using
  installed Node-API headers (and node.lib on Windows). No npm dependencies.
  require('./javascript').load(absolute_core_path). u64/i64 are BigInt only;
  u32/i32 are range-checked integer Numbers. Native addon architecture must match.
- TypeScript: typescript/index.js is the same runtime, index.d.ts its declaration.
  Use target ES2020+ for BigInt. A TS declaration alone is not a runtime test.

Every language has a separate manifest entry. Toolchain availability and actual
compile/load/behavior results belong in separate validation evidence, never
inferred from generated source. Do not publish this build-input bundle as a
protected binary handoff: it includes ABI details and native adapter source.
"""
    directory.mkdir(parents=True, exist_ok=False)
    for relative, content in files.items():
        target = directory / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
    manifest = {"schema_version": 1, "status": "generated_not_validated", "scope": "protected_native_core_ffi",
                "contract": contract, "output_dir": str(directory),
                "languages": [{"id": language, "status": "generated_not_validated"} for language in LANGUAGES],
                "files": {relative: hashlib.sha256(content.encode("utf-8")).hexdigest() for relative, content in sorted(files.items())},
                "original_language_source_protection": False, "executed": False}
    with (directory / "manifest.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(manifest, stream, indent=2)
        stream.write("\n")
    return manifest
