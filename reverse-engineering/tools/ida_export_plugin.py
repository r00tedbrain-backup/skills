# ida_export_plugin.py
# Original work — MIT License — part of r00tedbrain-backup/skills
#
# IDA Pro plugin that exports the current IDB analysis state into a directory
# of plain-text files an AI agent can read directly. Provides the same workflow
# pattern as community plugins (e.g. P4nda0s/IDA-NO-MCP) but written from
# scratch with proper licensing.
#
# Installation:
#   1. Copy this file to your IDA plugins directory:
#        Linux/macOS:  ~/.idapro/plugins/
#        Windows:      %APPDATA%\Hex-Rays\IDA Pro\plugins\
#   2. Restart IDA. The menu entry "Edit → Plugins → Skills RE Export"
#      and the hotkey Ctrl-Shift-E will be registered.
#
# Usage inside IDA:
#   - Press Ctrl-Shift-E (or use the menu) to launch the export dialog.
#   - Choose an output directory.
#   - Wait for the export to finish (status in the Output window).
#   - Open the resulting directory with your AI coding agent.
#
# Output layout produced:
#   <output>/
#     decompile/<hex_addr>.c     # one file per function with metadata header
#     decompile_failed.txt
#     decompile_skipped.txt
#     strings.txt
#     imports.txt
#     exports.txt
#     metadata.json              # binary metadata (arch, format, base, etc.)
#
# Compatible: IDA Pro 7.6+ (tested on 8.x and 9.0). Hex-Rays decompiler license
# is required for the actual C output; without it, only string/import/export
# tables are produced.

import json
import os
import sys
import traceback

import ida_kernwin
import ida_idaapi
import ida_funcs
import ida_hexrays
import ida_nalt
import idautils
import idc
import idaapi


PLUGIN_NAME    = "Skills RE Export"
PLUGIN_HOTKEY  = "Ctrl-Shift-E"
PLUGIN_COMMENT = "Export IDB analysis state for AI agents"
PLUGIN_HELP    = (
    "Exports decompiled functions, strings, imports, exports, and metadata\n"
    "into a directory of plain-text files an AI agent can read.\n"
    "See r00tedbrain-backup/skills/reverse-engineering/tools/ida_export_plugin.py"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def _write_text(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def _format_addr(ea):
    return f"{ea:#x}"


# ---------------------------------------------------------------------------
# Per-function export
# ---------------------------------------------------------------------------

def _get_callers(func_ea):
    """Return sorted unique addresses of functions calling func_ea."""
    callers = set()
    for ref in idautils.XrefsTo(func_ea):
        owner = ida_funcs.get_func(ref.frm)
        if owner is not None:
            callers.add(owner.start_ea)
    return sorted(callers)


def _get_callees(func_ea):
    """Return sorted unique addresses called from inside func_ea."""
    callees = set()
    func = ida_funcs.get_func(func_ea)
    if func is None:
        return []
    for head in idautils.Heads(func.start_ea, func.end_ea):
        if not idaapi.is_call_insn(head):
            continue
        target = idc.get_operand_value(head, 0)
        if target == idc.BADADDR:
            continue
        # Resolve through thunks — record the actual function start
        target_func = ida_funcs.get_func(target)
        if target_func is not None:
            callees.add(target_func.start_ea)
        else:
            callees.add(target)
    return sorted(callees)


def _build_metadata_header(func_ea, callers, callees):
    name = idc.get_func_name(func_ea) or f"sub_{func_ea:x}"
    return (
        f"/*\n"
        f" * func-name: {name}\n"
        f" * func-address: {_format_addr(func_ea)}\n"
        f" * callers: {', '.join(_format_addr(c) for c in callers)}\n"
        f" * callees: {', '.join(_format_addr(c) for c in callees)}\n"
        f" */\n\n"
    )


def _export_function(func_ea, decompile_dir, failed, skipped):
    """Write one .c file for the given function. Returns True on success."""
    out_path = os.path.join(decompile_dir, f"{func_ea:x}.c")
    callers = _get_callers(func_ea)
    callees = _get_callees(func_ea)
    header = _build_metadata_header(func_ea, callers, callees)

    # Skip thunks and library functions to keep the export focused
    func = ida_funcs.get_func(func_ea)
    if func and (func.flags & ida_funcs.FUNC_THUNK):
        skipped.append(f"{_format_addr(func_ea)}: thunk")
        return False
    if func and (func.flags & ida_funcs.FUNC_LIB):
        skipped.append(f"{_format_addr(func_ea)}: library")
        return False

    try:
        cfunc = ida_hexrays.decompile(func_ea)
    except Exception as exc:
        failed.append(f"{_format_addr(func_ea)}: {exc}")
        return False

    if cfunc is None:
        failed.append(f"{_format_addr(func_ea)}: decompiler returned None")
        return False

    body = str(cfunc)
    _write_text(out_path, header + body)
    return True


# ---------------------------------------------------------------------------
# Auxiliary tables
# ---------------------------------------------------------------------------

def _export_strings(out_dir):
    lines = []
    for s in idautils.Strings():
        try:
            content = str(s).replace("\n", "\\n").replace("\t", "\\t")
        except Exception:
            content = "<undecodable>"
        lines.append(f"{_format_addr(int(s.ea))}\t{s.length}\t{s.strtype}\t{content}")
    _write_text(os.path.join(out_dir, "strings.txt"), "\n".join(lines) + "\n")


def _export_imports(out_dir):
    lines = []
    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        mod = ida_nalt.get_import_module_name(i) or "<unnamed>"

        def cb(ea, name, ordinal, _mod=mod):
            label = name if name else f"<ordinal#{ordinal}>"
            lines.append(f"{_format_addr(ea)}:{_mod}!{label}")
            return True

        ida_nalt.enum_import_names(i, cb)
    _write_text(os.path.join(out_dir, "imports.txt"), "\n".join(lines) + "\n")


def _export_exports(out_dir):
    lines = []
    for index, ordinal, ea, name in idautils.Entries():
        if name:
            lines.append(f"{_format_addr(ea)}:{name}")
    _write_text(os.path.join(out_dir, "exports.txt"), "\n".join(lines) + "\n")


def _export_metadata(out_dir):
    info = idaapi.get_inf_structure() if hasattr(idaapi, "get_inf_structure") else None
    meta = {
        "input_file":   ida_nalt.get_input_file_path(),
        "input_md5":    ida_nalt.get_input_file_md5().hex() if ida_nalt.get_input_file_md5() else None,
        "image_base":   _format_addr(idaapi.get_imagebase()),
        "min_ea":       _format_addr(idc.get_inf_attr(idc.INF_MIN_EA)),
        "max_ea":       _format_addr(idc.get_inf_attr(idc.INF_MAX_EA)),
        "function_count": len(list(idautils.Functions())),
        "tool":         "skills/reverse-engineering ida_export_plugin",
        "tool_version": "1.0",
    }
    if info is not None:
        try:
            meta["procname"]  = info.procname.lower() if info.procname else None
            meta["is_64bit"]  = bool(info.is_64bit())
            meta["filetype"]  = int(info.filetype)
        except Exception:
            pass
    _write_text(os.path.join(out_dir, "metadata.json"),
                json.dumps(meta, indent=2, sort_keys=True))


# ---------------------------------------------------------------------------
# Main export pipeline
# ---------------------------------------------------------------------------

def run_export(output_dir):
    output_dir = os.path.abspath(output_dir)
    decompile_dir = os.path.join(output_dir, "decompile")
    _ensure_dir(decompile_dir)

    funcs = list(idautils.Functions())
    total = len(funcs)
    failed, skipped = [], []
    succeeded = 0

    print(f"[skills-export] starting export -> {output_dir}")
    print(f"[skills-export] {total} functions detected")

    has_hexrays = ida_hexrays.init_hexrays_plugin()
    if not has_hexrays:
        print("[skills-export] WARNING: Hex-Rays decompiler not available; "
              "function bodies will be skipped, but tables will still be exported.")

    for i, func_ea in enumerate(funcs):
        if i % 100 == 0 and i > 0:
            print(f"[skills-export]  progress: {i}/{total}")
        if has_hexrays:
            if _export_function(func_ea, decompile_dir, failed, skipped):
                succeeded += 1
        else:
            skipped.append(f"{_format_addr(func_ea)}: hex-rays unavailable")

    _export_strings(output_dir)
    _export_imports(output_dir)
    _export_exports(output_dir)
    _export_metadata(output_dir)

    _write_text(os.path.join(output_dir, "decompile_failed.txt"),  "\n".join(failed)  + "\n")
    _write_text(os.path.join(output_dir, "decompile_skipped.txt"), "\n".join(skipped) + "\n")

    print(f"[skills-export] DONE")
    print(f"[skills-export]  exported: {succeeded}")
    print(f"[skills-export]  failed:   {len(failed)}")
    print(f"[skills-export]  skipped:  {len(skipped)}")
    print(f"[skills-export]  output:   {output_dir}")

    ida_kernwin.info(
        f"Export complete\n\n"
        f"Functions exported: {succeeded}\n"
        f"Failed:             {len(failed)}\n"
        f"Skipped:            {len(skipped)}\n\n"
        f"Output: {output_dir}"
    )


# ---------------------------------------------------------------------------
# IDA plugin scaffolding
# ---------------------------------------------------------------------------

class SkillsReExportPlugin(ida_idaapi.plugin_t):
    flags    = ida_idaapi.PLUGIN_KEEP
    comment  = PLUGIN_COMMENT
    help     = PLUGIN_HELP
    wanted_name   = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        print(f"[{PLUGIN_NAME}] loaded — hotkey {PLUGIN_HOTKEY}")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        try:
            default_dir = os.path.dirname(ida_nalt.get_input_file_path() or "")
            chosen = ida_kernwin.ask_str(
                os.path.join(default_dir or os.getcwd(), "skills_export"),
                0,
                "Output directory for skills export:"
            )
            if not chosen:
                return
            run_export(chosen)
        except Exception:
            print("[skills-export] EXCEPTION:")
            traceback.print_exc()
            ida_kernwin.warning("Export failed; see Output window for traceback.")

    def term(self):
        pass


def PLUGIN_ENTRY():
    return SkillsReExportPlugin()


# ---------------------------------------------------------------------------
# Stand-alone usage (run via File → Script File…)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    default_dir = os.path.dirname(ida_nalt.get_input_file_path() or "")
    target = ida_kernwin.ask_str(
        os.path.join(default_dir or os.getcwd(), "skills_export"),
        0,
        "Output directory for skills export:"
    )
    if target:
        run_export(target)
