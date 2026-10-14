# -*- coding: utf-8 -*-
"""
PC Check-in - Phần mềm kiểm tra máy khách trước khi sửa/vệ sinh
Chạy trên Windows 10 / 11 (mọi bản cập nhật). Chỉ dùng thư viện chuẩn của Python.
Đọc thông tin bằng PowerShell + CIM (không dùng wmic vì Windows 11 mới đã bỏ wmic).
"""
import os
import re
import sys
import json
import time
import math
import html
import wave
import ctypes
import queue
import struct
import shutil
import threading
import tempfile
import datetime
import subprocess
import xml.etree.ElementTree as ET
import multiprocessing as mp
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog, ttk, messagebox

try:
    import winsound
except ImportError:  # chỉ để file vẫn import được trên máy không phải Windows
    winsound = None

APP_TITLE = "HAMTECH | PC Check-in - Kiểm tra máy trước khi sửa"
NO_WINDOW = 0x08000000  # CREATE_NO_WINDOW


# ----------------------------------------------------------------------------
# Tiện ích PowerShell
# ----------------------------------------------------------------------------
def ps(script, timeout=60):
    full = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
            "$ErrorActionPreference='SilentlyContinue';" + script)
    try:
        r = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", full],
            capture_output=True, timeout=timeout, creationflags=NO_WINDOW)
        return r.stdout.decode("utf-8", "ignore").strip()
    except Exception:
        return ""


def ps_json(script, timeout=60):
    out = ps(script + " | ConvertTo-Json -Compress -Depth 3", timeout=timeout)
    if not out:
        return []
    try:
        d = json.loads(out)
    except Exception:
        return []
    return d if isinstance(d, list) else [d]


def g(d, k, default=""):
    v = d.get(k) if d else None
    return default if v in (None, "") else v


def first(lst):
    return lst[0] if lst else {}


def S(name, status, detail="", pct=None, temp=None):
    return dict(name=name, status=status, detail=detail, pct=pct, temp=temp)


def gb(n):
    try:
        return "%.1f GB" % (float(n) / 1024 ** 3)
    except Exception:
        return "?"


# ----------------------------------------------------------------------------
# Các hạng mục quét tự động
# ----------------------------------------------------------------------------
def scan_system():
    cs = first(ps_json("Get-CimInstance Win32_ComputerSystem | Select Manufacturer,Model"))
    bios = first(ps_json("Get-CimInstance Win32_BIOS | Select SerialNumber,SMBIOSBIOSVersion"))
    bb = first(ps_json("Get-CimInstance Win32_BaseBoard | Select Manufacturer,Product"))
    d = "%s %s\nSerial: %s\nBIOS: %s\nMainboard: %s %s" % (
        g(cs, "Manufacturer"), g(cs, "Model"), g(bios, "SerialNumber"),
        g(bios, "SMBIOSBIOSVersion"), g(bb, "Manufacturer"), g(bb, "Product"))
    return [S("Thông tin máy", "INFO", d)]


def scan_os():
    o = first(ps_json("Get-CimInstance Win32_OperatingSystem | Select Caption,Version,BuildNumber,OSArchitecture"))
    lic = first(ps_json("Get-CimInstance SoftwareLicensingProduct | Where-Object "
                        "{$_.PartialProductKey -and $_.Name -like 'Windows*'} | Select -First 1 LicenseStatus"))
    act = "Đã kích hoạt" if lic.get("LicenseStatus") == 1 else "Chưa kích hoạt / không xác định"
    d = "%s\nPhiên bản %s (build %s) - %s\nBản quyền: %s" % (
        g(o, "Caption"), g(o, "Version"), g(o, "BuildNumber"), g(o, "OSArchitecture"), act)
    return [S("Windows", "INFO", d)]


def scan_cpu():
    c = first(ps_json("Get-CimInstance Win32_Processor | Select Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed"))
    d = "%s\n%s nhân / %s luồng, xung tối đa %s MHz" % (
        str(g(c, "Name")).strip(), g(c, "NumberOfCores"), g(c, "NumberOfLogicalProcessors"), g(c, "MaxClockSpeed"))
    return [S("CPU", "INFO", d)]


def to_int(v, default=0):
    try:
        if isinstance(v, list):
            return int.from_bytes(bytes(v), "little")
        return int(float(v))
    except Exception:
        return default


def count_events(filter_expr, days=30):
    """Đếm số sự kiện trong nhật ký System theo bộ lọc trong N ngày gần nhất."""
    out = ps("(Get-WinEvent -FilterHashtable @{%s;StartTime=(Get-Date).AddDays(-%d)} | Measure-Object).Count"
             % (filter_expr, days), timeout=40)
    return to_int(out.strip(), 0)


RAM_TYPES = {20: "DDR", 21: "DDR2", 22: "DDR2 FB-DIMM", 24: "DDR3", 26: "DDR4", 27: "LPDDR", 28: "LPDDR2",
             29: "LPDDR3", 30: "LPDDR4", 34: "DDR5", 35: "LPDDR5"}
RAM_FORM = {8: "DIMM (PC)", 12: "SODIMM (laptop)", 11: "RIMM", 15: "FB-DIMM"}
BUGCHECK_RAM = {0x1A: "MEMORY_MANAGEMENT", 0x4E: "PFN_LIST_CORRUPT", 0x50: "PAGE_FAULT_IN_NONPAGED_AREA",
                0x19: "BAD_POOL_HEADER", 0xC2: "BAD_POOL_CALLER", 0xC5: "DRIVER_CORRUPTED_EXPOOL",
                0x12E: "INVALID_MDL_RANGE"}


RAM_CHIP_FF = {2, 3, 4, 5, 9, 10, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}  # dạng chip: hàn trực tiếp lên main
LAPTOP_CHASSIS = {8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32}


def ram_kind(m):
    """Phân loại 1 thanh RAM -> ('slot' | 'on' | 'unk', mô tả ngắn)."""
    ff = to_int(g(m, "FormFactor", 0))
    t = to_int(g(m, "SMBIOSMemoryType", 0))
    loc = (str(g(m, "DeviceLocator")) + " " + str(g(m, "BankLabel"))).lower()
    if any(k in loc for k in ("onboard", "on board", "on-board", "solder", "memory down", "memorydown")):
        return "on", "hàn trên main (BIOS ghi rõ)"
    if ff == 12:
        return "slot", "RAM RỜI - SODIMM (khe laptop)"
    if ff == 8:
        return "slot", "RAM RỜI - DIMM (khe PC)"
    if ff in (7, 11, 13):
        return "slot", "RAM RỜI - cắm khe"
    if ff in RAM_CHIP_FF:
        return "on", "chip hàn trên main"
    if t in (27, 28, 29, 30, 35):
        return "on", "LPDDR - gần như chắc chắn hàn trên main (trừ vài dòng máy dùng LPCAMM2)"
    return "unk", "BIOS không khai báo dạng RAM"


def is_laptop():
    out = ps("(Get-CimInstance Win32_SystemEnclosure).ChassisTypes -join ','", timeout=20)
    ids = {to_int(x) for x in out.replace(" ", "").split(",") if x}
    if not ids:
        return None
    return bool(ids & LAPTOP_CHASSIS)


def ram_classify(mods):
    """-> (kết luận, [(loại, mô tả)] theo từng thanh)"""
    if not mods:
        return ("CHƯA XÁC ĐỊNH RAM onboard hay rời (BIOS không báo từng thanh RAM) - mở nắp máy xem trực tiếp", [])
    ks = [ram_kind(m) for m in mods]
    has_slot = any(k == "slot" for k, _ in ks)
    out = []
    for k, d in ks:
        if k == "unk" and has_slot:
            k, d = "on", "nhiều khả năng hàn trên main (BIOS không ghi dạng, khác thanh cắm khe)"
        out.append((k, d))
    caps = [to_int(g(m, "Capacity", 0)) for m in mods]

    def tot(kind):
        return sum(c for (k, _), c in zip(out, caps) if k == kind)

    s, o, u = tot("slot"), tot("on"), tot("unk")
    guess = any(d.startswith("nhiều khả năng") for _, d in out)
    if s and o:
        v = "RAM HỖN HỢP: %s hàn trên main (không tháo được) + %s cắm khe (nâng cấp được)" % (gb(o), gb(s))
    elif s and not u:
        v = "RAM RỜI (cắm khe, tháo lắp/nâng cấp được): %s" % gb(s)
    elif o and not u:
        v = "RAM ONBOARD (hàn trên main): %s - không tháo/nâng cấp được; RAM hỏng thì phải sửa/thay main" % gb(o)
    elif o and u:
        v = "Có RAM hàn trên main (%s), phần còn lại (%s) BIOS không ghi rõ" % (gb(o), gb(u))
    else:
        lap = is_laptop()
        if lap is False:
            v = "NHIỀU KHẢ NĂNG là RAM RỜI (PC để bàn dùng khe DIMM) nhưng BIOS không khai báo dạng RAM - nên mở nắp xác nhận"
        else:
            v = "CHƯA XÁC ĐỊNH RAM onboard hay rời: BIOS không khai báo dạng RAM%s - mở nắp đáy xem có thanh RAM cắm khe hay chỉ có chip hàn" % (
                " (laptop có thể hàn hoặc cắm khe)" if lap else "")
    if guess:
        v += " [phần hàn là suy đoán từ BIOS]"
    return v, out


def scan_ram():
    mods = ps_json("Get-CimInstance Win32_PhysicalMemory | Select Capacity,Speed,ConfiguredClockSpeed,Manufacturer,"
                   "PartNumber,SerialNumber,DeviceLocator,BankLabel,SMBIOSMemoryType,FormFactor,ConfiguredVoltage")
    arr = first(ps_json("Get-CimInstance Win32_PhysicalMemoryArray | Select MemoryDevices,MaxCapacity,MaxCapacityEx"))
    osr = first(ps_json("Get-CimInstance Win32_OperatingSystem | Select TotalVisibleMemorySize,FreePhysicalMemory"))
    total_vis = to_int(g(osr, "TotalVisibleMemorySize", 0)) * 1024
    free = to_int(g(osr, "FreePhysicalMemory", 0)) * 1024
    installed = sum(to_int(g(m, "Capacity", 0)) for m in mods)
    used_pct = (1 - free / float(total_vis)) * 100 if total_vis else 0
    status, notes, mlines = "INFO", [], []
    verdict, kds = ram_classify(mods)

    # --- từng thanh RAM ---
    caps, types, speeds, cfgs = [], set(), set(), []
    for mi, m in enumerate(mods):
        cap = to_int(g(m, "Capacity", 0))
        t = RAM_TYPES.get(to_int(g(m, "SMBIOSMemoryType", 0)), "")
        ff = RAM_FORM.get(to_int(g(m, "FormFactor", 0)), "")
        sp, cf = to_int(g(m, "Speed", 0)), to_int(g(m, "ConfiguredClockSpeed", 0))
        volt = to_int(g(m, "ConfiguredVoltage", 0))
        caps.append(cap)
        types.add(t)
        if sp:
            speeds.add(cf or sp)
        cfgs.append((sp, cf))
        spd = "%d MHz" % sp if sp else "? MHz"
        if cf and cf != sp:
            spd += " (đang chạy %d)" % cf
        loc = str(g(m, "DeviceLocator") or g(m, "BankLabel")).strip()
        mlines.append("- [%s] %s %s %s | %s | %s %s%s | SN %s" % (
            loc, gb(cap), t, ff, spd, str(g(m, "Manufacturer")).strip(), str(g(m, "PartNumber")).strip(),
            (" | %.2fV" % (volt / 1000.0)) if volt else "", str(g(m, "SerialNumber")).strip() or "?"))
        mlines[-1] += "\n    -> " + kds[mi][1]

    # --- đánh giá cấu hình ---
    slots = to_int(g(arr, "MemoryDevices", 0))
    maxb = (to_int(g(arr, "MaxCapacityEx", 0)) or to_int(g(arr, "MaxCapacity", 0))) * 1024
    if mods:
        lp = any(t.startswith("LPDDR") for t in types)
        if len(mods) == 1 and not lp and kds[0][0] == "slot":
            notes.append("Chỉ có 1 thanh RAM: chạy single-channel, hiệu năng (nhất là card onboard/game) giảm đáng kể. "
                         "Nên lắp thêm 1 thanh cùng loại để chạy dual-channel.")
        elif len(mods) >= 2 and len(set(caps)) == 1 and len(speeds) <= 1:
            notes.append("Các thanh RAM đồng bộ (cùng dung lượng/tốc độ) - có thể chạy dual-channel.")
        if len(set(caps)) > 1:
            notes.append("Các thanh RAM khác dung lượng: chạy Flex mode, hiệu năng giảm.")
        if len([t for t in types if t]) > 1:
            status = worse(status, "WARN")
            notes.append("CẢNH BÁO: lắp lẫn nhiều loại RAM (%s) - dễ mất ổn định." % ", ".join(sorted(t for t in types if t)))
        elif len(speeds) > 1:
            notes.append("Các thanh RAM khác tốc độ: tất cả chạy theo thanh chậm nhất.")
        if any(sp and cf and cf < sp for sp, cf in cfgs):
            notes.append("RAM đang chạy thấp hơn tốc độ định mức (XMP/EXPO có thể đang tắt hoặc bị BIOS giới hạn).")
    else:
        notes.append("Không đọc được thông tin từng thanh RAM (BIOS không cung cấp hoặc RAM hàn trên bo).")
    if installed and total_vis:
        ratio = total_vis / float(installed)
        if ratio < 0.75:
            status = worse(status, "WARN")
            notes.append("CẢNH BÁO: Windows chỉ dùng được %s / %s lắp. Nghi thanh RAM lỏng/lỗi, BIOS giới hạn, "
                         "hoặc dành nhiều cho card onboard." % (gb(total_vis), gb(installed)))
        elif ratio < 0.93:
            notes.append("Một phần RAM bị hệ thống/card onboard giữ lại (bình thường với máy dùng card tích hợp).")
    if total_vis and total_vis < 4 * 1024 ** 3:
        status = worse(status, "WARN")
        notes.append("CẢNH BÁO: dưới 4 GB - quá ít cho Windows 10/11, máy sẽ rất chậm.")
    elif total_vis and total_vis < 8 * 1024 ** 3:
        notes.append("Dưới 8 GB: đủ dùng văn phòng nhẹ, nên nâng cấp nếu khách dùng nhiều ứng dụng.")
    if used_pct >= 90:
        status = worse(status, "WARN")
        notes.append("CẢNH BÁO: RAM đang dùng %.0f%% ngay lúc nghỉ - dễ treo/chậm (nhiều phần mềm chạy nền hoặc rò rỉ bộ nhớ)." % used_pct)

    head = "Dung lượng lắp: %s | Windows dùng được: %s | Đang trống: %s (đã dùng %.0f%%)" % (
        gb(installed or total_vis), gb(total_vis), gb(free), used_pct)
    lines = ["KẾT LUẬN: " + verdict, head]
    if slots:
        lines.append("Khe RAM: đang dùng %d/%d | Bo mạch hỗ trợ tối đa: %s" % (len(mods), slots, gb(maxb) if maxb else "?"))
    lines += notes + mlines
    top = ps_json("Get-Process | Sort-Object WorkingSet64 -Descending | Select -First 3 Name,WorkingSet64")
    if top:
        lines.append("Tiến trình dùng nhiều RAM nhất: " + ", ".join(
            "%s (%s)" % (g(p, "Name"), gb(g(p, "WorkingSet64", 0))) for p in top))
    lines.append("Muốn kiểm tra lỗi bit thật sự: dùng mục 'Test RAM' ở khung Test lỗi.")
    return [S("RAM", status, "\n".join(lines)), scan_ram_history()]


def scan_ram_history():
    lines, status = [], "OK"
    diag = first(ps_json("Get-WinEvent -FilterHashtable @{LogName='System';ProviderName="
                         "'Microsoft-Windows-MemoryDiagnostics-Results'} -MaxEvents 1 | "
                         "Select Id,@{n='T';e={$_.TimeCreated.ToString('dd/MM/yyyy HH:mm')}}"))
    if diag:
        if to_int(g(diag, "Id", 0)) == 1202:
            status = "FAIL"
            lines.append("Windows Memory Diagnostic (%s): PHÁT HIỆN LỖI RAM - nên thay thanh RAM." % g(diag, "T"))
        else:
            lines.append("Windows Memory Diagnostic gần nhất (%s): không phát hiện lỗi." % g(diag, "T"))
    else:
        lines.append("Máy chưa từng chạy Windows Memory Diagnostic (có thể chạy ở khung Test lỗi > Test RAM).")
    whea = count_events("LogName='System';ProviderName='Microsoft-Windows-WHEA-Logger'")
    if whea:
        status = worse(status, "WARN")
        lines.append("Lỗi phần cứng WHEA trong 30 ngày: %d (có thể do RAM/CPU/ổ cứng/nguồn)" % whea)
    else:
        lines.append("Lỗi phần cứng WHEA trong 30 ngày: 0")
    bc = ps_json("Get-WinEvent -FilterHashtable @{LogName='System';ProviderName="
                 "'Microsoft-Windows-WER-SystemErrorReporting';Id=1001;StartTime=(Get-Date).AddDays(-30)} "
                 "-MaxEvents 30 | Select Message")
    codes = []
    for e in bc:
        m = re.search(r"0x[0-9a-fA-F]{6,8}", str(e.get("Message", "")))
        if m:
            codes.append(int(m.group(0), 16))
    lines.append("Màn hình xanh (BSOD) trong 30 ngày: %d lần" % len(bc))
    mem_codes = [c for c in codes if c in BUGCHECK_RAM]
    if mem_codes:
        names = sorted(set("%s (0x%X)" % (BUGCHECK_RAM[c], c) for c in mem_codes))
        lines.append("Trong đó %d lần có mã lỗi liên quan RAM: %s" % (len(mem_codes), ", ".join(names)))
        status = worse(status, "WARN" if len(mem_codes) < 3 else "FAIL")
    elif len(bc) >= 3:
        status = worse(status, "WARN")
    kp = count_events("LogName='System';ProviderName='Microsoft-Windows-Kernel-Power';Id=41")
    lines.append("Số lần máy tắt/treo đột ngột (Kernel-Power 41) trong 30 ngày: %d" % kp)
    if kp >= 5:
        status = worse(status, "WARN")
    return S("RAM - lịch sử lỗi (30 ngày)", status, "\n".join(lines))


NVSMI_FIELDS = ["name", "driver_version", "memory.total", "memory.used", "temperature.gpu", "utilization.gpu",
                "power.draw", "power.limit", "clocks.gr", "clocks.max.gr", "pcie.link.gen.current",
                "pcie.link.gen.max", "pcie.link.width.current", "pcie.link.width.max", "fan.speed"]


def find_nvsmi():
    cands = [shutil.which("nvidia-smi"),
             os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "nvidia-smi.exe"),
             os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "NVIDIA Corporation", "NVSMI",
                          "nvidia-smi.exe")]
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return None


def nvsmi_query(exe=None):
    """Đọc thông số realtime của card NVIDIA. Trả về list dict (mỗi card 1 dict) hoặc []."""
    exe = exe or find_nvsmi()
    if not exe:
        return []
    try:
        r = subprocess.run([exe, "--query-gpu=" + ",".join(NVSMI_FIELDS), "--format=csv,noheader,nounits"],
                           capture_output=True, timeout=15, creationflags=NO_WINDOW)
    except Exception:
        return []
    rows = []
    for line in r.stdout.decode("utf-8", "ignore").strip().splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= len(NVSMI_FIELDS):
            rows.append(dict(zip(NVSMI_FIELDS, parts)))
    return rows


def num(v):
    try:
        return float(v)
    except Exception:
        return None


def gpu_kind(name):
    n = name.lower()
    if any(x in n for x in ("nvidia", "geforce", "quadro", "rtx", "gtx")):
        return "Card rời (NVIDIA)"
    if "intel" in n:
        return "Card rời (Intel Arc)" if "arc" in n else "Card tích hợp (Intel)"
    if "radeon" in n or "amd" in n:
        if any(x in n for x in (" rx ", "radeon pro", "radeon rx", "firepro")):
            return "Card rời (AMD)"
        return "Card tích hợp (AMD)"
    return "Không xác định"


GPU_SKIP = ("remote display", "virtual", "parsec", "indirect display", "displaylink", "hyper-v", "citrix",
            "vnc", "spacedesk")
GPU_CACHE = []
GPU_ORDER = {"igpu": 0, "unk": 1, "dgpu": 2}
GPU_CLS_TEXT = {"igpu": "tích hợp", "dgpu": "rời", "unk": "chưa rõ loại"}
GPU_GENERIC = {"nvidia", "intel", "amd", "ati", "corporation", "gpu", "tm", "r", "c", "graphics", "advanced",
               "micro", "devices", "inc", "series", "laptop", "max", "q", "microsoft"}


def gpu_class(name):
    k = gpu_kind(name)
    if k.startswith("Card tích hợp"):
        return "igpu"
    if k.startswith("Card rời"):
        return "dgpu"
    return "unk"


def list_gpus():
    """Danh sách card đồ họa thật (bỏ card ảo). Quy ước giống Task Manager trên laptop 2 card:
    GPU 0 = card tích hợp, GPU 1 = card rời. Trả về các dòng WMI đã sắp xếp."""
    rows = ps_json("Get-CimInstance Win32_VideoController | Select Name,DriverVersion,"
                   "@{n='DD';e={if($_.DriverDate){$_.DriverDate.ToString('yyyy-MM-dd')}}},AdapterRAM,Status,"
                   "ConfigManagerErrorCode,CurrentHorizontalResolution,CurrentVerticalResolution,CurrentRefreshRate")
    real = [v for v in rows if str(g(v, "Name")).strip()
            and not any(k in str(g(v, "Name")).lower() for k in GPU_SKIP)]
    real.sort(key=lambda v: GPU_ORDER[gpu_class(str(g(v, "Name")))])
    GPU_CACHE[:] = [dict(idx=i, name=str(g(v, "Name")).strip(), cls=gpu_class(str(g(v, "Name"))))
                    for i, v in enumerate(real)]
    return real


def short_renderer(r):
    """'ANGLE (NVIDIA, NVIDIA GeForce RTX 3050 (0x000025A2) Direct3D11 ...)' -> 'NVIDIA GeForce RTX 3050'"""
    m = re.search(r"ANGLE \([^,]+,\s*(.+?)\s*\(0x[0-9A-Fa-f]+\)", r)
    return (m.group(1) if m else r)[:60]


def gpu_tokens(name):
    return [t for t in re.findall(r"[a-z0-9]+", name.lower()) if t not in GPU_GENERIC]


def gpu_which(renderer, gpus):
    """Chuỗi Renderer của WebGL khớp với card nào trong danh sách? -> chỉ số, hoặc None nếu không xác định."""
    r = renderer.lower()
    best, best_n = None, 0
    for g_ in gpus:
        toks = gpu_tokens(g_["name"])
        if toks and all(t in r for t in toks) and len(toks) > best_n:
            best, best_n = g_["idx"], len(toks)
    return best


GPU_PREF_KEY = r"Software\Microsoft\DirectX\UserGpuPreferences"


def find_browser():
    bases = [os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles"), os.environ.get("LOCALAPPDATA")]
    for rel in (r"Microsoft\Edge\Application\msedge.exe", r"Google\Chrome\Application\chrome.exe"):
        for b in bases:
            if b and os.path.isfile(os.path.join(b, rel)):
                return os.path.join(b, rel)
    return None


def set_gpu_pref(exe, val):
    """Ép Windows chạy exe này trên GPU: '1' = tiết kiệm điện (card tích hợp), '2' = hiệu năng cao (card rời).
    Trả về giá trị cũ để khôi phục."""
    import winreg
    k = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, GPU_PREF_KEY, 0, winreg.KEY_ALL_ACCESS)
    try:
        try:
            prev = winreg.QueryValueEx(k, exe)[0]
        except FileNotFoundError:
            prev = None
        winreg.SetValueEx(k, exe, 0, winreg.REG_SZ, "GpuPreference=%s;" % val)
    finally:
        winreg.CloseKey(k)
    return prev


def restore_gpu_pref(exe, prev):
    try:
        import winreg
        k = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, GPU_PREF_KEY, 0, winreg.KEY_ALL_ACCESS)
        try:
            if prev is None:
                winreg.DeleteValue(k, exe)
            else:
                winreg.SetValueEx(k, exe, 0, winreg.REG_SZ, prev)
        finally:
            winreg.CloseKey(k)
    except Exception:
        pass


def start_gpu_server(stats, page):
    """Máy chủ cục bộ (chỉ 127.0.0.1): phát trang test và nhận số liệu (tên GPU thật đang render, FPS) từ trang gửi về."""
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = page().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            try:
                n = int(self.headers.get("Content-Length") or 0)
                stats.update(json.loads(self.rfile.read(n).decode("utf-8", "ignore")))
            except Exception:
                pass
            self.send_response(204)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def scan_gpu():
    gpus = list_gpus()
    if not gpus:
        return [S("Card đồ họa", "WARN", "Không đọc được card đồ họa")]
    # VRAM thật lấy từ registry (AdapterRAM của WMI bị cắt ở 4 GB)
    reg = ps_json("Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}' "
                  "| ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_.DriverDesc } | "
                  "Select DriverDesc,@{n='Mem';e={if($_.'HardwareInformation.qwMemorySize'){"
                  "$_.'HardwareInformation.qwMemorySize'}else{$_.'HardwareInformation.MemorySize'}}}")
    vram = {}
    for r in reg:
        v = to_int(r.get("Mem"), 0)
        if v > 0:
            vram[str(r.get("DriverDesc", ""))] = v
    nv = nvsmi_query()
    nv_i = 0
    items = []
    for gi, v in enumerate(gpus):
        name = str(g(v, "Name")).strip()
        kind = gpu_kind(name)
        status, lines = "INFO", []
        low = name.lower()
        if "basic display" in low or "basic render" in low:
            status = "WARN"
            lines.append("CẢNH BÁO: đang dùng driver mặc định của Windows, chưa cài driver card đồ họa.")
        err = to_int(g(v, "ConfigManagerErrorCode", 0))
        if err:
            status = worse(status, "FAIL" if err in (10, 43, 31) else "WARN")
            lines.append("CẢNH BÁO: thiết bị báo lỗi Device Manager mã %d%s" % (
                err, " (Code 43: card/driver lỗi hoặc card hỏng)" if err == 43 else ""))
        lines.append("%s | %s" % (name, kind))
        dd = parse_date(g(v, "DD"))
        age = ""
        if dd:
            yrs = (datetime.datetime.now() - dd).days / 365.0
            age = " | ngày driver %s" % dd.strftime("%d/%m/%Y")
            if yrs > 3 and "basic" not in low:
                age += " (cũ %.1f năm - nên cập nhật)" % yrs
        lines.append("Driver %s%s | Trạng thái WMI: %s" % (g(v, "DriverVersion", "?"), age, g(v, "Status", "?")))
        mem = vram.get(name) or to_int(g(v, "AdapterRAM", 0))
        row = None
        if kind.startswith("Card rời (NVIDIA)") and nv_i < len(nv):
            row = nv[nv_i]
            nv_i += 1
            tot = num(row["memory.total"])
            if tot:
                mem = int(tot * 1024 * 1024)
        if mem > 0:
            lines.append("Bộ nhớ đồ họa (VRAM): %s%s" % (
                gb(mem), "" if kind.startswith("Card rời") else " (card tích hợp dùng chung RAM hệ thống)"))
        if g(v, "CurrentHorizontalResolution", ""):
            lines.append("Đang xuất hình: %sx%s @ %s Hz" % (g(v, "CurrentHorizontalResolution"),
                                                          g(v, "CurrentVerticalResolution", "?"),
                                                          g(v, "CurrentRefreshRate", "?")))
        if row:
            t, u = num(row["temperature.gpu"]), num(row["utilization.gpu"])
            pw, pl = num(row["power.draw"]), num(row["power.limit"])
            lines.append("Theo dõi trực tiếp (nvidia-smi): nhiệt %s°C | tải %s%% | xung %s/%s MHz | điện %s/%s W | quạt %s%%" % (
                row["temperature.gpu"], row["utilization.gpu"], row["clocks.gr"], row["clocks.max.gr"],
                row["power.draw"], row["power.limit"], row["fan.speed"]))
            lines.append("VRAM đã dùng: %s / %s MB | PCIe: Gen%s x%s (tối đa Gen%s x%s)" % (
                row["memory.used"], row["memory.total"], row["pcie.link.gen.current"], row["pcie.link.width.current"],
                row["pcie.link.gen.max"], row["pcie.link.width.max"]))
            if t is not None:
                if t >= 90:
                    status = worse(status, "FAIL")
                    lines.append("CẢNH BÁO: nhiệt độ GPU rất cao (%.0f°C) - kiểm tra keo tản nhiệt/quạt/bụi." % t)
                elif t >= 80 and (u or 0) < 30:
                    status = worse(status, "WARN")
                    lines.append("CẢNH BÁO: GPU nóng %.0f°C dù đang nhàn rỗi - nghi khô keo hoặc tản nhiệt kém." % t)
            wc, wm = num(row["pcie.link.width.current"]), num(row["pcie.link.width.max"])
            if wc and wm and wc < wm and (u or 0) >= 30:
                status = worse(status, "WARN")
                lines.append("CẢNH BÁO: khe PCIe đang chạy x%d thay vì x%d khi có tải (tiếp xúc khe kém?)." % (wc, wm))
        elif kind.startswith("Card rời (NVIDIA)"):
            lines.append("(Không đọc được nvidia-smi - có thể chưa cài driver NVIDIA đầy đủ)")
        else:
            lines.append("(Không đọc được nhiệt độ/xung của hãng này - dùng HWiNFO/GPU-Z nếu cần)")
        items.append(S("GPU %d (%s): %s" % (gi, GPU_CLS_TEXT[gpu_class(name)], name), status, "\n".join(lines)))
    kinds = [gpu_kind(str(g(v, "Name"))) for v in gpus]
    if any(k.startswith("Card tích hợp") for k in kinds) and any(k.startswith("Card rời") for k in kinds):
        items[0]["detail"] += "\nMáy có 2 card (tích hợp + rời): bình thường với laptop đồ họa/gaming."
    if len(gpus) == 1:
        items[0]["detail"] += "\nMáy chỉ có 1 GPU (không có GPU 1)."
    items.append(scan_gpu_history())
    return items


def scan_gpu_history():
    tdr = count_events("LogName='System';Id=4101")
    nvl = count_events("LogName='System';ProviderName='nvlddmkm'")
    status, lines = "OK", []
    lines.append("Lần driver card đồ họa bị treo rồi tự phục hồi (TDR, 30 ngày): %d" % tdr)
    lines.append("Lỗi từ driver NVIDIA (nvlddmkm, 30 ngày): %d" % nvl)
    if tdr >= 5:
        status = "FAIL"
        lines.append("KẾT LUẬN: GPU/driver mất ổn định nhiều lần - nghi card hỏng, quá nhiệt hoặc driver lỗi.")
    elif tdr or nvl:
        status = "WARN"
        lines.append("Có sự cố đồ họa - nên cài lại driver và chạy 'Test GPU' ở khung Test lỗi.")
    return S("Card đồ họa - lịch sử lỗi (30 ngày)", status, "\n".join(lines))


def parse_date(s):
    try:
        return datetime.datetime.strptime(str(s)[:10], "%Y-%m-%d")
    except Exception:
        return None


RANK = {"INFO": 0, "OK": 0, "WARN": 1, "FAIL": 2}


def worse(a, b):
    return a if RANK[a] >= RANK[b] else b


def app_dir():
    return os.path.dirname(sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__))


def find_smartctl():
    for base in (app_dir(), getattr(sys, "_MEIPASS", "")):
        if not base:
            continue
        for n in ("smartctl.exe", "smartctl-nc.exe"):
            p = os.path.join(base, n)
            if os.path.isfile(p):
                return p
        tools_dir = os.path.join(base, "tools")
        if os.path.isdir(tools_dir):
            for dirpath, _, filenames in os.walk(tools_dir):
                for fn in filenames:
                    if fn.lower() in ("smartctl.exe", "smartctl-nc.exe"):
                        return os.path.join(dirpath, fn)
    for pf in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
        if pf:
            p = os.path.join(pf, "smartmontools", "bin", "smartctl.exe")
            if os.path.isfile(p):
                return p
    return shutil.which("smartctl")

def find_qrious_js():
    """Tìm file qrious.min.js trong thư mục tools nằm cùng cấp với file exe/py của app."""
    for base in (app_dir(), getattr(sys, "_MEIPASS", "")):
        if not base:
            continue
        tools_dir = os.path.join(base, "tools")
        default_path = os.path.join(tools_dir, "qrious.min.js")
        if os.path.isfile(default_path):
            return default_path
        if os.path.isdir(tools_dir):
            for dirpath, _, filenames in os.walk(tools_dir):
                for fn in filenames:
                    if fn.lower() == "qrious.min.js":
                        return os.path.join(dirpath, fn)
    return None


def smart_json(exe, args, timeout=45):
    try:
        r = subprocess.run([exe] + args, capture_output=True, timeout=timeout, creationflags=NO_WINDOW)
        return json.loads(r.stdout.decode("utf-8", "ignore") or "{}")
    except Exception:
        return {}


WEAR_IDS = (231, 233, 177, 202, 169)  # các thuộc tính "tuổi thọ SSD còn lại" (giá trị chuẩn hóa = % còn lại)
VERDICT = {
    "OK": "TỐT",
    "WARN": "CẢNH BÁO - nên sao lưu dữ liệu và theo dõi thêm",
    "FAIL": "XẤU / SẮP HỎNG - sao lưu dữ liệu ngay, nên thay ổ",
}


def pct_status(p):
    return "OK" if p >= 50 else ("WARN" if p >= 20 else "FAIL")


def judge_ata(attrs, is_ssd):
    """attrs: {id: dict(value, thresh, raw, name, prefail, failed)} -> (status, pct_tuổi_thọ, lines)"""
    status, pct, lines = "OK", None, []
    raw = lambda i: attrs.get(i, {}).get("raw", 0)
    if is_ssd:
        for i in WEAR_IDS:
            if i in attrs:
                pct = max(0, min(100, attrs[i]["value"]))
                lines.append("Tuổi thọ SSD còn lại: %d%% (thuộc tính %d)" % (pct, i))
                status = worse(status, pct_status(pct))
                break
    for i, label in ((5, "Sector đã bị thay thế (Reallocated)"), (197, "Sector chờ xử lý (Pending)"),
                     (198, "Sector hỏng không sửa được (Uncorrectable)"), (187, "Lỗi đọc không sửa được")):
        if i in attrs:
            r = raw(i)
            lines.append("%s: %d" % (label, r))
            if r > 0:
                status = worse(status, "FAIL" if (i in (5, 197, 198) and r >= 50) else "WARN")
    if 199 in attrs and raw(199) > 0:
        lines.append("Lỗi CRC đường truyền: %d (kiểm tra cáp / khe SATA)" % raw(199))
    for aid, a in attrs.items():
        f = str(a.get("failed", "")).lower()
        if "now" in f or (a.get("prefail") and a.get("thresh") and a["value"] <= a["thresh"]):
            status = "FAIL"
            lines.append("Thuộc tính %d (%s) đã chạm ngưỡng hỏng" % (aid, a.get("name", "")))
        elif "past" in f:
            status = worse(status, "WARN")
            lines.append("Thuộc tính %d (%s) từng chạm ngưỡng hỏng trong quá khứ" % (aid, a.get("name", "")))
    return status, pct, lines


def disk_item(title, head, status, pct, body, info_only=False):
    verdict = "KẾT LUẬN: " + VERDICT.get(status, "")
    if pct is not None:
        verdict += "  (sức khỏe ổ cứng %d%%)" % pct
    lines = ([] if info_only else [verdict]) + head + body
    return S("Ổ cứng: " + title, "INFO" if info_only else status, "\n".join(lines), pct)


# ---- Đọc ổ cứng: Kết hợp danh sách ổ vật lý Windows + smartctl từng ổ ----
def has_smart_data(d):
    if not d:
        return False
    return bool(
        d.get("nvme_smart_health_information_log")
        or d.get("ata_smart_attributes", {}).get("table")
        or d.get("smart_status") is not None
    )


def query_smartctl_for_disk(exe, idx, is_usb=False):
    """Đọc dữ liệu smartctl cho ổ vật lý thứ idx (/dev/pd{idx}). Hỗ trợ xuyên chip USB Box."""
    dev_path = "/dev/pd%d" % idx
    types = ["auto"]
    if is_usb:
        types = ["sat", "sntrealtek", "sntjmicron", "sntasmedia", "nvme", "auto", "scsi"]
    best = {}
    for dtype in types:
        d = smart_json(exe, ["-a", "-j", "-d", dtype, dev_path], timeout=12)
        if has_smart_data(d):
            return d
        if not best and (d.get("model_name") or d.get("scsi_model_name")):
            best = d
    return best


def item_from_smartctl(d, fallback_model="?", fallback_size=0, parts_txt="", is_usb=False):
    model = (d.get("model_name") or d.get("scsi_model_name")
             or d.get("scsi_product") or fallback_model or "?").strip()
    size = d.get("user_capacity", {}).get("bytes", 0) or fallback_size
    nv = d.get("nvme_smart_health_information_log")
    rot = d.get("rotation_rate")
    is_ssd = bool(nv) or not rot
    kind = "NVMe SSD" if nv else ("SSD SATA" if is_ssd else "HDD %s vòng/phút" % rot)
    if is_usb:
        kind += " (USB Box/Ổ ngoài)"
    title = "%s (%s)" % (model, parts_txt) if parts_txt else model
    head = ["%s | %s | %s" % (model, kind, gb(size)),
            "Serial: %s | Firmware: %s" % (d.get("serial_number", "?"), d.get("firmware_version", "?"))]
    status, pct, body = "OK", None, []
    passed = d.get("smart_status", {}).get("passed")
    if passed is False:
        status = "FAIL"
        body.append("SMART tổng thể: FAILED (ổ tự báo hỏng)")
    elif passed is True:
        body.append("SMART tổng thể: PASSED")
    if nv:
        used = nv.get("percentage_used")
        if used is not None:
            pct = max(0, min(100, 100 - used))
            body.append("Tuổi thọ còn lại: %d%% (đã dùng %d%%)" % (pct, used))
            status = worse(status, pct_status(pct))
        spare, thr = nv.get("available_spare"), nv.get("available_spare_threshold")
        if spare is not None:
            body.append("Dung lượng dự phòng còn: %s%% (ngưỡng báo động %s%%)" % (spare, thr))
            if pct is None:
                pct = max(0, min(100, int(float(spare))))
            if thr is not None and spare <= thr:
                status = "FAIL"
        if nv.get("critical_warning"):
            status = "FAIL"
            body.append("Cờ cảnh báo nghiêm trọng của ổ = %s" % nv["critical_warning"])
        me = nv.get("media_errors", 0)
        body.append("Lỗi media: %s | Số mục trong log lỗi: %s" % (me, nv.get("num_err_log_entries", 0)))
        if me:
            status = worse(status, "WARN")
        w = nv.get("data_units_written")
        if w is not None:
            body.append("Tổng dữ liệu đã ghi: %.1f TB" % (w * 512000 / 1e12))
        body.append("Số lần tắt nguồn đột ngột: %s" % nv.get("unsafe_shutdowns", "?"))
    else:
        attrs = {}
        for a in d.get("ata_smart_attributes", {}).get("table", []):
            r = a.get("raw", {}).get("value", 0)
            if a["id"] in (5, 187, 197, 198, 199):
                r &= 0xFFFFFFFF
            attrs[a["id"]] = dict(value=a.get("value", 0), thresh=a.get("thresh", 0), raw=r, name=a.get("name", ""),
                                  prefail=a.get("flags", {}).get("prefailure", False), failed=a.get("when_failed", ""))
        if not attrs:
            return None
        st2, pct, lines = judge_ata(attrs, is_ssd)
        status = worse(status, st2)
        body += lines
    extra = []
    poh = d.get("power_on_time", {}).get("hours")
    if poh is not None:
        extra.append("Đã chạy: %s giờ (~%.1f tháng)" % (poh, poh / 730.0))
    cyc = d.get("power_cycle_count")
    if cyc is not None:
        extra.append("Số lần bật nguồn: %s" % cyc)
    t = d.get("temperature", {}).get("current")
    if t is not None:
        extra.append("Nhiệt độ: %s°C" % t)
        if t >= 60:
            status = worse(status, "WARN")
    return disk_item(title, head, status, pct, body + extra)


def parse_wmi_smart(vs, th):
    attrs, thr = {}, {}
    if th:
        for i in range(2, 2 + 12 * 30, 12):
            if i + 1 < len(th) and th[i]:
                thr[th[i]] = th[i + 1]
    for i in range(2, 2 + 12 * 30, 12):
        if i + 11 >= len(vs):
            break
        aid = vs[i]
        if aid == 0:
            continue
        raw = int.from_bytes(bytes(vs[i + 5:i + 11]), "little")
        if aid in (5, 187, 197, 198, 199):
            raw &= 0xFFFFFFFF
        attrs[aid] = dict(value=vs[i + 3], thresh=thr.get(aid, 0), raw=raw, name="", prefail=bool(vs[i + 1] & 1), failed="")
    return attrs


def scan_all_physical_disks(exe=None):
    items = []
    drives = ps_json("Get-CimInstance Win32_DiskDrive | Select Index,Model,Size,PNPDeviceID,InterfaceType,MediaType")
    drives.sort(key=lambda x: to_int(x.get("Index"), 99))

    rel = {}
    for r in ps_json("Get-PhysicalDisk | ForEach-Object { $c = $_ | Get-StorageReliabilityCounter; "
                     "[pscustomobject]@{Id=$_.DeviceId;Media=[string]$_.MediaType;Bus=[string]$_.BusType;"
                     "Health=[string]$_.HealthStatus;Temp=$c.Temperature;Wear=$c.Wear;Hours=$c.PowerOnHours;"
                     "ReadErr=$c.ReadErrorsTotal;WriteErr=$c.WriteErrorsTotal} }"):
        rel[str(r.get("Id"))] = r

    # Ánh xạ số thứ tự ổ cứng (DiskNumber) -> danh sách ký tự ổ (C:, D:, E:...)
    disk_parts = {}
    for p in ps_json("Get-Partition | Where-Object { $_.DriveLetter } | Select DiskNumber,DriveLetter"):
        dn = str(p.get("DiskNumber"))
        dl = str(p.get("DriveLetter")).strip()
        if dl:
            disk_parts.setdefault(dn, []).append(dl + ":")
    for dn in disk_parts:
        disk_parts[dn] = ", ".join(sorted(set(disk_parts[dn])))

    sm = ps_json("Get-CimInstance -Namespace root/wmi -ClassName MSStorageDriver_ATAPISmartData | Select InstanceName,VendorSpecific")
    th = ps_json("Get-CimInstance -Namespace root/wmi -ClassName MSStorageDriver_FailurePredictThresholds | Select InstanceName,VendorSpecific")
    pf = ps_json("Get-CimInstance -Namespace root/wmi -ClassName MSStorageDriver_FailurePredictStatus | Select InstanceName,PredictFailure")

    def pick(rows, pnp):
        for r in rows:
            if pnp and str(r.get("InstanceName", "")).upper().startswith(pnp):
                return r
        return {}

    for dr in drives:
        idx = to_int(dr.get("Index"), 0)
        idx_str = str(idx)
        pnp = str(dr.get("PNPDeviceID", "")).upper()
        r = rel.get(idx_str, {})
        media = str(r.get("Media") or g(dr, "MediaType") or "")
        bus = str(r.get("Bus") or g(dr, "InterfaceType") or "")
        is_usb = "usb" in bus.lower() or "usb" in pnp.lower()
        parts_txt = disk_parts.get(idx_str, "")
        wmi_model = str(g(dr, "Model", "?")).strip()
        wmi_size = to_int(g(dr, "Size", 0))

        # 1. Thử đọc bằng smartctl trước cho từng ổ
        if exe:
            sd = query_smartctl_for_disk(exe, idx, is_usb=is_usb)
            if has_smart_data(sd):
                sc_item = item_from_smartctl(sd, wmi_model, wmi_size, parts_txt, is_usb=is_usb)
                if sc_item:
                    items.append(sc_item)
                    continue

        # 2. Nếu ổ đó (VD: Box USB khóa cầu SMART hoặc RAID) không đọc được bằng smartctl -> dùng WMI của ổ đó
        is_nvme = "nvme" in bus.lower()
        is_ssd = is_nvme or "ssd" in media.lower()
        title = "%s (%s)" % (wmi_model, parts_txt) if parts_txt else wmi_model
        bus_label = "%s %s%s" % (bus, media, " (USB Box/Ổ ngoài)" if is_usb else "")
        head = ["%s | %s | %s" % (wmi_model, bus_label.strip(), gb(wmi_size))]
        status, pct, body = "OK", None, []
        health = str(r.get("Health", ""))
        if health:
            body.append("Windows báo tình trạng: %s" % health)
            status = worse(status, {"Healthy": "OK", "Warning": "WARN", "Unhealthy": "FAIL"}.get(health, "OK"))
        if pick(pf, pnp).get("PredictFailure") is True:
            status = "FAIL"
            body.append("Ổ tự DỰ BÁO SẮP HỎNG (PredictFailure = True)")
        vs = pick(sm, pnp).get("VendorSpecific")
        got_attrs = False
        if vs:
            attrs = parse_wmi_smart(vs, pick(th, pnp).get("VendorSpecific"))
            if attrs:
                got_attrs = True
                st2, pct, lines = judge_ata(attrs, is_ssd)
                status = worse(status, st2)
                body += lines
                poh = attrs.get(9, {}).get("raw")
                if poh:
                    body.append("Đã chạy: %d giờ" % (poh & 0xFFFFFF))
        if not got_attrs:
            wear = r.get("Wear")
            if wear not in (None, ""):
                pct = max(0, min(100, 100 - float(wear)))
                body.append("Tuổi thọ còn lại (theo Windows): %d%%" % pct)
                status = worse(status, pct_status(pct))
            elif r.get("Health") == "Healthy" and not is_usb:
                pct = 100
            if r.get("Hours") not in (None, "", 0):
                body.append("Đã chạy: %s giờ" % r["Hours"])
            if r.get("ReadErr") or r.get("WriteErr"):
                body.append("Lỗi đọc/ghi: %s/%s" % (r.get("ReadErr") or 0, r.get("WriteErr") or 0))
                status = worse(status, "WARN")
            if is_usb:
                body.append("(Ổ cắm qua cổng USB/Box không cho phép đọc sâu bảng SMART qua chip cầu chuyển.)")
            elif not exe:
                body.append("(Chưa đọc được thuộc tính SMART chi tiết. Chép smartctl.exe vào thư mục 'tools' để có kết quả chính xác.)")
        if r.get("Temp") not in (None, "", 0):
            body.append("Nhiệt độ: %s°C" % r["Temp"])
        items.append(disk_item(title, head, status, pct, body))

    # Nếu không có ổ nào trong Win32_DiskDrive mà smartctl quét được (hiếm gặp)
    if not items and exe:
        scan = smart_json(exe, ["--scan", "-j"])
        for dev in scan.get("devices", []):
            d = smart_json(exe, ["-a", "-j", "-d", dev.get("type", "auto"), dev.get("name", "")])
            if has_smart_data(d):
                sc_item = item_from_smartctl(d)
                if sc_item:
                    items.append(sc_item)
    return items


def scan_disks():
    exe = find_smartctl()
    res = scan_all_physical_disks(exe)
    if not exe:
        res.append(S("Nguồn dữ liệu ổ cứng", "INFO",
                     "Đang dùng dữ liệu Windows (WMI) vì không tìm thấy smartctl.exe trong thư mục tools."))
    vols = ps_json("Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2 OR DriveType=3' | Select DeviceID,DriveType,Size,FreeSpace")
    lines, status = [], "OK"
    for v in vols:
        size, free = float(g(v, "Size", 0)), float(g(v, "FreeSpace", 0))
        if size <= 0:
            continue
        pct = free / size * 100 if size else 0
        if pct < 10:
            status = "WARN"
        dtype = " (USB/Thẻ nhớ)" if to_int(g(v, "DriveType", 3)) == 2 else ""
        lines.append("%s%s  trống %s / %s (%.0f%%)" % (g(v, "DeviceID"), dtype, gb(free), gb(size), pct))
    if lines:
        res.append(S("Dung lượng các phân vùng", status, "\n".join(lines)))
    return res


# ---- Pin: báo cáo chính thức của Windows (powercfg) + đối chiếu WMI ----
def battery_from_powercfg():
    path = os.path.join(tempfile.gettempdir(), "pcc_battery.xml")
    try:
        if os.path.exists(path):
            os.remove(path)
        subprocess.run(["powercfg", "/batteryreport", "/output", path, "/xml"],
                       capture_output=True, timeout=45, creationflags=NO_WINDOW)
        root = ET.parse(path).getroot()
    except Exception:
        return []
    cells = []
    for el in root.iter():
        if el.tag.split("}")[-1] != "Battery":
            continue
        kv = {c.tag.split("}")[-1]: (c.text or "").strip() for c in el}
        if "DesignCapacity" not in kv:
            continue
        try:
            cells.append(dict(design=float(kv["DesignCapacity"]), full=float(kv.get("FullChargeCapacity", 0)),
                              cycles=int(kv.get("CycleCount", 0) or 0), id=kv.get("Id", ""),
                              maker=kv.get("Manufacturer", ""), serial=kv.get("SerialNumber", ""),
                              chem=kv.get("Chemistry", ""), source="Báo cáo pin Windows (powercfg)"))
        except ValueError:
            pass
    return cells


def scan_battery():
    st = ps_json("Get-CimInstance Win32_Battery | Select EstimatedChargeRemaining,BatteryStatus")
    wd = first(ps_json("Get-CimInstance -Namespace root/wmi -ClassName BatteryStaticData | Select DesignedCapacity"))
    wf = first(ps_json("Get-CimInstance -Namespace root/wmi -ClassName BatteryFullChargedCapacity | Select FullChargedCapacity"))
    wc = first(ps_json("Get-CimInstance -Namespace root/wmi -ClassName BatteryCycleCount | Select CycleCount"))
    cells = battery_from_powercfg()
    try:
        wmi_d, wmi_f = float(wd.get("DesignedCapacity") or 0), float(wf.get("FullChargedCapacity") or 0)
    except Exception:
        wmi_d = wmi_f = 0
    if not cells and wmi_d > 0:
        cells = [dict(design=wmi_d, full=wmi_f, cycles=int(wc.get("CycleCount") or 0), id="", maker="", serial="",
                      chem="", source="WMI")]
    if not cells:
        if st:
            return [S("Pin laptop", "WARN", "Có pin nhưng Windows không đọc được dung lượng thiết kế/thực tế.\n"
                      "Thử chạy bằng quyền Administrator, hoặc pin/mạch sạc có vấn đề.")]
        return [S("Pin laptop", "INFO", "Không phát hiện pin")]
    stat_map = {1: "đang xả", 2: "đang cắm sạc", 3: "đầy", 4: "yếu", 5: "rất yếu", 6: "đang sạc", 7: "đang sạc", 8: "đang sạc", 9: "đang sạc"}
    items = []
    for n, c in enumerate(cells, 1):
        d, f = c["design"], c["full"]
        label = "Pin laptop" + (" #%d" % n if len(cells) > 1 else "")
        if d <= 0:
            items.append(S(label, "WARN", "Không đọc được dung lượng thiết kế"))
            continue
        health = f / d * 100
        wear = max(0.0, 100 - health)
        status = "OK" if health >= 80 else ("WARN" if health >= 50 else "FAIL")
        if health >= 80:
            verdict = "Tốt"
        elif health >= 65:
            verdict = "Chai trung bình - dùng được, thời lượng giảm rõ"
        elif health >= 50:
            verdict = "Chai nhiều - sắp cần thay"
        else:
            verdict = "Chai nặng - nên thay pin"
        lines = ["KẾT LUẬN: %s" % verdict,
                 "Sức khỏe pin: %.0f%%   |   Mức độ chai: %.0f%%" % (min(health, 100), wear),
                 "Dung lượng thiết kế: %d mWh   |   Sạc đầy hiện tại: %d mWh" % (d, f)]
        if c["cycles"]:
            lines.append("Số chu kỳ sạc: %d" % c["cycles"])
        info = " ".join(x for x in (c["maker"], c["id"], c["chem"]) if x)
        if info:
            lines.append("Pin: " + info)
        if st:
            lines.append("Mức pin hiện tại: %s%% (%s)" % (g(st[0], "EstimatedChargeRemaining", "?"),
                                                       stat_map.get(st[0].get("BatteryStatus"), "?")))
        if health > 105:
            lines.append("Lưu ý: dung lượng thực lớn hơn thiết kế - chip pin báo chưa chuẩn hoặc pin mới.")
        if c["source"].startswith("Báo cáo") and wmi_d > 0 and wmi_f > 0:
            hw = wmi_f / wmi_d * 100
            if abs(hw - health) > 10:
                lines.append("Cảnh báo: nguồn WMI báo %.0f%% khác nhiều so với powercfg - nên test xả pin thực tế." % hw)
        lines.append("Nguồn số liệu: %s. Đây là số do chip pin tự báo cáo." % c["source"])
        items.append(S(label, status, "\n".join(lines), min(100, round(health))))
    return items


def scan_network():
    res = []
    ad = ps_json("Get-NetAdapter -Physical | Select Name,Status,LinkSpeed,InterfaceDescription")
    wifi = [a for a in ad if any(x in str(a.get("InterfaceDescription", "")).lower()
                                 for x in ("wi-fi", "wifi", "wireless", "802.11"))]
    lines = ["%s [%s] %s - %s" % (g(a, "Name"), g(a, "Status"), g(a, "LinkSpeed"), g(a, "InterfaceDescription")) for a in ad]
    res.append(S("Card mạng (Wi-Fi/LAN)", "OK" if wifi else "WARN",
                 "\n".join(lines) if lines else "Không thấy card mạng vật lý nào"))
    try:
        r = subprocess.run(["ping", "-n", "2", "-w", "1500", "8.8.8.8"], capture_output=True,
                           timeout=15, creationflags=NO_WINDOW)
        ok = r.returncode == 0
    except Exception:
        ok = False
    res.append(S("Kết nối Internet", "OK" if ok else "WARN",
                 "Ping 8.8.8.8 thành công" if ok else "Không ping được (có thể chưa kết nối mạng)"))
    return res


def scan_devices():
    bad = ps_json("Get-CimInstance Win32_PnPEntity | Where-Object {$_.ConfigManagerErrorCode -ne 0} | "
                  "Select Name,ConfigManagerErrorCode")
    if not bad:
        return [S("Thiết bị lỗi trong Device Manager", "OK", "Không có thiết bị nào báo lỗi")]
    lines = ["%s (mã lỗi %s)" % (g(b, "Name", "Thiết bị không tên"), g(b, "ConfigManagerErrorCode")) for b in bad]
    return [S("Thiết bị lỗi trong Device Manager", "WARN", "\n".join(lines))]


def scan_peripherals():
    res = []
    snd = ps_json("Get-CimInstance Win32_SoundDevice | Select Name,Status")
    res.append(S("Âm thanh (driver)", "OK" if snd else "WARN",
                 "\n".join("%s [%s]" % (g(s, "Name"), g(s, "Status")) for s in snd) or "Không thấy thiết bị âm thanh"))
    cam = ps_json("Get-PnpDevice -Class Camera,Image -PresentOnly | Select FriendlyName,Status")
    res.append(S("Webcam (driver)", "OK" if cam else "WARN",
                 "\n".join("%s [%s]" % (g(c, "FriendlyName"), g(c, "Status")) for c in cam) or "Không thấy webcam"))
    bt = ps_json("Get-PnpDevice -Class Bluetooth -PresentOnly | Select FriendlyName,Status")
    res.append(S("Bluetooth (driver)", "OK" if bt else "WARN",
                 "\n".join("%s [%s]" % (g(b, "FriendlyName"), g(b, "Status")) for b in bt[:6]) or "Không thấy Bluetooth"))
    return res


# ----------------------------------------------------------------------------
# Đọc nhiệt độ CPU qua Core Temp Shared Memory
# ----------------------------------------------------------------------------
class _CoreTempSharedData(ctypes.Structure):
    _fields_ = [
        ("uiLoad", ctypes.c_uint * 256),
        ("uiTjMax", ctypes.c_uint * 128),
        ("uiCoreCnt", ctypes.c_uint),
        ("uiCPUCnt", ctypes.c_uint),
        ("fTemp", ctypes.c_float * 256),
        ("fVID", ctypes.c_float),
        ("fCPUSpeed", ctypes.c_float),
        ("fFSBSpeed", ctypes.c_float),
        ("fMultiplier", ctypes.c_float),
        ("sCPUName", ctypes.c_char * 100),
        ("ucFahrenheit", ctypes.c_ubyte),
        ("ucDeltaToTjMax", ctypes.c_ubyte),
    ]


def _read_coretemp_memory():
    """Trả về danh sách nhiệt độ (°C) của từng nhân CPU từ bộ nhớ chia sẻ Core Temp."""
    from ctypes import wintypes
    FILE_MAP_READ = 0x0004
    k32 = ctypes.windll.kernel32
    k32.OpenFileMappingW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    k32.OpenFileMappingW.restype = wintypes.HANDLE
    k32.MapViewOfFile.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_size_t]
    k32.MapViewOfFile.restype = ctypes.c_void_p
    k32.UnmapViewOfFile.argtypes = [ctypes.c_void_p]
    k32.UnmapViewOfFile.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL

    handle = None
    for map_name in ("CoreTempMappingObject", "Global\\CoreTempMappingObject", "CoreTempMappingObjectEx"):
        handle = k32.OpenFileMappingW(FILE_MAP_READ, False, map_name)
        if handle:
            break
    if not handle:
        return []
    try:
        ptr = k32.MapViewOfFile(handle, FILE_MAP_READ, 0, 0, ctypes.sizeof(_CoreTempSharedData))
        if not ptr:
            return []
        try:
            data = _CoreTempSharedData.from_address(ptr)
            cores = min(int(data.uiCoreCnt), 128)
            if cores <= 0:
                return []
            temps = []
            for i in range(cores):
                val = float(data.fTemp[i])
                if data.ucDeltaToTjMax and data.uiTjMax[0] > 0:
                    val = float(data.uiTjMax[0]) - val
                if data.ucFahrenheit:
                    val = (val - 32.0) * 5.0 / 9.0
                if 0 < val < 130:
                    temps.append(val)
            return temps
        finally:
            k32.UnmapViewOfFile(ptr)
    finally:
        k32.CloseHandle(handle)


def find_coretemp_exe():
    """Tìm Core Temp trong thư mục tools nằm cùng cấp với file exe/py của app."""
    for base in (app_dir(), getattr(sys, "_MEIPASS", "")):
        if not base:
            continue
        tools_dir = os.path.join(base, "tools")
        # Ưu tiên đường dẫn mặc định tools\Core Temp\Core Temp.exe
        default_path = os.path.join(tools_dir, "Core Temp", "Core Temp.exe")
        if os.path.isfile(default_path):
            return default_path
        # Quét toàn bộ thư mục tools phòng khi đổi tên thư mục con
        if os.path.isdir(tools_dir):
            for dirpath, _, filenames in os.walk(tools_dir):
                for fn in filenames:
                    if fn.lower() in ("core temp.exe", "coretemp.exe", "coretemp64.exe"):
                        return os.path.join(dirpath, fn)
    return None


def _ensure_coretemp_ini(exe_path):
    """Đảm bảo CoreTemp.ini bật sẵn EnableSharedMemory=1 và khởi động thu nhỏ."""
    ini_path = os.path.join(os.path.dirname(exe_path), "CoreTemp.ini")
    try:
        if not os.path.isfile(ini_path):
            with open(ini_path, "w", encoding="utf-8") as f:
                f.write("[General]\nEnableSharedMemory=1\nStartMinimized=1\nCloseToSystray=1\n")
            return
        with open(ini_path, "r", encoding="utf-8", errors="ignore") as f:
            txt = f.read()
        changed = False
        if "EnableSharedMemory=0" in txt:
            txt = txt.replace("EnableSharedMemory=0", "EnableSharedMemory=1")
            changed = True
        elif "EnableSharedMemory=" not in txt:
            txt = txt.rstrip() + "\nEnableSharedMemory=1\n"
            changed = True
        if changed:
            with open(ini_path, "w", encoding="utf-8") as f:
                f.write(txt)
    except Exception:
        pass


def get_coretemp_readings():
    """Lấy danh sách nhiệt độ các nhân CPU từ Core Temp (tự bật ẩn nếu chưa chạy)."""
    temps = _read_coretemp_memory()
    if temps:
        return temps
    exe = find_coretemp_exe()
    if not exe:
        return []
    _ensure_coretemp_ini(exe)
    exe_dir = os.path.dirname(exe)
    try:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 7  # SW_SHOWMINNOACTIVE
        subprocess.Popen([exe], cwd=exe_dir, startupinfo=si)
    except OSError:
        try:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, None, exe_dir, 7)
        except Exception:
            return []
    for _ in range(20):
        time.sleep(0.25)
        temps = _read_coretemp_memory()
        if temps:
            return temps
    return []


def get_temp():
    """Trả về nhiệt độ nhân CPU cao nhất (dùng cho cả quét tự động và Stress CPU)."""
    temps = get_coretemp_readings()
    return max(temps) if temps else None


def scan_temp():
    temps = get_coretemp_readings()
    if not temps:
        return [S("Nhiệt độ CPU", "INFO",
                  "Không đọc được nhiệt độ từ Core Temp.\n"
                  "Hãy kiểm tra file tools\\Core Temp\\Core Temp.exe hoặc chạy app bằng quyền Administrator.")]
    tmax = max(temps)
    tmin = min(temps)
    tavg = sum(temps) / len(temps)
    st = "OK" if tavg < 70 else ("WARN" if tavg < 85 else "FAIL")
    lines = [
        "Nhiệt độ CPU: %.0f°C (MAX: %.0f°C | MIN: %.0f°C)" % (tavg, tmax, tmin),
        "Chi tiết %d nhân: %s" % (len(temps), ", ".join("%.0f°C" % t for t in temps)),
    ]
    return [S("Nhiệt độ CPU", st, "\n".join(lines), temp=tavg)]


SCANS = [
    ("Thông tin máy", scan_system), ("Windows", scan_os), ("CPU", scan_cpu), ("RAM", scan_ram),
    ("Card đồ họa", scan_gpu), ("Ổ cứng", scan_disks), ("Pin", scan_battery),
    ("Mạng", scan_network), ("Thiết bị lỗi", scan_devices), ("Âm thanh/Webcam/Bluetooth", scan_peripherals),
    ("Nhiệt độ", scan_temp),
]

STATUS_TEXT = {"OK": "Đạt", "WARN": "Cảnh báo", "FAIL": "Lỗi", "INFO": "Thông tin"}


# ----------------------------------------------------------------------------
# Stress CPU (phải nằm ở cấp module để multiprocessing + PyInstaller hoạt động)
# ----------------------------------------------------------------------------
def burn(seconds):
    end = time.time() + seconds
    x = 0.0001
    while time.time() < end:
        for _ in range(20000):
            x = math.sqrt(x * x + 1.2345) * 1.0000001


# ----------------------------------------------------------------------------
# Test RAM: ghi - đọc lại - so sánh nhiều mẫu bit (chạy ở tiến trình riêng)
# ----------------------------------------------------------------------------
class _MEMSTAT(ctypes.Structure):
    _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                ("sullAvailExtendedVirtual", ctypes.c_ulonglong)]


def mem_status():
    """(tổng RAM vật lý, RAM vật lý còn trống) tính bằng byte."""
    m = _MEMSTAT()
    m.dwLength = ctypes.sizeof(m)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
    return m.ullTotalPhys, m.ullAvailPhys


RAM_BLOCK = 32 * 1024 * 1024
# (tên mẫu, byte lặp lại / None = ngẫu nhiên / "addr" = khác nhau theo từng khối)
RAM_PATTERNS = [("0x00 (toàn bit 0)", b"\x00"), ("0xFF (toàn bit 1)", b"\xff"),
                ("0xAA (10101010)", b"\xaa"), ("0x55 (01010101)", b"\x55"),
                ("Ngẫu nhiên", None), ("Theo địa chỉ khối", "addr")]


def _first_diffs(blk, ref, limit=3):
    bad, step = [], 1 << 20
    for off in range(0, len(blk), step):
        if blk[off:off + step] != ref[off:off + step]:
            for j in range(off, min(off + step, len(blk))):
                if blk[j] != ref[j]:
                    bad.append(j)
                    if len(bad) >= limit:
                        return bad
    return bad


def ram_worker(idx, mb, q):
    n_blk = max(1, mb // 32)
    try:
        blocks = [bytearray(RAM_BLOCK) for _ in range(n_blk)]
    except MemoryError:
        q.put(("fail", idx, "Không cấp phát đủ RAM để test"))
        return
    errors, done, total = 0, 0, n_blk * len(RAM_PATTERNS) * 2
    for pname, p in RAM_PATTERNS:
        if isinstance(p, bytes):
            const = p * RAM_BLOCK
        elif p is None:
            const = os.urandom(RAM_BLOCK)
        else:
            const = None

        def ref_of(bi):
            return const if const is not None else bytes([(bi * 29 + 13 + idx * 7) & 0xFF]) * RAM_BLOCK

        for bi, b in enumerate(blocks):
            b[:] = ref_of(bi)
            done += 1
            q.put(("prog", idx, done / float(total), pname))
        for bi, b in enumerate(blocks):
            ref = ref_of(bi)
            if b != ref:
                errors += 1
                for j in _first_diffs(b, ref):
                    q.put(("err", idx, "Mẫu %s | khối %d | offset %d: ghi 0x%02X, đọc lại 0x%02X" % (
                        pname, bi, j, ref[j], b[j])))
            done += 1
            q.put(("prog", idx, done / float(total), pname))
    q.put(("done", idx, n_blk * 32, errors))


# ----------------------------------------------------------------------------
# Test GPU: trang WebGL tự tạo (chạy bằng trình duyệt, tải GPU thật)
# ----------------------------------------------------------------------------
GPU_HTML = """<!DOCTYPE html><html lang="vi"><head><meta charset="utf-8"><title>PC Check-in - Test GPU</title>
<style>html,body{margin:0;height:100%;background:#000;overflow:hidden;font-family:Segoe UI,Arial,sans-serif}
canvas{width:100%;height:100%;display:block}
#hud{position:fixed;left:12px;top:12px;color:#fff;background:rgba(0,0,0,.7);padding:10px 14px;border-radius:8px;
font-size:14px;line-height:1.6;white-space:pre}
#alert{position:fixed;left:0;top:0;right:0;bottom:0;display:none;align-items:center;justify-content:center;
background:#b91c1c;color:#fff;font-size:30px;text-align:center;padding:30px}</style></head><body>
<canvas id="c"></canvas><div id="hud">Đang khởi tạo WebGL...</div><div id="alert"></div>
<script>
var DRAWS=__DRAWS__, LEVEL="__LEVEL__";
function post(o){try{fetch('/r',{method:'POST',body:JSON.stringify(o)}).catch(function(){});}catch(e){}}
var c=document.getElementById('c'),hud=document.getElementById('hud'),al=document.getElementById('alert');
var gl=c.getContext('webgl',{antialias:false,powerPreference:'__PREF__'})||c.getContext('experimental-webgl');
if(!gl){hud.textContent='KHÔNG bật được WebGL: driver card lỗi, GPU bị tắt hoặc trình duyệt tắt tăng tốc phần cứng.';post({error:'Không bật được WebGL'});}
else{
var dbg=gl.getExtension('WEBGL_debug_renderer_info');
var gpu=dbg?gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL):'(không rõ)';
function sh(t,s){var o=gl.createShader(t);gl.shaderSource(o,s);gl.compileShader(o);return o;}
var vs='attribute vec2 p;void main(){gl_Position=vec4(p,0.,1.);}';
var fs='precision highp float;uniform vec2 r;uniform float t;'+
'void main(){vec2 uv=(gl_FragCoord.xy-.5*r)/r.y;vec2 z=uv*1.8;'+
'vec2 k=vec2(.355+.1*sin(t*.3),.355+.1*cos(t*.2));float a=0.;'+
'for(int i=0;i<120;i++){z=vec2(z.x*z.x-z.y*z.y,2.*z.x*z.y)+k;float l=dot(z,z);if(l>4.){z/=l;}a+=sin(l*3.+float(i)*.05);}'+
'float v=.5+.5*sin(a*.05+t);gl_FragColor=vec4(v,.5+.5*sin(a*.03),.5+.5*cos(v*6.),1.);}';
var pr=gl.createProgram();gl.attachShader(pr,sh(gl.VERTEX_SHADER,vs));gl.attachShader(pr,sh(gl.FRAGMENT_SHADER,fs));
gl.linkProgram(pr);gl.useProgram(pr);
if(!gl.getProgramParameter(pr,gl.LINK_STATUS)){hud.textContent='Lỗi biên dịch shader trên GPU này: '+gl.getProgramInfoLog(pr);post({error:'Lỗi biên dịch shader',renderer:String(gpu)});}
var b=gl.createBuffer();gl.bindBuffer(gl.ARRAY_BUFFER,b);
gl.bufferData(gl.ARRAY_BUFFER,new Float32Array([-1,-1,1,-1,-1,1,1,1]),gl.STATIC_DRAW);
var loc=gl.getAttribLocation(pr,'p');gl.enableVertexAttribArray(loc);gl.vertexAttribPointer(loc,2,gl.FLOAT,false,0,0);
var ur=gl.getUniformLocation(pr,'r'),ut=gl.getUniformLocation(pr,'t');
var lost=false,t0=performance.now(),last=t0,frames=0,tot=0,minfps=1e9,shown='',lastpost=0;
c.addEventListener('webglcontextlost',function(e){e.preventDefault();lost=true;post({lost:true,renderer:String(gpu)});
al.style.display='flex';al.textContent='GPU BỊ RESET (mất ngữ cảnh WebGL) sau '+((performance.now()-t0)/1000).toFixed(0)+
' giây - GPU/driver mất ổn định. Hãy chọn "GPU lỗi" trong phần mềm.';});
function frame(now){
 if(lost)return;
 var d=window.devicePixelRatio||1,w=Math.floor(innerWidth*d),h=Math.floor(innerHeight*d);
 if(c.width!=w||c.height!=h){c.width=w;c.height=h;}
 gl.viewport(0,0,w,h);gl.uniform2f(ur,w,h);
 for(var i=0;i<DRAWS;i++){gl.uniform1f(ut,now/1000+i*.01);gl.drawArrays(gl.TRIANGLE_STRIP,0,4);}
 frames++;
 if(now-last>=500){var fps=frames*1000/(now-last);frames=0;last=now;tot++;
  if(fps<minfps)minfps=fps;
  var el=(now-t0)/1000;
  if(now-lastpost>=2000){lastpost=now;post({renderer:String(gpu),fps:+fps.toFixed(1),min:+minfps.toFixed(1),secs:+el.toFixed(0),draws:DRAWS});}
  hud.textContent='GPU đang dùng: '+gpu+'\\nMức tải: '+LEVEL+' ('+DRAWS+' lớp/khung hình)\\nFPS: '+fps.toFixed(0)+
  '   (thấp nhất: '+minfps.toFixed(0)+')\\nĐã chạy: '+el.toFixed(0)+' giây\\n'+
  'Quan sát: nhấp nháy, sọc, đốm màu lạ, đơ hình, tắt màn hình = GPU lỗi.\\nXong thì đóng tab và quay lại phần mềm.';}
 requestAnimationFrame(frame);}
requestAnimationFrame(frame);
}
</script></body></html>"""


# ----------------------------------------------------------------------------
# Bố cục bàn phím (id = VK code, hoặc keysym cho phím Shift/Ctrl/Alt)
# ----------------------------------------------------------------------------
def _kb_rows():
    L = lambda s: [(c, ord(c), 1) for c in s]
    r0 = [("Esc", 27, 1.3)] + [("F%d" % i, 111 + i, 1) for i in range(1, 13)] + [("Del", 46, 1.3)]
    r1 = [("`", 192, 1)] + L("1234567890") + [("-", 189, 1), ("=", 187, 1), ("Backspace", 8, 2.4)]
    r2 = [("Tab", 9, 1.8)] + L("QWERTYUIOP") + [("[", 219, 1), ("]", 221, 1), ("\\", 220, 1.6)]
    r3 = [("Caps", 20, 2.2)] + L("ASDFGHJKL") + [(";", 186, 1), ("'", 222, 1), ("Enter", 13, 2.6)]
    r4 = [("Shift", "Shift_L", 2.8)] + L("ZXCVBNM") + [(",", 188, 1), (".", 190, 1), ("/", 191, 1), ("Shift", "Shift_R", 3.2)]
    r5 = [("Ctrl", "Control_L", 1.6), ("Alt", "Alt_L", 1.6), ("Space", 32, 7), ("Alt", "Alt_R", 1.6),
          ("Ctrl", "Control_R", 1.6), ("<", 37, 1), ("^", 38, 1), ("v", 40, 1), (">", 39, 1)]
    return [r0, r1, r2, r3, r4, r5]


KB_ROWS = _kb_rows()
MOD_KEYSYMS = ("Shift_L", "Shift_R", "Control_L", "Control_R", "Alt_L", "Alt_R")


LOGO_B64 = (
    "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"
    "pRa9CzhsvQF7JBQitq4UBotvvuUPn/5y9+OryqTryGab7d505henH7D3M5B3RKYyro4dA0QD2hCCB01kgJGyTEAjAqqCTUip56h0"
    "ZFjwycsv4QphU9zZVatW3X777WvWrAGAcrm8xx577LTTTgXCis3bYYcd2ir1iiuu2H333efMmWOtXbJkyTPPPHPggQdaa6+//vpd"
    "d911zpw5RHTTTTeFYbjbbrsVNQfNZvO666578sknp02bVqvVvPf77LNPb2/v/ffff9RRRxVU3bfccsuiRYvmzp171113MfN+++23"
    "5557rlu37pJLLjn44IOdc1ddddXy5csLrO+999577LFHgQnv/Z133nnPPfeISKVSGRwc3GmnnbbZZpsHHnhg9913X7BggXPu/PPP"
    "HxgYeOc73/nss89efvnlSqlCUz/++OMFQC+++OKDDz64u7vbObd48eL+/v5999232Wzeeuuty5cvL1ylcrl88sknV6vVAvcAsGzZ"
    "spUrVy5cuHD69OmFOCzQec011yilDjnkkEajoZS65557giDYa6+9eHRAuK0Fnc9Sdimw5RzSBjQHXMBGucXn//reT35m1uKH5i3o"
    "XBYAv3r//S76TfXgQ1psZkMUMCksCBO54LRUIJoFPbBn78CnbBvs+1vkns0rfYlkBIFuUMaBVyUAQwCBNQoiC9qCfrmVrVKqbXU1"
    "Go2Pf/zj999/f3GzTjnllDvvvLMwgM4///zzzjvvYx/7WKEvEPGMM87YZ599rrvuOmPMY4899v/+3/8Lw7Cvr+8zn/lM27w755xz"
    "Lr744oLzGhGTJHnqqafyPD/77LOvv/76Z555pkDYpz71qTAMS6VSqVT67Gc/u3z5cgA477zzfvCDH/T29s6cOfMHP/jB1KlTX/Wq"
    "V919990f+chHHn744SzLrrrqqjPOOKO/v78oSlVKrV+/fmBg4KKLLvr2t7/d19fXaDT6+vr+5V/+pfigp59++sILL3z961+vtf78"
    "5z//ox/9aN26dYODg3fdddfFF1988sknI+KnPvWpV73qVTfccEMURVdeeeVZZ50VhuEDDzzwoQ996Nlnn+3r6xORa6+9dsWKFW25"
    "BQCLFy/+wAc+MDQ0VDAwF3i699573/Wud5111lmPPvpoqVSK4/iqq6769re/XUi+Nr3kiIRTJktzBT6Iggw9R5FiiJieuPzy//7c"
    "53awqqNr2gNPPjzn4CMO/+xnunbaseFdhYz3Tm1Gk8H/fE1bmxFMKVWv13/729/29/e3Wq0kSf7rv/7rLW95y29/+9u99tpr9erV"
    "55577s9+9rNvfetbP//5z9/5zncCQLVaXbhw4Re/+MXly5dvt912WZbBCE/AZz/72RkzZiil7rrrrj333BNGOrq7u7s/8IEPBEFw"
    "/fXXv+c97zn88MMB4OGHHx4aGvrEJz5RGD3r1q0rnv40TQsjr636ASBJkkql8pnPfGbevHknnHDC8uXLC1emMLaOPvroY445Rmv9"
    "0EMPnXnmmQBw1113BUFQ2H/GmHK5XGjY9evXH3nkkZ///OcBYOnSpddff32lUgGAUql00EEHfeYzn/n85z8/e/bs4jkcGhqqVqtf"
    "//rXb7/99osvvnjXXXctBHbhqBZWBDNXKpXiUwowfetb3/ra1762ZMmSs8466z//8z9hhDi6uOHFmZVSI3BxPg6COufW5hUd5OyM"
    "CR/4r19c969n77hqsDOuLI/0zH32PfLrZ8av3L3uXAQEzqImRQQg8L9kFTZW+17MmzevUqn09PTMmzfvmWeeefrpp3feeWcA+PnP"
    "f37LLbd873vfu/fee++7776DDz54q622GhgY+OQnPzl//vxPfvKT69atK8xzZk6SZI899ujp6ent7b322muHhoZgpHO2aHgrrJyV"
    "K1cWcC9acbfffnsiKpfLl1xySWGcFX5xG8SFZC0svOIFTzzxxE033fTKV76y8D0Lk9x7v27dusLdKQy4RqNRIGBgYKCwH2AkEFPs"
    "favVKigli99/8IMffOMb3/iVr3xl5cqVixYtKvzQVatW1ev1MAxnzpz5ta99bc8991ywYEEhz4IgKCzIVquFiGmalsvlyy+//NJL"
    "L/XeP/XUU3ffffcpp5xy1FFHOeeKx7LA5bAVOyJ8nLAYFSWce1RB36q7fnfRPed8f0Zfo7tcebR/5bzXv+GY733Hzpvfl6YdYWSc"
    "4zyHoJx7H7+c1UQvUxyucN8OPvjg7bff/oEHHlixYsU3v/nN3t7ed73rXU8++eTVV1995ZVXdnd3p2n6gx/84Jxzzvn2t7/d2dk5"
    "NDS0yy67nH/++UcffXTbFe3q6nrHO94xbdo0ALjwwguLp79gHCtCMEqpnp6eSqUyXDXNvN122733ve8tLubXv/51sSs77LDDL37x"
    "i2Kfnn766be85S1ENH/+/FKpdMopp8yaNWvx4sXbbbddgeN2XarWure3d3BwsHBiOjs7t95660984hPd3d0rV66cMmXKrFmzAGCX"
    "XXa54oorCuGKiIsWLerq6hKRqVOn9vX1HXTQQXPmzHnDG95QfKmtt9566623PvbYYyuVSmdn56xZs+bMmVM4wsXnFi2b733vezs6"
    "OtatW3fmmWdeddVV3/rWtxYtWjR16tTvfOc7Z5xxxlFHHVUul+fMmTO6YhzapCdgU1DUAASbV4bqj5133h/+7Rtz+uuut7cVx7Nf"
    "tefrvnRGsmj7JuoYlWE2zjvvnTGoVQQCee5B2IQG8b7rb1jytpPiVes4aKcOASzmIegQmKbi+qGut39gz+99LS6VOLUQm/Vf+fd7"
    "fv271zx+WwA03pPeggWYbUlQmB3NZnPZsmV5nhce4vbbb6+1HhgYqNVq8+fPL95Sq9Xq9fqsWbNWr15dLpcLhdVoNIaGhmbMmAEA"
    "fX19xe/zPB8cHKxWqx0dHe14WOFFPvjgg1tvvXWlUmHmRqOxfv363t7eUqnUaDQGBweL7XTOLVu2rNlsRlFkrS1eXwiw1atXF3TH"
    "CxYs6OzsbDabBS9CAeh169Z572fOnNloNEqlUn9/f2HvB0EwY8aMadOmFV926dKl9XrdGNNsNrfaaqtp06ZZa5955pmurq5qtWqM"
    "aTQatVpt+vTpAPDMM8/09fUVIOvq6ipMiDbPbr1eX7JkSaH3iWjatGmtVmv+/PltL/WJJ57Yeuut+/r6Wq3WNttsIyJpmhbRnGHA"
    "Zd5Z4EgRrlzx1x/85In//GXXYC2aNm3ZsqemH3Lgsef9JJk3D31uHCnSzmdKh1bpJgiBdCJBlnoQDqK/f8BZa4sAabFbbanTZtMu"
    "HMDilYXBVAC08BNbrVYYhoV2aJ+kHV9tB2nbaINR8wWKLu72eIJC2w4HgUeY+UYzCrSDdu1xP0VMpz3wvYg7FDFe55wxppi00e7e"
    "LV6cpikiFq5MEV6mkThzYc4X96Qd122HNtonKe5J8VkFt8vo6yy+aaG7CypwRCyigEV6pnichgfIDEtmpVCAG42//OS8Jd/9EdUG"
    "uTr1hv7BQz/wwYNP/3B9xgx0Qh4UaQHQQQxICqQEIMyAwiYo0q0g4pWSv9eel+GszsjAnbZ1X8QzdTvZoNTobSt+U9zWcrncdj6K"
    "Xxa/b7+3baWNQU/7/xZWdjsnW0y5aIfiYBQ5ZDuiW4C+OG1hs7dTJu3Pasf5CsOuHZMrooDDNfHet5+fQji1E8Ttiy/ChIX4LC6g"
    "OEk7Ul1gqP36NpLaj0HxQcV52syqxTUQ0QghoTiFqp5kzz76WE8tsTqsKdzn5FP3P/1fZNutsoHBzo4wgyBVGFERZxdVUMQjgbAo"
    "JTDcACRIAvj3bMONFpnFvo5v1RlNbzhexD5nkWxICdB+10apT8b8dTSLwOiPa/9cxPTHnKH91zENde1fjr/a9geNjvGOv85RaW0a"
    "/x3bjnP7XcXvRze+tD+9eMHol7VfoEecVG80AkhYCgED7xozZs547b9+EUqRy/Kero7+wUGqVuNR87s3Y3TZ5JpcY1JbLCziRZyw"
    "aCSNKKFpVCsSho4dONtZ7dAFP/LkPZtcLx1wKMWc3UIxD9cJtkTyNAu0zi0zS0nrFzG2bHJNro0BjpBQIyooGsWFgbnTGGVzInRG"
    "t5zTLHpSvk2ul7ZGkUqPTIUfZlcWkjQjJADUWitjwPPG3U9EFMERuYibqXVH8xNOmoP/KIAbppDAYUwpYDRKogAkEMRQGJFAbYy8"
    "GFFAKM8EhE0EiMo7mpjmFRYCUQCCKMwFJcKkDP2HUKnPg4jhBv8JgAAnxdPkesmAm1yTaxJwk2sScJNrck0CbnJNAm5yTa5JwE2u"
    "ScBNrknATa7JNQm4yTUJuM1cOEz8gMAy0SFBk2sScC8WbuLFAkCGjksGwRW0LDBSWj1ZfTcJuC25ankLJAUQpxz0RC5vEg4Xy2+U"
    "lmJyTQLuJS2lQ+UEAKSZZesHDGhIsnZzRyHnin6QyX2aBNxLXgJElEVhiyUCKOcWVGhJpUkKAEEQFE3to3lQJtck4F6Sv2DTllUm"
    "IIqr5ZJRkc/DsGSMbjONTUJtEnBbTsCxVOJyudFYe9mld954w22LH7/9xz9Z/+gjojWKFN3wRQ/ppEqdBNxLV6dFOIQeufjSO979"
    "vm2mTX/DB97/9K9+c9lXv7asb13BHJumKSBMCrlJwG0ZxOkwyO++7xc//NnMT3xqu++es+M53znm179uDjVWfPEb6JwJgzAIfCux"
    "pGESc5OAe+mII6Xqjy4OFO1z2lsaUdyXZJVtt1m0zz4rlj49zPyNoIwxajIXMgm4LeEyCDNPn7IeYfnyZ8VoV4pAYFl/P0/rgeGB"
    "WIRaeXaTmzQJuC3gojrnZuy6aO+O3ts++OnKlVdX/vrXx/71O0uvuHanY48AbTxLK8sHBobSVmuyk+sfBHCy5VG2gZfKabW8x/6v"
    "Tpctf/LKP9buv/+Jq6+dOmVq7y6L8jRhAB2YsFKulks4mV79P7T08yNjcwcNyvPBrJgZCcVoKkQEREEQSFS46H1vrcVw+U1/oTVr"
    "eredfeLbTp263XbofcuxZTREnr0mNZnS/z8HOClwQQAgmJIA0mDxlxeO9QsIiACODHYvRg8W0xERgEE8CACBAYohbTnKEZzXlsRN"
    "CUrc23Pghz9w4NvfCWTAZ1AtMRIojAkEJCAqxt1N7tP/NcCJIACBKAQRysgDqYE2s2F79krBoTcWcCxICnFkriYSECEBCnov3qOA"
    "aGPQ9NKQF7AMzmur2QIC6hB0KFGlGDuMhY5HHDVlcxJt//dV6ib/tAmVKh6QQUgQUCF4ASAgI0QmQOU5U8qwRkBBQQBBAYUj4eDJ"
    "qNs/KuBegtPgwXsQQgQBRBIhAtAKkUiRWI0EQMOjZwoenUlZNgm4F++LehYPgB4BGbVoAVDIMszMJCMuxCTGJgH3fEGMzUOcADIA"
    "oBCAIgQUQPY5K3G5F4HMe0YvICggk1GPf6hF45zO4aG54mTY65yg+TaKagl9QccNKCAsIIDMkjvvc8eWQdB7LGatToLtH1PCKRQG"
    "SX3qxLmoo7vVCFtdWZ6TSBjHxVQ5AGhzp4+CGjpF3jotws6ZOFqdpxBPLZeUazNQI6FPQ9/Cjlmxt8hTulyga4l0TYq3f9iwCAsj"
    "5wi1Urw6UEFT5nVWX6k1jQwJaHOnj9G6LOJBNClNgEqBdR1x6c5pFfZNCMywzENUVmsUKpda/UPeuu1CmV2JpgGqIm43uf7RAIdK"
    "IWK5e8q+b36z7PtqlyXRtGkGsBgW2Obf30gtpAgDOGFwEGgNItvOm68+eTonCY5E7wABGURQlEjSAoZ4u21dZzcDqEm0/YOt4UAu"
    "e9dymQrDEJBAFZYYe0baYNDEGMAhgBXOAMAzsY+DEEXEORwZfTLW0EMpfAph369UVzFaZHL9AwKuSEI58ZaFkZwIA3TraPQYnvYo"
    "z9GAcyI5gkEq5juLcyDekRqjKQWBAD38//bOGAeBKAihwDfqxvsf1jUDFqNrslrb7OcC0xAImeJZQXOni1oozYA7ZqU6Zj203pfz"
    "tURAcvLG7zUFrLFU+8zqBAwSV6Ih2/yxfsFEYhmrdAFuL9j51DErNcWEMUBoAICNcdpSbaOMfa1UOF2URjLG6Af+/szHdSlSCRNq"
    "Ou64lTo19Q89AVBpwGDescwzAAAAAElFTkSuQmCC"
)


ICONS_B64 = {
    "user_g22": (
        "iVBORw0KGgoAAAANSUhEUgAAABYAAAAWCAYAAADEtGw7AAAC2klEQVR42sVUz0sbURCeedmYWOuPGKu9Sg8eIi14LZToxVtLDQmV"
        "omA1XT157PFlb/bqRbPudsFQIhujbUHQgyT0P2ghF4N4FX+waJOyuMlOD5u0UZM0tJTO7c1887153347AP8riAg550L1zDkXiAj/"
        "mvRPagAAQrNGRKSlpXh3f/89TkQhAABETJ+cnEqIeFHF1OvHZtMkEok7tt39GZE9uroyVQCAtjbvLJH9hbGLJ1NTU98rl90iZ/WI"
        "Y7GsCxHJNNsXBcE1YpqFoWg0LEajYdE0C0NOrn0RESkWy7rqcbD6QgRtZxKaKBYLO6I4eci55uVc84ri5GGxWNhBpIlabEsaBwJV"
        "ibCAyHqcXIf1Uz9kPQBYuI5tgTiXy1bAJPf2+t9r2nYoEnmeBgDQtO1QZ2fXY8M4f3kd22JwzhkAgKpuraVS+6QoqbyipPKp1D6p"
        "6tZaLaZlV9y0nKKknyJipJLT5+ZCn5pZ7beh67qr3lScc6bruqtZb1MfVydaX/84aFn0AADA7cbD6elnR/VwTT9e7RMVZXPK5RLe"
        "EGHA7cZKHUDTPuTK5dJbREzc7Kk7MRFhLAYIIHsHB++rHR13X1xeXuzZdkkDEL46qNJDxoSZrq7u8WKxsHF0dDwL8NqMxYAaal7V"
        "TVXT28nkLsny5ngjDWV5czyZ3CVVTW/X9t6amPOMIEmjpdVVfcbv9787OzsZXViYzMbjcbfP57NzuRw5P0QADcNgoihaKyvJYF9f"
        "f+b8/PzV/HxEq3Lc0jaTyQiKkjqWZX3DuUxva+xzpybL+oaipI4zmcy1Pc0cUs4QkfL502GPp31AEHCZc84CASg3Ig4EoMw5Z4KA"
        "yx5P+0A+fzqMiETk2JM52yzoHBiOICJYludAkiQ7HA7bjYjD4bAtSZJtWZ4DRATGcKSWSwAAkKRgGQDAsmivXP425vMxo5E/fy0i"
        "p+bzmYZh2GO2zQ5quf5Z/ADr3GnpKhquVQAAAABJRU5ErkJggg=="
    ),
    "user_r22": (
        "iVBORw0KGgoAAAANSUhEUgAAABYAAAAWCAYAAADEtGw7AAACZElEQVR42sVVPU/bUBQ913ZQxFIKPD+nsZ+TZqNDESNIBSa2LkgV"
        "SwfUH1GJperYvwDqQgdQpAoJsVN19lKpXUBtRD4KbpFQEATUxL4dsMGEJIQy9Eq2ZN1zj+875773gP8VDNA2YMTf24DBAN2b9F9y"
        "QKKTToUEsPfw8QPHaL1hwjwAEONjpWW8paMf9RjTqZ56dXMg5eAApz8T4el5yO8BIK3RK2Z8+UPnzyzfb0Qk3K8EBgBURp2lY+ny"
        "nnAKcW5POIVj6XJl1FlKYvsl1gCgaipvTzhbkWnpbSAdkW9VTeUlsf1qTNHrRCcMAcAM0IyTOmGIgJNecnb826dLMC1nNGPKF2qe"
        "gICAwBdqPqMZUwAtX8feUY596a4EVp5rptqtmWo3sPK8L92VXjJ0XUb7yFVN53mKtRcA0KSwaP+qbPYatX661jt1xYDGgH7nDcJX"
        "5gUAcCRVPmAUIuO+k18uteH4VimSS/wp1MsU0Wud8ISu8ggY35rM7x79Ln9or+k4FVEH5GUyg4emWpO6vhqAq40gXDhrYuysibFG"
        "EC4E4KrU9dVDU615mczgxU7v4Vcx0s0XauPUynFN2HPdsDVhz51aOfaF2kjW3oj4aCwLe7Fl5bk0kp0BAA9IxSbGpnlACgBKI9mZ"
        "lpXnsrAXkxw3tGVMGzXhHFSEWgeArxgb6NZxnKsItV4TzgFj+uY5fXk2CHe8LnPsCzV520jFq/CFmqzLHFeFO57k0qJtqUVWTmgA"
        "WkZ6h4AQF0+3CAkIW0Z6J2KauMaVnMfysJ0tSXe2eMvwtxteku5sedjO9nOz3Dv+AnwF5txBm6P6AAAAAElFTkSuQmCC"
    ),
    "chip_g22": (
        "iVBORw0KGgoAAAANSUhEUgAAABYAAAAWCAYAAADEtGw7AAADzUlEQVR42r1VTWhcVRT+vnvfTN68mWljA6lCIphFwD+kG7txMSAI"
        "/iEaHFQigk4SKmJREVyI4wiCCFUoQpjOpBUUqfnBgLpx4WSVRWuKiwqaRSgFU5IJSer8vDcz797j4k1KKJNaNz2be7j3nO/dc+53"
        "vgfcSRMRAkC5vPDQmTPzb3T9p4vFuScBoFRayE1Pzz6wP/ZmU702l5aWdDfp2VQqVY58+wGJUwAQizklrfn6/tjbBI5W0mw0mw0j"
        "IiTlKglfRNhutzYBmFtVrQ46yOfzSoRCQpMUEVGAkIz2ALEHteEGcD6fV5VKxcnnK06lUnGOHPF1oVCwAPsBhOXyYhqgB1C6viIZ"
        "JynVarWbm3e6qwKAA79YLJ7/3PNS75NEEATwPA8igiDw4boJWGvh+81vJyezr/bKv/H6iYT7RKPRuE6CANOum/ii3W59bYypiCBU"
        "ioG1hiTjStGxlo+kUqn3Go36R4BcAwDPSx7y/eCXXG7ssgMA1prjSulTJKGUgrVGlFIShp2fpqZeWiiXF48BHcTjfRKLxTA+/szv"
        "xeL5P8Kw8w6JT0gNay2U0rDW5ABc7tmKc+cqrrXbPmBfEcGf/f0Dl3y/ARFBOn0Y1erGi0rxiut6F2u19n0nTjx/5WYMZ4/8iUTi"
        "rUajtktShWHVTSbTqNWut7XWCALf+n49E4/3re/ubq9GTFEdktA6nC6VZv8REZtMpvt93/8qlxv72QEAY6wVkQGSgwBVRCULrR0A"
        "AgCW1NdE7vpbZMcqRekOEEg7DKgOCSsixhhrb8mKmZkFETEvA/xrYODopZ2dLVhrMTh4DzY317MispZIJH/z/fDuiYnnNnqyolSa"
        "zXle6nSzWa+J0CGFyWS6v16vZScns/Pl8g9j1oZaKS2xWNysrV1cHBp68JjrJi4EgV8ToSEl9LxUutmsvz0xkS07ABCGWDbGfglA"
        "M6oyZox5l1THS6W5rVarddV1Y21jQvp+4AwPP/yYMeZRpbQCMEvKdrelJgyx/F8D8k06fXi802lDaw1SQUQQARg4joN6vf7r1FT2"
        "8QMHRES4p1Krq6sMgmF18uRTrbNn5z+0lh93OnJ/LCanRTAUhnxBa7mglJo9dMi8OTIyolZWVrC+PiqZDJDJZAy7ZfcQoIoT3fr7"
        "12ZmFqT7Dt+VSnMrXX+rWJz9NIopxv6XugGA1kqLwOTzedVVOEaqB0PSAcDR0VG5beBMZu9PwqOel9SFQsGK4F6AbqFQsPF43yAA"
        "vUfyXub0Bs6YSOj5Y71e34x89Zm1Efk7nXDCGFneH3vH7F84LQThsFoXzQAAAABJRU5ErkJggg=="
    ),
    "chip_r22": (
        "iVBORw0KGgoAAAANSUhEUgAAABYAAAAWCAYAAADEtGw7AAADk0lEQVR42r2VQWicVRSFv/veP0nazqTRpJOGZP5QKC2IIKXFboQU"
        "CgUp7nQjdqN1J4JKwY0UXIlQBBEE7ULQlSAIKhUX1m66sVUXFbQVTDKZpsnENsnEZsz87x4XmdQiSeiqd/F4i3fPu/e8e86DhxkC"
        "A5gdHnu8MZy/BDA7lJ+sD40+DdCo5qcn9+aP3X/2/xG2wI4A7vGZRwjnAVLgTbNwDqAX+7iUeHH96ER8YOAfNioPzC3Jk8CCMR2M"
        "VYG15fMype26DtvQEQAZRANJBIEZyLAI5lvRcA/4LAQxkV2ETJCNsj8aeBADQNEcPFjB2ClQc/BgBQhR9BgImkHQzZ3IznYxt7xx"
        "qlp7d8DimQCsyOm3gHf3lRBIgpanz8aa9VOb5Wcbr1+2eGJZWkKYocouC2f+ln+SpItyFUvB2gmZ5D3LIkvwxKMxvjFTza8bzAL0"
        "B+tfUfpuZG7mWgbghKMRO4dEBBKmiCmp+LrWbHwxPzR+aE3QY6ZdFik3p36ZHMl/XXO9FuDtACQgYjjhNHBtUyr+HB/v27Gq1eT+"
        "fIn421AWf2rJcWAgBGaK4rnomixn8ce/WN23b25ucgsq8pNlwivL8kUgcFd9lRi4LdbWBCtyX0zpWJ9xsyldNynGEDsGlNT7YaOa"
        "LwPeb2FgBf9gZG76mwygSOaKGhSqGgRZcL/vdgM30+zd5kxjZ3Xc16fx3lLD1DFwoVQk83sV1xamLgAX7m/lVjWXyUs9RMohZHeJ"
        "N1J1nGoWaXSktjzbSSCz9vG98/Nzm1Jxq5qfLlt4f8lTCyzDsIoF3TaKanPq55t78mdditFMrU5Ko83pL2dH8kPJ5QW9vzf25AlU"
        "7A6xsiJ/de/89PkMoB24vEP+nswigIlSYbweTEfrw+MLq0WaLodsrYPsjnu2MjT2lBc8mUULOJ/LuB0wEp7agcvbCmR6T+3TwRBf"
        "aCNKGLbBKVAgejAWPX0/1qwf31LSAhMTmSC7wuHSdfb35s36qZb8rY6UllLnwLL825b7taXUObDqvthy/2i0WT8hDpeucLikrqQ3"
        "/GND1zIuFQbFEa52GvyRAIqgOhBrC40bMu7ItFZbaNwASyn4gq3rgiNc7RgUXQxt625d34yCJAhh3elMEIQSsm51ZT2wbR7bmF9n"
        "eLeFaOAucok+A++zUDVZtP9o39yENokEEEL66g5hHiA67xSs6+Yf9HInrr8+XEoP9d/8F04JzLFijD+WAAAAAElFTkSuQmCC"
    ),
    "clipboard_g22": (
        "iVBORw0KGgoAAAANSUhEUgAAABYAAAAWCAYAAADEtGw7AAADeElEQVR42qVVT2gcVRz+fr/5092QP27TSJWKe/Ai8aIXBU+DqBAo"
        "iLprIRpY0nUbSsXiWd4OeBE8KBSTTdIsEYpl1hbRmwdfDoLgQfCwNy1brF01tOmOMZvdnXk/D5uVJhnTEH/wYObNm2++973v9w3h"
        "gBIRqtVqXK/n5P75ycka5XI5Q0SCIxT9nzX7HiiluFwug4jM5cvBBEDzAGfjOGYAYCaxbbfZ63XeLRbzPwdBYNXrOfF9ModmValc"
        "9TKZ8W9brY1vRLAJAETgsbHjr4ThxuzZs7mVBzJWSrHvl2V+vvZkKuVWjTHZOI7SzDxijPkRoPYOsCVingWow8yh47i/b29vny+V"
        "8t8pJTxgznu+I7ZNV5h5PIqiFYBWRWQznR56JpVKPd8f6eeIrA5Aq8aYFRHTYabrQRC45TL+PUx7cOH7/o5Gkm23tz4+d+6MDwCL"
        "i9c+ZHbTYRgCAEZHj4EI3WIxdxMAFhaCNxzHutrppFNE1BURIiKx91sMPWYe1lrbjQbsQsG7laShUsJAmS0LD8VxLJ1Od5f19gET"
        "gUTIeJ4Xaa2hlOLdHp6kfD4fj46uPhKGaIogIqJ9JrAP8mi73bZ8348GE0EQWPl8Pr506bMnMpmJ+vDwMQ+wWsyA7GkVTkQkEACZ"
        "mprqDBiLCNXrOVFKpUZGxr6Oot7NdPr4TyJmVGR/A3KCxmSM9JaXvxxZWvritO/7RinhtbU1y/fJZLNPB5ZlP3b37p2XZmZe/ptZ"
        "nEMBExEz819A96lTpx7/ammp9o7v9zVfXr720dDQ0OmNjXsvXrxYaOy8EiftOkFjiUVMZmyMfmg2b31+8uSjnywuBiERd0+cePi9"
        "ZvO3Ny9cmP6+Wq2mCoXC9n8dkJ2sMVM+n4sBTFer1yWTGa+KCNbX//xgbu7MlUql4jQa2eigOODkuOx3kNbaKhRenQ7Dewut1san"
        "xeJr7wdBYJVKpehBsWcngwprre319XVHaw3P8+b6oVRxJiYmRGttNRqwtda4ceMOx7GRvU5OksIxxmx6nhcB2MWsVCr17ruNdlq6"
        "5TgWua5LicCDZCLCL+n00FuVSpBiJmsgS4JgDCByXfeFbrf3x9bWr+1BTuxhXAYgxFybAaTqOPZsFMUDgKQmEiJLiLhpWfL67Gyp"
        "d/v22wzgSL+ro5dSikWEDrteRKifdLvrHywynwry7RBHAAAAAElFTkSuQmCC"
    ),
    "clipboard_r22": (
        "iVBORw0KGgoAAAANSUhEUgAAABYAAAAWCAYAAADEtGw7AAADCUlEQVR42rWVz2scZRjHP8/7zrC7sGtsmm2abnZ2hRYt9mZBT1Yo"
        "9SIFQcFDVQTxIIIIPUsp9CJ40JPH4KFU2lv9A2pAUKQ/6MWDVpPZbthMlkYaU7O7M/M+PcwsTZpJmgp9YJh3hofv+zzf5/s8j7CL"
        "KQhgsuMWE8DJ9v9Pthz0f/t4Bc4mD8n9cfBwveaG3wmmneIMgMGoD73/NP1C+t07ChZQAbcZx7A9Rzd2qmh8bMp47yToPYUFhQVV"
        "7UwY85ZRXs/908dBx1xtjlR7B4OjJcdcAu0YrRiklqI3BTYARLFO5FWjOrQia76wPHD6WaN/92cFM75kC7CAWzrQvFURU1tXvWLQ"
        "KshHNTFVzeskCA9cOnDI9wj/VJCTA3XtQ/3aLPwejwvqbaYgv6G9jn4TrHTOA9ydbHxVMl6lzxCA5yiBx2h2eTEECKeb75WQH+5N"
        "jspTq4wUREALiiexRasK3iItr7kadouqfg7MG2CM8nwCasXqrsXLaMQJJG3ayTkwuvWxAG9Pzs78BM6IJFIgO7OLTAWW7PlcJQLu"
        "SpZm+md99vAR3/79ST14TRz37V50nCNKps07w3FR82bQa61WeXJDfxxBaM3wdpz6L3lisE+KWEFUJO7vf7HW3d88nYMawAq4lze4"
        "7CPNCN6ciaIHYsQv6uuiBjHi9N+hHRxrlEpXl6aCz3Mqkl49+HrCmNMRnDoahYsZgKTskYpUhX2NlfC3leng0iHf/7Zbb655YkbT"
        "1p4N0+T9IyudXxZarfILYTjY86wYcyyQEnXORNOBzlhvzgHLSXqh3e9cvA5+OwyT3QaUt8PU0ux9wko0f6ZXD9ac4Br9zpeacZ1c"
        "A/u0wCqZXj0Y+soJpD//KcB1XvGhqsq8XaTlKSE9MK5gLnvbaVA/RdYFEvh1S7rHuRE/+sqoCEXvl1RENJVC4Ed6lb+qIh90DgRl"
        "i1rdYUtk/pKUVU4O1EXd1YmN8ZzYFrGC9CwfqtO5EnwcqyA7d6d6glqhJ8q7x7kRa/Eae8aWDxp5mt2oBVk9BNGxRu/BIlNTAAAA"
        "AElFTkSuQmCC"
    ),
    "report_g22": (
        "iVBORw0KGgoAAAANSUhEUgAAABYAAAAWCAYAAADEtGw7AAADTUlEQVR42rVVPWxbVRQ+373P//lxlB9UFTIAQqpCK3VgYsEI1LWL"
        "s8HUZqlQVIkVPb+BDSnK0KW222YB6bmYjIAQiQplRAxYlWCgQ4sUXKdJg3/yfO/9GGJbTuqkEVKPdPWu7nn67jnn+865Iv/TfN9X"
        "J/kx/GMQBK5cvvtBIpF6s91u7pOilAJFRJwjAHGp1Hi61dq7v7S0+Jvvb3hBkDOjgL3+ZmGhAJFAnOOn6XTmUrvdskpB9/1KQUjS"
        "8zTi8fjWjRtf5a5dyz04DnyQTq22CRERUnYajfqvQGzK2smsiDfRbLYnRbyJVquT3d19Wkunx15JpZI/raysnQuCnPH9De/YiPtG"
        "Mi4icvXq5b1RKRaL4eTOznZVa+/i3Nzs/ZWVtXevX889yOdDXaks2uciHhQdQhEBSYQhNUn4vq9I4mAhDfDn7e1/zwNozMxMf1cs"
        "Vs9VKot2mNBjmQXAWk0IgEEQEAABUIQdz0t8ns2mftjbezaeyWReEzHfr61VpwuFAkniROCjFepHA+ATz/O+Afi31vrHen3r21gs"
        "8WoU7c8BYKFQwMgaH7ZNFYbhQJJhGOrFxXxVRKr9s1u3vn4HwCWRdPdE8obtOI0Oa99am9U6BmO6eCEwedA4xWLlQiKRnul0moel"
        "5GkBlMtkur/s7qJ7YoMcErcSRxKl0t3NZDI+BVAADF3sZGxsQp48+Scnwj2tn6dqJHnOiQJAY5Lnu932rDHdqW43GixjzFS9vvX6"
        "o0e/33POTVjrThdxT8uidftDY5Lzxlgh3SBkrRUTiWQ0P79QthZmOJsXApNEsVj5jLSzJLsiotBzOEejtRrvdHBPa2mfGlgE6qAZ"
        "5I3jFLG6uppYXl7ev3kzfN+5U5aCJH3fV2fPvv1lPB5/K4r2qbWGiLSstR8tLeUfnjlTMb7vK6VGhDt6VgAiwiAIHCCRCP8C8Idz"
        "9k9AnnmeNSJgPp93QRA4a2lOJTdSIhGFUml9/MqVyx8f9d++vZEsldbH79xZ16XSurU2GiNpTxj077FHXHZ6euZio1F/Wi5X9dFE"
        "rW30viIkJR6PSSwWkyiyozuvViuw91J80Wo110W4b61RvbPB83R0TzrVbDbx+DEfHoyBwMnLtP8AHGeo6+kewD4AAAAASUVORK5C"
        "YII="
    ),
    "report_r22": (
        "iVBORw0KGgoAAAANSUhEUgAAABYAAAAWCAYAAADEtGw7AAADAklEQVR42rWVPW9cRRiFnzNz98PB9q4TvF7zsauIKFaKIKWgogAj"
        "UOiR0sE/4Ccg44KOv0CbgsKiTBBSIiCUiAZFDkWylrP+WJyYOM56d2fmpfB1tLG9toXElUZ37r2vzrznvOfown+8DNxJ37ODzQK4"
        "RUirtcbHk06XnsXYkzlnyACEyZTSlHPnNpPuqdP64w5k8xCOA9ZQB14Q27XGrVmXXW+nEAV+uDiBTTuvHYsbOwPNX3zSuj8K/CWd"
        "u/khRtpeS4Pfi3FsqjzIqoU4Nvk8FCuFODb5IhSrmzH+WZGfeS2zX5bPN6/MQ7gzxPyIFC87NxVNML21vHMcxce1RmUjxaUCujZb"
        "0L3l883355607n8P/gbEIx0PiWMC2f7yBloAlz8L45xhv65p76pgq17gdrvevHID4vBAR05WYIAJbDG/C8zE3hjum+lU+mk7xYlJ"
        "599OyX5cnXjjAmCWS5qd1V0GTpDM9GXR6bMeqexND1fiYGpc7tNeoVATbOVd22nAzg47p9NaApYO3nXqF9/D0vXg4+BYV4yQIwji"
        "8DockphCVSCZ6URX5H4VwHrtzXdL8q8/HyoM+T4LMTFT+c22dgc6KXmHEpMM1MbfHZefktkr1BJQKWasbuzOe9mO8+50YMspCmwl"
        "pKvd0qD3tFsM1aGabaBbDlNvba201meaH0TsdOBceANwXp+EWGoUSondoSGOgRVRf61+6TtTLyi5s0lhuR8fo68SNi0YGOa0n0yL"
        "EDJpoh/7Pxc9XYfOJoVyKeisvDPKMQ+gdBl6azONj84khYYC0a41bpbhchczjyTshUmf1zdWHgFhAZwMHdPwUR+bobQf3wTWT/BQ"
        "6EGCv4SexX4h5HFPi5CSc4Ez2U3Wd0idC3MT05vLXxw5uNksd9zcxHZY952sHoN1xxOKI4E/zJ0gXHXWZdfadJ9u1BqeV3ga613D"
        "fJeBrwBdCoiyxB7F45P3dQ6c4Nsd4g9mqRecczEa7uD35JFF5XUmhyw6c/+Yafvv8Uf5jBL/5/UvkEFdfMxJ3n8AAAAASUVORK5C"
        "YII="
    ),
    "user_r40": (
        "iVBORw0KGgoAAAANSUhEUgAAACgAAAAoCAYAAACM/rhtAAAFAklEQVR42u2YT2xUVRTGf+fcN51Spm34MzMUOq+11IRAdI2GACYk"
        "RDcuSMTE4BIW4AZdaiDBhI3KgnRRlxoTxZUsFDa0GqLsSAQ2iAidSum0tJla2tKZd4+LeVMnFUqZtgSJN3mTSea+73z3/P3mwv/r"
        "OV+yXEAGWoNnAv6ZOOEZcDG5fxE+A26p+MFSyb0FEcBYW1dYLs12AgSJhlsydHNg/p6nGmIDFfAD6fa9q9V9UDLbriIpAG82mRC5"
        "dN9Hn4Qjg+ere+uxo/V6TsDn07kTzerOKexpFE01ITQhNIqmFPY0qzuXT+dOCPh6wy11eM4JRHcy4cF16nrv+ShqFHEz3i55oQ9A"
        "jdcaVbbPmEXr1Ll7Pjq0sTDwefXdFSNoIAJ2a33YlhB+C4RGgAg7vLGQ763deyeTO+SQHoCyMVMyXuwcHRiqYqxUiB1AQm1/s+rq"
        "pKgrGac3FvK9fRBY/PRBsLGQ7y0Zp5Oirll1dUJtfy3GShGsnnyHCDZt0QOP7zFwuyu9ryxQ3g1m4Dy+Z9qiByIYsGMexgoSNNYq"
        "SNmk2BQ1FuK8qq1SLxA1RY2FsklRQTDWPg2CEn+OebBArHXKzWSsErZaLDVwU24mE4i1ejCEsXryXuus+otmyCpxSUUPC0T9INUc"
        "7K8UQqTo4VXikmYIcLEegs98FT9ffXD+DM6ncydSqh9WgGRusJcBi5006f3HuZH8R/XO5Gd+Fi9ZalW/j7V1hYX17TsL69t3jrV1"
        "hQ/b81zqwSUpaqu8r7BLYHIeVsrgR4ubtj1Vrx2LG/GTVP6xOqVd3W0GYGxNV6slo1e98UoZ6/beMgCqUgiQGyr8Ig/cz2vHbxbn"
        "v7vsBONwioD/I9vRmcLeM5P9TtjUgMz9CBWlYMAsRmT8KWLfTCKnXxi+fSvOV1ts2HWx5I7H5IbS4ZGU2eUkejQQNiUQShhFH82O"
        "R350PPKjRR/NljASCIGwKYkeTZldHkqHRwT88cpYlGXxYBVIwIYyuS9a1R0oek+TKFPeD6vyXeTl/IwvXQtKOgJQTvh0oya2ObW9"
        "3vNmk2p2yjytqhR99GVbIf9uLW7dBP+pUmwoE37Vqvr2hPc+AG/waSTBZ23DNwsLYQxluzLOykcF3i+Dtqhq0fuv2woD78T266/y"
        "aqXmM7memQ2dNpwJS6PZ8O5gJtxT3RMraWeVypb4UQPXV/O3djAT7hnNhneHM2FpZkOn5TO5nlobT+zBasXl13e83uLk+2nzZRWm"
        "/jK/Y3Nh8IpBgoqCtkVEIRAo/Z5pf6lZ9KI3mlaJBhORvZEbvf3DQtWtCxD31+lOqvpTs2aWFAmmIzu4uTB45SpbGwRKiwmNVCq2"
        "dJWtDZsLg1emIzuYFAlmzUzVn7pOdzJW44tvedXQ3EmH+4rZThvPdlg+HZ6NPRIsYfIEAPl0eHY822HFbKfdSYf7am0uyoMjsWc8"
        "HACsBCYiJ+NwLWVsmYGIyMlSBcdiG3M2H5uDVcV7uzVc4xq40aK6tuj9tfaRgZefpME+ruEPpsNfW1W3TXg/Fs3S3VEcGH+Y2tZH"
        "kU4k6HJCi0Ckwk8Cvn8Z1El/fG0SY0ZOaEkk6HqUw/QhAApgypa0uiAl6gy7AbCbXUsWGlUMw26kRF1aXWDKllrbC16/zeWfj8bu"
        "oxeozNOrAN9W5NOSVhUjMq5OeH+hamuhPPxvXgFXk7nmSndZT7fS+E9t/Q001H1MBH805QAAAABJRU5ErkJggg=="
    ),
    "chip_r40": (
        "iVBORw0KGgoAAAANSUhEUgAAACgAAAAoCAYAAACM/rhtAAAF70lEQVR42t1Zz29jVxk957vv2XF+TKaJnUDiODMV01QVqGSmVOpi"
        "SFgh1H+APWoRq7KqxKYFISHxL1BVSKgSEmxYVaqQYFI0dNMO6QIx7aQMmcTDTJ351fy0n989LN57juNk3LGRs+hdWce+9557v3O+"
        "+91roM8mwP4AuH6wgTcB7Pz8pFivLeiHHAFtTs4sRAyHubX+j16xXuazXsMKALeLlUs5F1wbd7i2Uay8DAD/nS6/2B2b/QEBqcdw"
        "90TwCmAEJPMLeXI4B8JMSwQkz2e7YTR3ORlliQMjuJyGJ7agWk92QybsAYAnu2PAfj8atH46Ud4x0RN9OgalJ8JOheBpNuvLxTrS"
        "jwKMUFeMEvtJNb0SNAJCqjECEBUR8E0lGnsc5okGAd1AdTAuTnNY9PdyuRAaLhFAM5n8a5uT5xZovPg4LAIUwr7+4VNPjz+DtXov"
        "O8nOPHcFsOXjydQAxBvF8uVR596uS097qCmQrZ6gEfBqHy3FkLiYebK25/VauXbrjwJCJN+1pzEuA55tODtPiG6rqU5VNs/QZncl"
        "jJEJhYyi2gY8AdtDItyGfOOgbtPnH60//LLTqnXUZcDN4vziU44XtqEaIKZqNxHeYnzTgNk9ee+Bzx5KVwUYBemQZ2sGHd0BD+jb"
        "IfitkJbzOf/TjenK+9nYmY3GwNKDWDfaj8XUbfDVyflnA6drQ7RCHTomEgKoS9FZWvjA+9+Ua7d+3IvYq6XK6xPOfn3Px1GeFp6w"
        "a8iDOJDfb8a8OHtv/boAaxULMgyFZMERKIjHCMYA6smCQCL/VyAYA1gpVooFp4ltUlSy6yI1JrFGt3P/zuTtbXwkQCNKoxUACDtm"
        "yOQSgoXIMNSqZlJhk7X11ZvF+ZcnnF7a8d636ZMABLII4JWs4/eA5tZEebZOfSTZtJdiZJEVuA3aKPxurrR1+YUaVjeS3IgAtF3v"
        "3yFwM/VOZgiNmtmjGB+c31pfTUPsg5RBoqOt9XcBvHtiiHBpWFOfv8LkxwSA/UCTObjpCEKedMNMstaBhD3Jj4GjdTVnAKxaapqQ"
        "tAPjr87fWf9XzyZZn5x7YdzZM7vwtVgyByqGzIEe3HrOwCM2d+aakfdxnmYNaa0hXU2neD4Pe74OyMyiDqkoF/sfVktzVwmZQB9D"
        "dKQfgZUexf5T3tv4MOMUdJjkfZKFEIYcjyfCA6HZXhqnmtMIyQj+yszdjVcBYKM097MR4+JeYmemNqYRiLyP82ZvnGQSghhy3K9O"
        "zl9kPybpniapw8XQdwkfwkSLgzNJB03uS4D0nc2pyptJgtbyniQSzFRhad4OQNsZtEkyhpTMwdyuvM/DFs+QiwBwQGFfisbAsOH9"
        "YZRO2ySi247lG2fpchGE/fRbAhilhR4CHe6fukmSRS0F/7y7crtUOveiCdMH9GodQIRG5PiQzS/OfV5YFZaC2/i3BmwSJZuW2GGf"
        "WGkCAGr/+fjLD7o1bKKyY+kx3ctJwvYQ3yqVvz9u7qVtqWUSShQpAlMAfpID0YA+FvAnSa69qPRpHzviI4OomMBynvxuLCGSfg/y"
        "BiUTD00yRtojH39QqW2+1yoWeiu35h4M0c5GEs6YtVaelVXWVh12YrsS4vS+EDM3NXNnrfbEJmlzskvurSsAllodbqDqLmAtqoqv"
        "GvVWQI7f93EEgAYGIQkvIJJvCoDrwAAogIV5qL4T4/Xy1trWp/hG/gJm40Na2ZwrYpZ20UPpna3qk4ny7HhgP3LkzwOAu96/I+Nv"
        "zWspZ/ZGAOAETJH0u33pl/O1jc96eQKxHu4GEhAu3N+sRrT3ADAHwoTrc3dv/QXAnwHgMRjr0vWE3HO5Xt5ner3V+TcBo/xYS2vE"
        "kABHaLQbBqCQvO2U/EDvxb8A/GGZjiz1xDp6/h7DSB65DH1lXhaCfjqJFkuSkhX6tMyPlWaXbthAd/BK6nrnm7P57FGIGAYAk7pj"
        "QGHgBJez0szbJ3VprwHBe64IIE3Xu2Hy8d/SfKeBaiIrqDcnZxZuFucX+8G+Uo/o/w/JU/kb4n+iMsbWlRAdvwAAAABJRU5ErkJg"
        "gg=="
    ),
    "clipboard_r40": (
        "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"
    ),
    "report_r40": (
        "iVBORw0KGgoAAAANSUhEUgAAACgAAAAoCAYAAACM/rhtAAAEnElEQVR42u2ZP2xbVRTGv+++5z91kzahOE2bxC2KKGWjtAN/BoiQ"
        "EBsDAxMLooixKsxQRpCKxMBAkWBhYKkQbEVIbiVAAjUUJFCHUmjt2EpjJXXiuHHt987H4Jimle08O3FZeiVLT3r33fu755zv3HuP"
        "iU2aAAeAzceeGwmEGFRTE+x/HcPvNjAB5R+amNzj+1NLIZcIUWBXS7b6+F4Qp9wwS7mfWpDswwttAd9rulVzo9NTnl//pU6O07NA"
        "0Kbe1jpmCOeNOMdiOvMxS7kTWcAXEPYKyQ6TeATCQnrqxd3OO3dTFqRIP8lo3pKAFRkEBKPO+TdD+2iilHs7C/jP9wjpd3tpzjVq"
        "kOKgV5Ndqom/RxGMpDiJVwjGy2b1Uc+dLKQzaEH2Ykl/E1tQIIdIlI1fTZRyH0YVRnEs85IHJgyKL5mF/UL6EScEoJ1ZwD+IA/41"
        "XA/a9RsGWAF0ZWh8dCeacdIwlECNrJpppA9IP3K6IG0GCISDeKQDYEv51714IMGGHFGHfjTgizj5zYpZo1dIhwG2EIABo5ML+W9X"
        "pdeSZGzljrtPzwDBecDrlisHCrie/G4DwNRC7ssV2csJorp8RzinZ4DgVLMrt+TifuiqJlE4WkhPfQ/Sg1CpSnWfHF4ya+zx3Mli"
        "OuN+KOXeUYdEPhBAA+XDdnlwjDvsSdG90HJXVUIgwQGxJTNLOJ54Kj39CUtX/xLgCNjAANnM0Q7L15eL6akP6PRmQ/LKJm3Y7hwI"
        "QkqRTNQk8yzw71sMEjACmijl350PVh9NJXEoqOOxsI5DYR2Hqmv1w8FtTNPx7C7nAMi67e8Di0EBjouLFSwutn1fTGRqUXZON0CN"
        "mADe+7sIxNafI83t92kd705aeC7CFxf++7QCiIAK23FY6GKdsM3kkVq2xzn7ALwQ5scyx1PAE2vADUpO7BzklCjShun2rSr4bmJh"
        "7uuBAFLyAKCYzjyTdu5MXUCi44nyntyzHuxxem/Nj2Wmxxdyfw8iBgUAATRfNiskyIkaol04DMAOEHXTH4oFy70c/3s6zQDAgVL+"
        "6pX9+58easQfv8VQUARGQiaPigWzk8Xi4l2nuO2OQeFojMXZPIB8PwK7CMSOAY0BimQ2yI9l3txJPrlmdsMA57pYw5pRYMPO7auY"
        "zk2Vcmfvh0g+rQvY7bzIwesAJB2OPxBJJJEQMjLcaP84jKk6fx0tFcsPRNJOJAbQAbbDub0V2W+fL+TPnFqvUGz09vkeKwvbLhID"
        "sNd5eGPvwUu8ce3nVpViw16MgQBGEYkAxACUTQXPuXn1X7brz8VZwM+UXv+nsP+z9iIhlJLHaqxxebJYzF/E0VgFs8renVL8bJe6"
        "UF+AbF6Ebs0AAfA+UEQkkRzDbDsxBAAwJ9zm1gEpAlqV4KhXC2OZw62VC3KdF0Tr4tqW25+tSptasiugM4slncebsCBFdyRJHtmu"
        "K8EtCTXJknReQ50X2xbwVPP6yEIQv1yJ1eeH6Y1XZcGaDNsQ9y0rY4TOXzb7M4l4oZOguN0l4GhwzXF2OXu4nLDLmbm5pdZ8972I"
        "vpVKbySpb/FviEgJopvl/gXFqIVJQp813AAAAABJRU5ErkJggg=="
    ),
    "keyboard_r40": (
        "iVBORw0KGgoAAAANSUhEUgAAACgAAAAoCAYAAACM/rhtAAAD+0lEQVR42u1YTW8bVRQ9571nJyltQ+qvJPaYtEVQUVQhtbSLIpEd"
        "LGCFukRiwaZ/AAQLCgKEWLFnAWIJQixYI6UgBSFBWlGJIpVQiOPJpzExbR3HM/Mui/EEJ02cuHZSKvlIlqzj5/G5n+9eAz300MOD"
        "DXb4ebcg7ZykAHq/PSWAFkDtKO5+uK+VBhO9uQQoAvb39NHMIO27AjnnCbQVUXucY2KobBy4WrbeeyzN3ZCGlnUnRapnD+eGTL/6"
        "Lqn0yVURmH1yYSBAnMQta+d9yvnhxcKfAEjARh7UBHy3T72aVPpkyfprApTFYoWkBgARCdatJhRAdo0DD4KSTigz8lcQvEbg4kRY"
        "B6HAy1H8KU/WIRaggcUL2VLhKjdVmISWdYWLQlk4kstqo37xIHGBnACA8UaI1cZ8oE9ABRAR6NsEpJDJnS2l8i81qpsEZCbhnOkG"
        "F7WXA+i/JYK6AkjQb9aktup7BJUysjaTco7HRU0mtPlyLuW8DQAL6eypPs3vO+XcdP6t6Derfs381zSErQSuowagj5QwFBJ9U7yG"
        "2d3iAIhQbduotxEotr8uB4aXCjc9Bs+UEVyYX06/PwEYZ8m95gX2fKfcwlLqg4mmNtcS0UE3nf/0zvCYFNOOV0yMPS5b9Oq94GYG"
        "80PFVH75zvCYuCnnm6iAWoY4aqKC0zEB1HzGebGQyZ0NuWdNN7jZTPYcAdHWV22GuFnklDefcl5O0nwdEzU5m86eIr713WTulU45"
        "I3qymBx9rDCoqtxGi8L/HGYXl7fi8uxnxYxTtpTF/KJ77RKgcqXiJ8WMs9wJJ7RLTmnuRvHQaEL6lW27SJqTNcJPYU4aaTKuHW4i"
        "5LjbIjHtuvwMprxucNHMSSCY6STEl0NLrDt0LN8X81+vEytWUKcIpdHIdyy0xllFxOOCh9c88yH/vln4YheD8Y4Cx3GawBQY8z9O"
        "aPNcxdpwDGtnFGuc9QEMaoV5+McBPH9hF09RrXYDAdRvj1aUAMpaXKlaCw+CtXt8eRBUrYW1uBLm2BOqKccl8ncLD4qx4R1JIYWA"
        "xfT0GgCgVHhzNpX9fEDF+qvw7qllDCCGsvVqTsn9OWSu1wGgrIytITAWEEDMXQLH103gdAwkgUAYfOWmnAU0jUUC3q7ZwBKaqp1N"
        "DIAFWEMghFZuyjnYPB+u0ksQfEiDBPlHc+5vHPmP5Ebjhj8eVnqkLkCMG9OoW13dbsolvxHnVbFVX+HpkYXCr9HIz83TrZt45MSA"
        "lo984ClPoGXvlzsxgMSI6/8geOPokvvDXUvTViN5eejYoDrkq0pl76+zPCiszKxE2+U7DXHbXm1yH+7oxlqgdv3Xhuzz3s42i66H"
        "Hnp4UPAvCAqYpwB15VcAAAAASUVORK5CYII="
    ),
    "monitor_r40": (
        "iVBORw0KGgoAAAANSUhEUgAAACgAAAAoCAYAAACM/rhtAAADTElEQVR42u2YwW4cRRCGv6qeXQc7ztoE2xjwGuWWnPII5oLgAbiD"
        "uHCDG4JLwgmeAQkJIcSBvACIA3kBXoBIWBs7kYntCJLY3vVO989hZp1l4zFr4TGR2JJao5me7vnr7+rqvwYmNrH/1mz0gYpnDtjt"
        "cwKxBtwurtFAlS/qGMDnbTcKcp5lUGAGure8PD2lxttEv3hIJNUM2kEByNx7v4f+T9fu398dYDkCOGBua+nKgin/seXhek86NzoF"
        "NA32Uur0Unjz1Z31OxQg04DOYKBI/uFLHq7vprynE0KhDogPUzy85GEVizdL9gwgowxQAJNWuigBYT+lTwRbIAOrBW0AYrHQ02b2"
        "+aGUGVoeIrYAOBSSuRmOSBn+9dJ2Z+ucltjuLbRvunMJLB/uy6rSTox68WfYWQDfhlQHsFmwx6A7F1+enz76tuwkgEeWzOMbkAvc"
        "agI42K2d0MxP2OXPt00ATgBOAE4A1mxZtZKVlSrHatSJJmBDyaq4qmQw80bfinMnltc6WjLQXmOmPxaDqfBIAL0YL3da7Ych5R49"
        "S/XQl0zmUn4wZ83jJVP2d/ljuQszyD3EHwhEyAjjFTeGlSsikhhHUPrRWJlmpKdn/q1hPbg9mCzFb7ohvN/ycAFxwU4RebngQMX8"
        "U240TzFYQBJkBtH0FcA7o/LqBvhnkO4uvPbWrIcPukkz6Rj5U1EZSrAczK4CRLFuaH3Q98/sm5pGf5/0bfvB5nfDNcmZVXUbS6tr"
        "O0urerL0ujYWVz79NxKschdbwUQom4/ZGiqKMx+47KJZ9F1rnmKeoLI2OjEP2qBMqPbQR5ZNgEzYCP+CFzTyrpUxo1pOkjI20kgu"
        "yw2U3I9UsczK3PlL/7i8dyYnScVu0NZi+0qe5X/GvSy1gL3YD3loRKU4h/ng6zOdVnu+EZtZPxzmAC2AKebnHtz9bVjun/rfTNWy"
        "GqTNxfYXM/DRnng0OtZMGdhseXsg0R0tc6aN1oF069ftjffWCjbTWQC0sorW5uJK5xXP2k/QM8lbehq8TuHRaK5rYOykvP8o7l++"
        "urv7eBwWszHzqAOS+bt/KH7cTbiQVzk8cGgk16VpN3PZlyW42qrF59dOkdMq2/eMdbRP7P9jfwE7r5fe5qHWswAAAABJRU5ErkJg"
        "gg=="
    ),
    "touchpad_r40": (
        "iVBORw0KGgoAAAANSUhEUgAAACgAAAAoCAYAAACM/rhtAAAEFElEQVR42u2YzWtcVRjGf+85N5m0TWPbNDNT0kymEq1rQRdumnRR"
        "oehOu1DBhcuuNSgUcaEiLgQ3/gFCC3Xj1oU0RQU3LkRwYaKSzkyxGayGpklm5p7zdDGTUtP5uK0pdDEPXLgcznvPc9+Pc573wBBD"
        "DNEXNmiCwMEpB1eBU3u6+Fdc1TkID/2BNrlHC4Gpj6OSfoYGce1o6VnvbKGBxuMekUpA3mjEqB+sXvn+nmgqS4jv/tH1/MznOXPn"
        "RzEsSz48AGLn2Yrx4vZ+e6u8utoEZLtIJt3CahBqU6XFovPn/4qhPbDHofXAlkTB+9dubKX/Gpy/3B4OPT3YCatqx47tJyQrY7h8"
        "C21EtBjMlk2Y7P4wPFBVCvOGojjm0KcJLt8khpDqydLNau19cB+0ndu7KKqT5ZPV/Exro1hWJV+69KgK5Hqh9OFGoax6YVaVQul0"
        "h4PPVCQ77vWweQWSafBPQbo31OaSJVZCFI1Bie2ybDULkNYg2B49MB0WIJU0cP1Hvs/1jZCZHmuCWTAkOCQ4JPgwBJ2i3yUe/DR4"
        "ZXiuQDJoDtTa7/fsg6buXLqeJCm5dWO7rX9MzY5W2EO9sBIAarC1c5C0sI3MBJNk+yXDrCmBrFQplE5HyTuzviSddDDKEhz/JPQ+"
        "F53ko1lAPNPqaI9Ri/PAj7s14d2T8AokC5DWCjPvTpr/6O8Yg8B7ILHBStCAkY5ubCGyiNsgkbZtwxHn/E2F96ZvVD7e4dLdg+Jw"
        "rk1IdMjtyyBVW4hbikGIMXM+i822QSoBaBQDcbhniOchCGx5Indhbb2x6cwujJipIf3cQF+b5GQW79d37XGDEwm8meDYjnGpYbaU"
        "wWZ+zOyUIFlT+Oz2RO6C1nA9831HD/45NVus5meam8WyalOlL7Kk/bXCiefrhVndLpRVmSotZrGpTpXevt3Rg9eKx5/rpgddt2Zp"
        "LE0mAYuA0HimRsg0tpMXZoxm3OQO3a2IkBzp1t3tzkEZ6DezygHZejPqUIKdqRydPevEH01hI7tC5hR9NBdiCCfkXKc4lK9Olk/6"
        "GJLgfPrfYlI7wb2Oe/HGJoothEzLBlKvKr7Hg94gVPMznxRd8s6NGGKCuRYxHajuOuERRFDs0UkCxgiWtJDyzttaSC8er1devwz+"
        "XL+maSfEgC0zN3Iw3/xywtyrkXar1w9NiQ0pAuwzc/sGbE1BMGKwHuM3pvFX8vVfN7u1ndanaRdAvTDzsuTORHQgdLexCHLo6XHz"
        "LxhwK8ZfovGT6+5CGTAK2yn2XXFt9dLuNbPezZjaEzK1matPlA7ncvo2wU0ExRcL9crvD3L90WudLJdHHrClPnPm2x9KL4Mfn5tL"
        "zq6sNATJIJulzv6b1Qn/+xKo2/tjhUE3VUMM0QV3AFEO5Sot2WryAAAAAElFTkSuQmCC"
    ),
    "speaker_r40": (
        "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"
    ),
    "mic_r40": (
        "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"
    ),
    "camera_r40": (
        "iVBORw0KGgoAAAANSUhEUgAAACgAAAAoCAYAAACM/rhtAAAGbUlEQVR42u1YW2icxxX+vjOzu5IsyRdppVqXtRocg40JhJIUQrGt"
        "kpDSPpQ+xDTBDZQ+hD6klEJKSQu2oRAobQxuS6ABF5JSjCm0lN5ffGlampc+OKlNHdeuVysrkeRIsq67+898fdj941+yZMux24fU"
        "B352Yc6c882Zb845M8B9+YgL72ayGvPdqTXG9zV+AgHdj2BWDgJ2CNBEd+ljZvhOArSG5fbkAHhgMUZ8tzhZfvcQwMNA/J8AFOAI"
        "hErP4Ml+y+27rgi/wlIioJOG0Vg/NTA+MpzO+a8DTB2N9JQObKa9PqNQJViIUJLVM9ALqm6kK0wpfmlwvPyzDwOStyD/TWOnANsH"
        "xJHOgU2+YOc92W2ELYX4RfN2looGAKLFmMSHWpwdj0JMpMmkGncOXq9MpzZWc7uuwyTAbqdTKQ6+OtM7pKneIY0US6+spTdSLL0y"
        "1Tukmd4hVYqDr97O7gnA3TKCBwFrEtmmiwMP1KN31XTLJItkpNPOPPHLuiQCc1H6LJ1dqytajhYBIP2vELuM/J2A9hzJmvAFBZ5P"
        "baV+O0gdn7x8+TmgLsCYiTCzkSMQy90De9qd+1FdejABnKAVW01HIAFASQ0+kQ4Q2DT3wT41x0k6ABLgAYXlEaIcEPPglevSt4cm"
        "yr/IgmRmWzXaNbQj7+LfC7S2CCHPmymqDEvIxsQGMDXY37RuICKEuMqclZIICM1lzYWwtzRZOXMCcPuB4NMdJJCMuvCVDnNtUzHU"
        "Jfx5gSw3F7EqeSU5E5YiOAfKE2xvRnYuinUHtIFqAxiyJE8lAjRAkLpJPtFJK5jxeQBnnmrq+ObpTNfXGxoLNiS5L/dPXSqvh9jD"
        "PaWnBT4egCEBLkeW87DTVc3/vHd8Yu72B/MTubHixBgMeUZ0ZZfiV+gGAhQgY9hwEvBFwCYypN0H4B1sdztwsVruGXi6jXakjdbb"
        "yH0N1sRGonomUesPRoulF/snyj+8gO2FB3ExZOt2B8BZQKMdY52AFwEui/YqAD9gSCTjcIMey05VgxsXq+Vi6fkttKNzEKoSFhoH"
        "4hKgCGGozaxQF9q7nB0d6RkcHBy/+M2UV9l8S0BXzEe3LB1mE/4dSOqgUiw9tsF4dE6xngNQlY61Ij48Nd6+u298ZLfkH6oK33eE"
        "pmOsbTH3QqVYemo/ELRKrruV+DtR/keTFwSOEECBzC0gvtg/PvLSMsXJyxcAvHC1WDqbN742HyUSL49u3fpbjI0tppFbj0+7gxps"
        "h4FY6d72sCMeAaBF6Y3+90ZeEuBPAC4tkQLsbezK902UX69GHc+TbCMHFPzjTWDr9rtuxVOprsVPttLoQAbgtSYo7L/RmIpAnMC5"
        "2Miv+mkCyYMC+FjD2l7ec4D7sDdN1H0OQBWCzC6koFbppiOB6JG/tKgYjCCgvsZiT+OeA8yUptkIyANwMdl8ELBTq3dFFMCg+kYP"
        "mgQRnL1Tf3cA8LQaTQPfrkN0ICR+7jAQi9i1ip1djoDqps9soFkAKOitzF3lnkcwAsCMWt5YjHG8BsUCeeBfXQOP7Ma52knAK/MR"
        "52rvbO4bbAW/viTFecWa1dzvs7buKUA2SqDbee2fs6C+105aAPxG5341Whx4chhImPnGej/+6Kac/6OALe1GC9BP+qb/faXZVce7"
        "zoOEmEkbBIBDgE4Cvn+8cmSsp/REl7kn34+hz9P9YayndCYAf6WUiHwUCp+OpG8nMRPiWW+1bzWTtHSDsxSA8zGxzjWg+DVyHpJE"
        "1eYJzdZGpTezC535z/vZ2rFW8pkagBZwT4Hc02hYG6e8AGIhxj/NutqBHe++N7+GK4zOalEtaSag1gQowARED5IFPHBlY2l6U0xs"
        "2vyyLWFHZMdEPY7mF5/rstY3nfDVKrB9XlEEYQA9UFmEjk0uxR/nfXtS6evrCvPL7biYWDAfa3luK1AtUYjNG+vqAA34SwF89jpU"
        "hfhrl8fCLPzNxbNqWMiLm9GKIEwHaANBAmSaFKvCBhDPbirY14gaVfdy+Zs30AFwUKugXIE0kX/LFIbI7C3u6tatLQz+Nz3mhxck"
        "uHXke9dsr+orUrXnjbHbFd0goIXEtRDeCkvJcP/s1ffTg8mVrU95YKC1pea+QehTdcHffCdZ3xVWTQfrmKYcIBrfXFjSy9tmylNr"
        "NhO6y8ekeyErMXCtFyt8iHeUuxT7yL+E3Zf78n8p/wEwYv2KTvOqEQAAAABJRU5ErkJggg=="
    ),
    "ram_r40": (
        "iVBORw0KGgoAAAANSUhEUgAAACgAAAAoCAYAAACM/rhtAAAE9ElEQVR42u2YzW+cVxXGf+fcOzPOjD2O7XGSOvEQgisEihCVKkBC"
        "FWJRsek2FQvEoks2Fd10R8Su/AV0gRQhJARlwaoLVBBsQKgq6gIJRCSs4I7TFtd2bTMfHr/3PixmnE6mmThGsbPAZ/nc5x0993zf"
        "gTM7szM7sxM1Gwf0AOyUBWni4U3wJ+0xjWn4lLduQHij2ayv7ZyusOYs/GVt7T/PwsGnBA5Va+3i8hersl8kWCpE4vTCrWh4ydjq"
        "Zb20tPHeHwEzyBHgD+DfhGJd9sqCh+vv58SsO36K2biTMzMWFnqkmwbPH4Y6jvG8LWUg7eb0DtAR+ITE1cNS5Xgci0Jf7UplkI9+"
        "Oy4QN1xStqL07cvbq2un4b3brFSqi/33orEIlkfP4sRyt1QD+NvM0sLstExmAqhLtppz98sffth+A8KLkG7Pr9QvVdrl3SHHJNvs"
        "lNKXdta273FWVipPd+L0OrsccmSmK3fvblZnOtMQhx6WPYJAC9H1cavRfGE22K29JDRMio7hT8Fea+Hqty5v3rm93lh+7lw4+GU7"
        "lcpoEBYzaFaM1mLze1c21n71/sWLF/JO/3cbdnAZxXQoY9bMW4tXfvCnjdbrXz/XDA9S4hOapfXLRR/nmZp7I6PGefdG1b2RYH7G"
        "/TNu+pyBFP36tPlTCRbq7o3zQ/508IZMzw68FS9NuV1PaK7m1pgL3nCsMWU+D/a1FyFpzHNHh1gyiV5PUoC0rfS2wXwZe7ormTwf"
        "DFN5v4dUgrSn9FegG+ArPSm46AJkD0U351TCvJO11iavmtlzfRTAOg/LTz9i7BhgU+YxpNLLWbo14x4yOBpUpSETWM08euY1L+L3"
        "K+ZxeG6HlwVUd7cEv1GqfBcIBuYTPHekB4d1LoPUUS4U8m9dHrdyPjhn5tgg34TJIe0qF9n5CV7krtiveIh5rOy2ck4RvqPYv2HQ"
        "F8SM6X8SKDMhKlPmYcoUprCKbDCH6mb0UhGHtyhPu4cDCGWoGNBDVM3ZsjR1+Gt1C0GDNlZ1o7ovqJqzTaoeW6Ag93N5uoze3Mnp"
        "Gz1l7w3vGc3s39LWvsV3Bb6e7PebpDcLONdVvpcb25kE+dc3wWPR/ddeqN2qwNX9wSAwQFEyKf9crFTW6esYHlSupVC6+NE/3wWe"
        "f2iX3bzzD+CFh1F+uLm5B5svTWzU8yv1migeReC9W6Sc51pLSwshpZBCSOMVnkLI2nPNzmRrp+SHjfy+LmCm1I7ZZrKFB3Dqku2a"
        "qWj364TDgr2fE8cSryRRGCaF4i0rYs6KmYwMHBtuPyJ5AVbG2303cBhsP4zyECmUwfbdMTcbfnvI2zPMgFKZLGO6EIVQeaJAmVo1"
        "D3EnZQI2awwy2g26EoXESWEHiLo77Zzvji4XNrrmr85dq1dj8aNgdiOh84OZpLcN2mDPuDGXQI8bM/TnknnX4YPOQXp1eat1d9L6"
        "bwDrF5o/bV+6qtaF5YMPLjSvAbQWl392Utj63LXmI02SdyAKAjBSFLkmcGx0DXq8mFmqCVxQGn+03Sdwbzg5RpdLmWWDPNbEHyuW"
        "P8HSeFif+CvuKJskUHlwkzw6l08aO1LgxtC9kj5bxqxsXpZ5HjbeE8OwyQtDnCD79YS+0M/5rcuzldUBph8n9PmTwD7+qHbn5uBx"
        "lh859n9fWJh5Etix/n4YLfnTwI4r0p4Edmb/d/Zfp2cO6oPguVkAAAAASUVORK5CYII="
    ),
    "gpu_r40": (
        "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"
        "RK5CYII="
    ),
    "usb_r40": (
        "iVBORw0KGgoAAAANSUhEUgAAACgAAAAoCAYAAACM/rhtAAAGBElEQVR42sVYXWyb1Rl+nvccx25dN01tp2nz40K3rjCGJhZQmTRB"
        "L1h2MU1I3HRDSENIg6FpSJPYdkenMYlt0iR2McTGxe7WFU2o4mZcpaNsq7T1Ak0UWkqJnThp/khCEieOv/O+u/hssKq2SWM3+STL"
        "9vd955z3PO9znuc9B2jTZQCbfku7+vXtCo6Alfr69i6tSpIzpYnGvVb7ljYEJwSsmO8/lFyT/+0TXBzt7j1KwAxw2xpgPa38uFBI"
        "dRCnkuQBIzMJyF8+6bqzE4C90OIYrSLoCAS/Yq900t23bIaqGdJ0Bys++jMBPRGPwS0P0OLgopHcwI/3Ur6/YBpgNgnY1SXTkHXy"
        "aDHf/3MCUSuLZlMNT9WRK+X7hnYJf/epaQ2AGCgwdgCQedVamvJiKd83RCCc2iQfeasS0pgYgVDO9/875/zRGQ0QAALCYNC4DXLi"
        "MBOic73Tow/WEQ9tl5nrycVwPWAze7liWhAgEYCkwnbVG60KsVwxrZnZywDw+iZTvCEEP+4s7OmCEZ3A5UWvg3NXFhrPPurq6rwz"
        "k5Hyqn0jSTmdArFo+tL+FH4zskC7Y6E4f1tWcUPDyt39z+VSuLyUxKXKKi59MRE+HM8PPBa/87XEobm5BZZKcypuoTFjBSosleYO"
        "Lows2O2SmTOfocujHZCsgDmD5dJO8koMxs92mQHeAIrqZ3ShmYt5O+gJaDNdhuP3pfHdBg5yeQ2mBgsGoGrmCVuMEV4iACVgo/yc"
        "p0Za7CS77Bo+GYCo/ldvxPFb82LaDgEF8QpUAIQxRyAYvm3v4bzHOquzyat3JKv8mRf5OhVXZqC/5fToRzcLUjagMZcUUAESu+mS"
        "86qhg/jh1e7Cr8/gF3IPsLaO5xIADQ95VuV0zvkXPPhI2snTu4mzY12H+gHgRpZ4wwCP1VPRO1V6cTXC3QQfrJj+NU06I1M7yZ9+"
        "uXvgX+XcwH0EAu36ilDnmY3lRr65V+SRCQ21JQvz0yFUusTvR6L2LAF7+FYDbJp+yM+OXOyZKp7rmSodX0H4rsAmAwxC3p8S/LO8"
        "b+CpYFbFddL0IeAZ0zJtcSbEgKsELJhFhPW2bHUWdyrDgN8/OXZyQfwDNbM3O0BEZCoJvuaJ19ZMa8Im9/lC2R0Gqld6DhaSxFMr"
        "ZqYAPHgERNqRnsbTAPDwpjkYo6gE9BgQDQP+0MSVUvdU6TsVs5+IYUUAOMiXGrJhZjFqly9Xx/MDT+xW+68jh4RwHaTzJFJgbVLD"
        "SwemS3+r15Rh005yA16BgI7lC19N0l5NUh74VMNazrmOmaDPO6m+kkDyjx7yvVUo0hBUVM9FsOd3ivjlUBvvmxm/tJ7MsBWVHwZ8"
        "A9W7ugd+78lnAGBN7U0F7tjj5CsVM9CgavjV6HTul4M4X7umGteWvXgdNBMEasWe/sFOk/8smukOUhRAEkTV9GKk+oMDM2NvN1so"
        "AFsvuLbsSQCoARTjvoZbRAYkAKwh/Gk27Lj/wMzY23VrI4FQ/+hGOm95V3cG4DHAxoJmxHl4mHlgvGr4Uc/U6BvN1fe27Ooa8mDO"
        "TVZhyFB8BfZqz1TxDcPdHQ3Utm3b2cRG1tGCAIy5ltdW98ZtCTDmoLmmckuwQY7d9gDP1zfuQWz+84KVFQL2HqZb7t+3ihyB2jvZ"
        "bCZp8rgCtgpDB3D0nWw2c8/shcVWj0A2PcNGeTSZL/QcdumzachzkRlXzJgUefSwS5+dzBd6blZKtW3TdJMzGR3r7v97VtzQnCoM"
        "VotnzcQeEcyqvtU3VfrWRhyjrQg2BixnC0cEHFpSU4FdgJN74eRewi7E9zBUzhaOMBZz2coUEwCCsOBJ20lKBJ7snSh+0DtR/CAC"
        "T+4kxZMWhIVWsuU3n2HAqRUjGiuAetjx8v7C6wDggh6vmGkEE6coNrfZNg5+ogqYrca9MrVXBLMa3uqbGt16DgLAibrMRMonF1Xf"
        "zYpDRlwqIy6VFYdF1Xcj5ZMG8EQLUsY26KC9n81mcj79bDA8VD80/MdMtPyHu2ZnF9t1FNyWw/NbebYlCF4TiGvyX0Fc820fclt1"
        "/R9BTLzdsMrcpQAAAABJRU5ErkJggg=="
    ),
    "power_r40": (
        "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"
    ),
    "body_r40": (
        "iVBORw0KGgoAAAANSUhEUgAAACgAAAAoCAYAAACM/rhtAAADf0lEQVR42u2YO28cVRiGn/fM7MXGuUCyGwfZJjEgoIQGCQoHivQU"
        "aVFKJASiQVQkfwEkKLmVUPALUJzUUcoAguCA7d3ESwJySOzdnZnzUmRtViYYb+wYE+1bjubMPPOe73yXgaGGGmpTaSs3zUJ6gpkd"
        "euUFYIbzXOAEFAI/vA4aJHCzNvl6hTC9Ksetur7ZY6sE5cRrR1rHP4ULRQ/knk6mm22rIG8cmXp7XMmHK5iKtSOuWHBIKY363JMT"
        "Ld4zJEAxEGCfxS+u2MWyiywlVMM2GQ1k0Z1CpMDLfZe5L0CbDoHExpnjaUsLJaNMgwW3jCys3GNK9EUqDipq9d/WpVt59ppp1aL6"
        "zeFff2xsz8GZtFG7mml9s7cPuK7bdA4YrgMBiPdxIN0c++EglLYcKAMBpgqFoPDdT48Dxp4E/iUpFckA68Jez4NDwCHgEHAn00xw"
        "TGYhvQxhdsA0cwk0C+4U3XSU8vYADToPqcHNvu6lG/j9Fci3VUluX7/RGJnyXxWQ5DIkhuxeHU36DynfQBugKXfvLhOp+LhRn1pe"
        "qwqDgEVQADfsCvBINEjKdbeLKbbkoNfdmkmW6j+dKqybtiYyGYH2hfDadoPWgmVHZxjMoaXa5MkY/Nj40v6v4dtsY2+oDYBBEOfr"
        "E59NhNLpG45kto2L3n7kOxH41poxCmUp1JSwGLOPJlsLbxkS9TmqPrgEiM3DU8+PJLq0andHpHJFQg/ohBpYtcnsTJB38/j05G+L"
        "zV4HFf+2xQIvKJ4JpC6J8mr0lyvyd7KDpbijcHYiqQBeKksnR1ApT3hX8I770p8AvoLkVM+9UtBFgyJujLfmj2mTAN4JXTkyXd8X"
        "8zmk0YjvlPL47KE+F9ON7pWUhjJw08UH50FLtdrYyuho/iDgqu12Mr40d2OxPvn5owpvRjR2q+fibC/ktBaUjcNTL5SCLkqEjuP3"
        "E62F53arWjSOHh1N8tLVEFQr7Dvdws88cXOhaQhp38l6vyKFth0xsVGf/ASURPCDqodxLVnnzjPcSY3HFMaWQzwDvLE+blw7MHW8"
        "XNVcxyaCq5JGpV0b+QXcjqaLHUBViU7b00eX56+mZyFQ7bTasXyuEsKrHTu2bbUdI7sqJYDLklZjPBeq3dbZZYLWZgVDcuvxY0/9"
        "0flvu5d9Fdjf/PlKb/YRe13aUIf3CrH/93+9hnpo9Cf0H45NzawNHgAAAABJRU5ErkJggg=="
    ),
    "gauge_r40": (
        "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"
    ),
    "windows_r20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAACj0lEQVR42u1UPW8TQRSc93bvHGM7sZXYOCE2ECSokSMkGj7+ANT0"
        "iJKKPqLLD6BHghJ+AhISHRJWqiRCcrBi2Q4RIU4cOb7z7e6j8JmcSdp0jLTa29335nQzs0eIIQBhPM6BABfXMC6GECC4DJAARIDs"
        "F4vZtLpSGYjjCEIA4AFQ1httHjR/PAbsfrGy4ljSUdzsgaRA7PaH8vP6casnAOk6ahqoR4ZmXrJgzTocM1gTIA4QX7n8rfLy/R3n"
        "tSzMtggNtJAVgC1gIqKc57v3AF4AUDqhU7kv8jmbpmc88vWRDiwABCFvEXMuFYW+eCowglVKuV4h8rVNmehk6NYFuDbh0UlhnSDI"
        "t1q9pCbtUtUAJEIkBNhwLvXrdqPRn0jVLlZPk4bwP27y2M2Henr77HkmCOKzWjzLFMfUQuJ4AI9cYtudMZOzSsXrlXimZO3ZJ4vI"
        "SUGpp+1SZbeLt7qNKghwBVbLh9aGhpXNEBVk6LY7part4it1UTVZoqW+w4dzseksLi4UjHfnN5MHgHSsiycI5me9DTQa0V55ueaJ"
        "ypi42QCYZ2UOwlGzetjuCEB6IuggkznJ98ImrOVJMQCErOx8oxER4PbE36Uo9M2UTFZUyvZisUV/Q81bRT3K9sNXotVrEhwDmLxI"
        "MsT5vfLNezsOLSemG2o1UBDrACaQcUQ5sfQOwHMBdNLNq31xn7Iz0zkchm7LMXKpyPjw1MAI7lJKEjmUdfqfwziH6M8pftIuVZqT"
        "HAJweeLlI5HAsLJpogKGsjnJYQdVkwMt9UU+/iWsoW4AQJF+A4cv7Niz8e9LAxgqOY3S2Lix2xp1FyoPWNGsteNmBRImMqzU95jP"
        "4tIg41ujLhqJmgvP1xJe/AF/PW1bWxvceAAAAABJRU5ErkJggg=="
    ),
    "info_r20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAACW0lEQVR42q2Vv0tbURTHP+e9l0SxkATNTQm+94QKgkuhYIvQUsGp"
        "UykU6b/QoXQXiq4dS4cOgnOJQulUdHIoSItjFhOKpIkBf4AGBGmTvNMhNxofts3gnR7n3vO955zv934f/GUVwVXw4nEFrwgugy4F"
        "iSecpMPMSTrMXHOhxPMlDiagAHUTzqbQ1woP2pAG8KAp8O0X8m78sLodzwFw+sEAlsA7zocrI8KmgtMiWowimY8imW8RLSo4I8Lm"
        "cT5cWbIj6a9U+gIOIMcm+Ooht35r9DR/VPtx3VgOcv6dpDif2+jZ2OHPh10IootK1c6sZvzVIxOUi0wnAUpMJ/fCcKhhgo2GCTb2"
        "wnCoZPeKTCePTFCuGX+1H+PiozE6PtMwgVayBR9gBxIKUmYyVc8FpXouKJWZTCnIDiQAKtmC3zCBNkbHZy6wetKoG3993/hrPWlc"
        "R1psTB7AvvHX6sZf78UcgXZ3hjKrKkUF2bokyuleFrypm2CpP7ZlZ68qRZBZy3bbATgNw7TAsEpnV0DnIOpCPhYAUZ0Q1UcWSADm"
        "LAk2Z/g0DHvSGmRJU+FskJMOQKZabSqci7pTtmXnquDVlVhsCxwFsTnnmWq1Cd2g19WPbovogm05XmGHvtdgW0ZARXQBdFtAFTyv"
        "d9Dp6Ftc53slW/DlpFG7agx6GyuVHpsC7Uq24AvyXDrR/cutfwqbpIK7Pxbcq+Um7iq4/xP2jT89iZvDMriv8uEHF160lC8tOp+I"
        "nN0uhdFUAvdZQnjSgY/vD6ovl6FjK9OB7atl7SsxgH3duMFy07+AP5WYGWfVNte4AAAAAElFTkSuQmCC"
    ),
    "chip_r20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAADd0lEQVR42r1Uz2tcZRQ9937fe5M3SSbNrxknM3lpNZUSSFBTl0rd"
        "KLjqQqRr250K/sA/wJVQFVzoQsWNCEoRl7oQQdDuDBYt/iIldjqTlziTZJLMj5d577vXRWZKMA240Qt3d8/h3nO+7wD/QxEARIXC"
        "cK0QXr4GmKgwd6FyX/lxBWytEF7Wcjk4OnsMfLQUIAL0zkSpnPXsnZh703DeVQWKnZx/cXI/idtwi+Fm9aYCTIAcxfO9VlSAOCNx"
        "V91OkiSeEiIo4rOrq0mssk2iRk/A8oBg0OhvWIqibQJjrtHYEEUPQIcAIRAajhr9zegf2OMnA8CfU2FxhPFOlvnZbSdfE+E8FL4S"
        "vj/F/FRP5Muuo1dLW7d/O9EAm/pjiZckWd9PuzF9mIEudIDPAB1m0L5AFUAOoHYW9GSsYrIBPd1OEuP3rJ/a3m5xc7NtD3kzl4Ys"
        "vdcTv9OKBZNsx+vOvRbWq281x8JxkzF+G4DrxK7UihqVfPnnSbZfNGO5BXgYspRtIfM8gI/unlwrFqeSxPN820tJ/U9U9Uaz666O"
        "B7YuQBtQN0JmbFfTJRY8ysSvtEzviZwE7EzsSlHUAAB7ePLchVHFM03WfRGrI0QLLeC7YMjznEon7dESgZot3/3OZEYAaQVERRH/"
        "ZYHDmPq5qDD3eXHz9rcWANQ5cYaLUJ0hIjGAOTQOACFt7h789RA229V8mAAAE4khGFJ9UBTsFKpO5K4pCtAKlu15rCQAUMvPfqXA"
        "T2TSN4fFr7dF6yAkU2xm6unBIwA/TMQvleqVJQD4AcveMlZSAtQCwEYhfO4ctt6tadgFVMfZTDRc+k0YRY2N/P1LhtwwADTdQVxu"
        "rN9Ymy6dmWJeXM+HWwrQGG0FGwhfwGbl0JRKuRxkUz7Tdc4T5jSj9LYPGm2rvE/KFpAWiFRURokozYIuJsDZA9ZLrGICNmnHylpY"
        "rXbv+bDXJufO5Qw+8Ike21P3CxQPKJFPipujzIupyo97ihdP1yvXT0wYBbjfBgCuLcCv5md3/phHpjY9+3ptOvz0UN9w+9dC4XRf"
        "ezvADfywgzwgQI/8a641Z0YB1dxe/pRjMirIKEDrUB1Rm+uTyL9KGwJEiYKAzLgzxkExA0KA+Xl/iHhCiY4RnUg4ENWm6U4MvXI9"
        "inaY6GNheQOrqy6GXpn1cKs/q/953P8NDC+phrdOfzkAAAAASUVORK5CYII="
    ),
    "ram_r20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAACnUlEQVR42s1Uz2tUZxQ95/vem2cmQSPm5UfNPKS6VxAXCkVx4yZb"
        "6SYW6aorzbL/QikSN120m6wEFRH3ihBFS6FLVzKmTSeTxASSyUziZN68d08X8SVT6y9ESu/qcr6Pc79zv3Mv8H8PFol68k8kEj4X"
        "WS9HULA/i+OB8SgqwTk1zT66wH4A1a1SzvW5jV3JC3Fypt/xzrZUMigsqhHMBDkA7vVlE2iAgj2Z7A6QtmX47ovV+bs7B9KpFGib"
        "5/ksVTMMo24jS4PBgIOZobMBv1UmVab1EdafZlwvBWm2mvrokFO548IZyM4B2CEEmXdNK42XA3OH482ptqUHx4i1weUj00tjfxz/"
        "UrokmW+aPT68Uru/PFyZgpVGjgbcXO3gJ5VUI5nv9tAo78BOHG+eCp374ZXymyXnv18eqT6yzF/JqNNGNQBeWBwdfV6Wm25Jt7vE"
        "RRda1ZNtgzyK3hQflct8U7bcZnq1YbZSOGIbuLMt/QJBItU02+oaptrQs8A5rx7LFJJFKWSOtcizLJWqZUe1u76l0Ob6EVzN5fgK"
        "di/tht2I6NDh+QFSaxmW6BSBaO0+rTaUXFmIK7/9y+1vm4CeuA14AKjFya2FOLm+50OyVXY4UR9OZigdENmA0CcgIrEhaD/BDQD9"
        "FEJR6wIGBbbqUDQATmwK1wDACXDlzN/NhBv7yMtG1ARMgkpAWR95GUBdwCSgcaOsj+5bAHUPfQ3wmBE/5nn+czEyHgDqQ5Wv6sNJ"
        "9bXRf10aSib+isePLcSVP9+FLQ4nj2tx5ZveNrhiDkkXAxgRzgYg4pyWeHGM78Og2AnjwtngdyAsCEVAObIXAp4SsxmEB3BYQx7O"
        "A3jyLkzgQ4AvidnsJGD/zT4koDfX2Yewf+zCzx1/A7+wVPgn9R0MAAAAAElFTkSuQmCC"
    ),
    "gpu_r20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAACnklEQVR42tWUTWhcVRiGn/fcezOTxLQWk0nHODMiUkQpWKS4qwgi"
        "InTRhaCLQqmIO/FnVYvYtdK9C8GVGxdCqcQKgq66ELeCFarMdBKdTNsgRKeZmfu9LjJJ+oPZiKDf6juL857D+wf/izHIoH9y/31I"
        "/8pDMqg93zw4k/jU8OgILMhtD0F/bB2ZlVQYQoBxBkjgDEWOft0sObl0o/1jLnBXOmHF48MynS5S5GWwHpmXKujpMOMRvkz4Zsq0"
        "L0qFpPUyPNx05DNZlnL8EYnXgHdyAOE0DDqN6+1lgN5C8+Qs6dzAHgml+0jHB4o3lnrXLgJ0Fx96eV9Kh3MX2lBcHgQ/ZBMOd4hM"
        "aNqQdedbp5P0SVhv19c6jx1c6xwK8cFUSl91a83nDJmsp0rUCkUrwoczXIkJTr7LJqWgXEk+MzBvNfvtC91a4+Nk9eZ77bPdWuOI"
        "zLuCr7vB9ym5KJ0y2WsojqZ7AHEA2J4zXDFoxXolcAc4G9ZPGRwDUNLzSEcTViiWBSHfBWirmKxfVNH5b+HIs/3OLMDVA4/sr2j8"
        "3ticB1ha67x6u1VWFhoXDd4BNFjyGKDg1ptJ08tP1lo/r8IFOSpVlSdG6JsH++0PJ77UOeAJyF+CcXdLjF3AZE0hC2Cx398AjvUW"
        "W6dy8yJJo2Hw+mK//fmdngfDWBCrAFJlSwqgM//wM9MpLpVwo8QJZJv17V/bTEncP1GvvCMZEFW0sBlxqn792mc7sbp6oN6s50Xj"
        "Jlg4lXZ2u2KWYoSiIObCKQfIkKuZtUn0673ud9vRS6u1xvEZtPG7uVXskdMqmnug3770d7kXWL+0WtXiT385Ix0aYBvf0xqaEJxB"
        "WSZeqP/WuTIJxbafrd39P9Cde9bXXRzsBYQmdtlr/gI1pC8Weh9V1AAAAABJRU5ErkJggg=="
    ),
    "disk_r20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAB4UlEQVR42tWUv24TQRDGf9/e2U4cCEpIDsWyT0IgeANaCqBClIBo"
        "EI+AeIm8AAUSDZRAR0OJgJ6WBiyZ2FHABOKIOLbl3aG4s2USSAxSJFhptKOd2dnvmz8L/80y0EuIDeLRfpDs8dWRAZOBBGbgPiXp"
        "LYnFYZjusnNQCm67U7YnpxuNnoFiwAF+fTl9OCtd7Zk1kUVZFg4G401eslOF3XDD4NpP1maSbjYWa1f+lOKHpcq5VlLb3UrTBYB4"
        "oig7zqloGeII8IcxBsJa5IqYdkaH44DKHJRTtSkoZz6G8uDjVyasmDI1KNd/JyOfghT2ws4RmgOFaXPncgZ9KccxZgrry7Xbx6Po"
        "Ucf7z5IGGCBk7O/YvM2U6wZoXqpsh3Cn2l57nOUwKr34HgZfBA8MeytZBAqjYMM82U7yg2CDonODIeZcsNiws13c6pzTayYBNJN0"
        "05tdiI2bJi1V2x/v/YpqK6k9EwozUtQN1vyq3uoiM+/7x+LqmXq9Ez+F6DqElvFmXu55V5YCc62kdn6i6iO+pZMuulSSA4m+Daky"
        "e7lr9u5bfaFr4Maj11pZKZd88a6XlYfBgsGJ/YVQCGLLgQ9AZCoUHfTVv1/Z2GgfySehyeplE3LxL8K88jp8EP6R9QPj0tAsuSGv"
        "wgAAAABJRU5ErkJggg=="
    ),
    "battery_r20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAACGElEQVR42uWUzUpVYRSGn/fb397HH1TMPIKlYSjkIBrYsEGC0AVE"
        "d9CgW+hWugVpGtKkhKCRswZBBqUntfKYP/hzzj7fWg22J/sjMGjUGq214Hu/9b7rB/47U9fxytc537vAf82eH+iPFQrwt/Wpsbo0"
        "+sXbEq4oWQnIPVSfylFVTY68AC58XH8tSA7qVipAjdErN2rBl8wJJbQFuFMAmcSxA7jnQvGUkfUH5UduLw4Ha3f3V1dtDjoCj4C7"
        "mO+4N1umhV5xNUrWyrQB8cisnB4A9j1tW4+aWUrBssz2WmE2oqftovCbUHYph4q4J0OfekIazQLPCrGcUjnXV7Q7YM9jYJkQ7k02"
        "GjvjG5vNyUZjJ1rYBlojzYM7x/Wpha361NgZoLuAYCkUAeUB5XIVJydZIVTlnMJBzEwXlWauIIbN9TjJnhjpwRngqZWVPjhgwOFP"
        "sYA33S4iD4BQ7lIO1ABiRVmO41EyB3cgIOsNmZklc5AkA3xmaMgAD7llneR74A+jq525LX8DlCsKG9zZHng1MXI0myvYrg43F7fW"
        "j+5fvHQtyyMWO00AVlY6AO1qfML47bVHWiT9sCkfRidu1aSlDnxO0HYQ7oVQcHFyqnNURQ0H60M9x+7viOX8+OZ4CStJYOoO5Vr9"
        "8vUhhckDULVRck+4Mj/VuYoBMuT9EbdjXg7vvd/9frD/yep1QcNfHAf77XH4v+wr42L6IhgPMWoAAAAASUVORK5CYII="
    ),
    "wifi_r20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAACBElEQVR42q1UTWtTQRQ9ZyaJCQmEFOclmrw8aVFoiwj+BQVXLhVc"
        "deVaBEFcFXeuuhaXFhQKdVP/gIh7N0WpSEzz8YyJUqkEDe/NdZFUn/GliZKzGZj7MXfuufcAcwaPM8rQzoifABAOz9khgN4C9DF2"
        "JYCWmIIS444ELIEQADrG5JLMLX63tkItTCh8TPT5nl/rB9HHj/wnfvmT491QkJsBcF4ACtAfRWc0SUV5Zy0fv+jWH12PJPuVcFS6"
        "ahv3UoZqA0B+ADwNrd1BMnhz2vc/E0At7+V1OjyXFnVFkWtKRP8g77U69e0dILwPWIwqYMeYXMdxd3uO92ALK6lZet1zvNs9p/q2"
        "XSqZSGG/UfO89F8EFIvZdslb9ovu6pfCYn7cPk4eYxhMEAiaTvXyCeFdS7kQAgoANCCa3BtY2TjV3X+GISFBNF7FJAvbxl3Lks9J"
        "2QutvaagV7+pwfIA4VUr8jJNbrZM9Q6BQMYmJW6Q0VgoVxony2cn+e0vVMp+0TsT27dpA340jx1jctG7SVBxl+ujTfjgecmmcZ+A"
        "mQaZabSMu7mLFS2AXp8QyynfVy3HvaWpX1GEgYQXy93mw//a5z/GyXilmvFKs/iqaUrTLCy5KYqfovjNwpKL0SJMiktMIQUHNjjs"
        "Q14DQNYGhzIPvRzJlZpFQ/9VhDkXWZcpfYviJ/0GvGyvp35hAAAAAElFTkSuQmCC"
    ),
    "warning_r20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAACkklEQVR42q2VMWgUURCGv3l7XhIDGjW7R+LuOw2pzkKsIyLY2whp"
        "LIUUSkBQKyEqioWNEGy00MY0SZdGQTE2YqEg6IkgwZjNbqJJFESi3HG7Y3G3eolJLoLTLPu/2Zl//vczC/8QCtIqJ9eigBFIY9cO"
        "AMhS+CzDNvrGtGgoACrcE9EHZUr5CZDNmJpN2DkCSVywp1C+GeXFLvf7xUFInoKzKYMNtJL5np52TbbNaSInUkfDnFKuIn37lmYX"
        "LwNXNhl9VUw1tI294Ebs2qkMj9xgLHKDsWyCLTFUMJeBoV19vuRq72qkB42YoiPoCpVye9r2QTED/tLH1xNgBiFpZQ0HYM61k7Fn"
        "7wJEnh2PveAJQOz612I3eL4RS7PeRcy6wWERPdKZT89fAoMQofJdQXp3tl9VYV/kBccFkrVFVxWcaDwduCOpjHRF0dcrkJKq09BH"
        "ZXq6YpALKKNTkJtYY3jTzG4QkjnPDolIbu9yOFoulfINqRXUAJRLpXzvYnhfkG/93cHwWhuZJpvoQqHQaZTrCqcBDlSrjc7arUgC"
        "kP+DnTGGkZmdxa6jkK4ye2aTyLU3Y9c+yhhnSTPFYtf73f07suaZbrFrJyPX3m6+IKNgnkL6sWD3A0OpJqf1jxQCSP5HerbTqZzL"
        "3hu6mYpjhoGTn12/nzpL87vyvGcfznnBLYDxBpYxjF37Jnbtm2Ysy6lPFTxeZaPIs8ciL1hYKBQ61/Nm6Psdoe93rHf2sqdne+zZ"
        "+JNnjwFI6PsdTkXe5sUUK5qGIpKrN6tfFCCqWgPY6KxNjK1qOpu06QFRkNlue6jLOHt+SpKvJX8vycSpj+kkaDNeA3IOdKhTXUmT"
        "L73L4Sv+d0i2ENjCem/1hxBIfwEv/wRrpUZ43gAAAABJRU5ErkJggg=="
    ),
    "speaker_r20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAACIklEQVR42sWUv2tTURTHv+fc91LTNA1JkxcbXt7r4CAO4iCCP/AX"
        "iAouLg5O/gsORdRNUHBxFaSDUwdBHVwUQalOooOgKIiDeS8/iI2xjT9qbe49DnmvhGDBSqpnvPecD9/vPece4H+FADRMGA9NVQwT"
        "wPrNvVqXqhhWd8pnqwXvVeC6yUH7g0/BAwAlgHoB2AQYAkzT8WfGSF0DSZkXzWhcF7huslnwjxEg/dBVYATQBOidwEol42Xbjv+M"
        "IXsWYU4Q6BvSq7laaZ0iktthwTsXQRUAWAIwAaZa8KYzzLsXjFGKQAnQPhCev24Ge7cWvbKGpAyzAEBjwj+4uVF5Gubd44p5rpot"
        "zdLneigAc5/KIysi2xh4PwL6oMVczDUrRw8B3a7R4ySkv2vNApBhc6XulG95reoTQF7Cts70EAfY6rO89NXIXa8VnB/oogmZNAyQ"
        "7uVJg3+eNpJ418rlxpdEHoGwq1cxN6T56gurT01yjOlkreAlNhHZXTFvaT68DgChEQUAX6IxqZvELAj38u12p+akDgvoTmQZDMBE"
        "zIc20RsDbFmGTCniy+2i/+AxYFmsOkKiRpUyBAgbvlD6GJ4K8u5+gHZgpXszsmzW/J+VjJdNj9B9DUn/IEyz4IZY3e1uvf4JAGqT"
        "k3lb25VlwaXyfHBVAEWAxlqDHZ83HX+mU5ySqlNeqKZLE3Gz4sH+48Xxt1/v3y2HDVlfG7Zg1xO/AKqu5g+3ZxUvAAAAAElFTkSu"
        "QmCC"
    ),
    "camera_r20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAC9UlEQVR42qWUT2hcZRTFf/d7b/6QUtMmzkwmmXlDSrTgpCBoQehC"
        "QRBcZiu40EU3oS7FXdGdrtxViosKokvFjTtLFoKIBUGbYEDj/C+TENJY0/nz3ndczExIU2vUnt373rvnnXPv/Y5xAgTB0WeDhP8L"
        "gf2bs6MI/4nMQK1cdCnlOAMw9OzZdv3bybsTrQnCmxBuspQBaOSjy7uFStzOR812PmruFipxIx9dBthkKXMTwknNcb6HbGzMnj/d"
        "ykeNTqFcnZx1CuVqKx81NmbPn36UMLsK7l3wnVzljbSx0tOhk2ezzsr3vb50SB5wGBlnKz2vBvAjQNaMHv6bhW7jw3EroJUrvxIY"
        "X4G77iXvkZnRF/aHpFRgzIMFidR0xn3gjETGGbjRj94cSFdK240bIYDJVWNLfip1a28dlX8V3JVC5VoivSDMska23fOry/vN3aPf"
        "NZ8sLzjnngdGhN40MCwUL4bQCm6T1szcYNr5wQ9OWh84v5r4oJ+SreaybquZXry4sDOz1S62U/Odpwdt+y0rqQ8jxdh4KMZafPuZ"
        "tJZZHyTJ4B0v7s5066/O32mulbu172a3a68nYg1LPjBuDTfTaW+sxaMlGXG441Oqruc8gDO9LLguCDZZyvwMaUGYyK6ZcRHgpVpt"
        "eLz+IUKeu2fjvbwnKBokKYZ2iooziGXJ3MTerb+pd+NiASZwv+/sBALnsI8C4+1W8Vy0SK23SK3369lz02nc+87shsAVi8WURhw2"
        "ts14ygRA38BTq/UA6NY/vZOPqlM++b6Ti76QozelZGUAX8916++NNr1zANAUPWejEAlH/bJ9bzxVz5cuAKQMmbC+9HEi3XXYa06k"
        "euizgyT+pFMoLQPEkpOZD2UXEtnGWBzWzeVOJZb9PIW7NJQSTXpjchJ7MvoOkCxlxtnx5RegtJl56RdZsFLobnUfuMN7pdLM/vE4"
        "iuPANGV/AlN2oDgMD/PwCec07b1Z88FFR2OlPAZ0uMv/ITwfmTAnZePj4C+C1lJhzg+YTwAAAABJRU5ErkJggg=="
    ),
    "thermo_r20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAACJklEQVR42r2UzWsTURTFf/fNJClUqSWZGRFnRltEEDdCV90pVCgW"
        "iptu/C9cuHCjdunC/8FtV90JxUJdFurSjyJCp+mHSZpCTKUmZt51kUZCTcfowrt855zLu+fc9+A/ligIwBc/vl/zowcKBqB3PlB0"
        "FqBgBOyOH70cQeaAVlv13Wbt6uwab+wz0C5tiIa9ZokXTjoinxxhsl45tzvuN49sau6G9WRNwRFIT2tN1swdsaMChx8r2+WbvG8r"
        "si/Y81kaNwvMk0fpNK/50eM9tKLokbrZxrvZqViDcKzKlBVchZbR7KnMMGkb4UCQZlaIf9MQVc2BDsXNDkXVCCgi1iAna6LyTw0V"
        "TN7luwUxqo5FjSiOGKetGbqBwNOuWbaqrYMccsmILAjcc0VufD3WDwJ20FIPXOxfL6R45fqoq6spvG2pXkApFox8duDWt47MXK5v"
        "bfa4f7yhgmDS5Q68KlWS+RRNUtGkVEnm28oKJl3WIRKn581eMZza8cPmEjjlILpTD2I98OPOfhDfXgJnxw+be8Vwql9z1g0FwIpc"
        "BGksQGqtugWEERGnbW1uAVKQRpfzu22nX4oFMG5+XdOWt+VF03FteyXxoxmAuFZ+veVF06LqiVtY79dkje0A7Hrh4mEQNapBNNfD"
        "qkE0dxhEjV0vXOznDv19VbzoUc7wsKV0AAqC+8PyIqhtPx+UcGY9OfF3Y3xirFqKZ6uleHZjfGKsHxtUPwHs8d/fI5OfhwAAAABJ"
        "RU5ErkJggg=="
    ),
    "user_r20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAACGklEQVR42qWUP08bQRDFf7M2dhRBxe2diXJ7WCCQXCAhJNrUEaKh"
        "SE+qfIEUaUIUCVHkC6RKScEXSBlAoqSJ3Ebmz5kDTEKqCCLsSWEfuVg+Q8Trduftu3k3TwP3gIJRMDwUCqIgeedBKA4TE1CAnzac"
        "ApDW8bf+Wj8G2lgDI6AHnptoBdHelcj+lch+K4j2Djw3IaBrOW/NoM7egSq10ojRbaM024XiXLtQnDNKc8TotlIrdTnD7aeCBYAT"
        "G600rbvorzetuzix0UqWO7TD7d5XVTshokfdh9NlZboMgOiRaifMcu+MCEA8Pjmb+E6ToLqY1pKgupj4TuPxydksNwvJExXoxNa9"
        "fiy8v4YtgDK8+KW8fdo6+pBy7iWYFT3xoudFw0uAmw6fnlwcfs4Tu3M4g6bYC3fhv4Ld66ANyI/K5LPrdmcOoFwwX+X0YBdo39ty"
        "Sjz1w1dlzJvfqo9uhASgqEyURK6u6WxUzo8/DrWuIFs9K2eB27z0o+9nQbRat3Y05dStHT0LotVuzW0CbOX8mtuQxtatt3x32bBR"
        "JW/bNGxUafnuMrZufWDAU/KhDacS32nDi+YB6tRK/dumTq0E0PCi+cR3ethbHP9kUnvDiT23EVu3A/BlyCZKa7F1O7HnNrIa5q8m"
        "iLAkyO4amDEWcjM6xoJ0N5LsirCU1bi1AhAH4fK5V53J3uUNEODcq87EQbh8F/9B+APrKs80gUEYigAAAABJRU5ErkJggg=="
    ),
    "clipboard_r20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAACmElEQVR42o2UvWtcRxTFf2fmSUK2FQnbesK2VptgJ0UwJsHCBNvY"
        "SeFGjYuAm4T0Af8PqlKmSeEujXERcKq0iz8EakIQSSFUKP7SSlq0uxgjCzmy9s3cFPsWvd2sVrkwPJg5c+eec+87MCAMXO/efJ+9"
        "YqhPEpFfEgTrwQgsf0hAFFjxPOlNlgMCwObk9I/bLpnbjTEz0HHhamZ/qrn+TZ873RV2DlZPXvggHW5dfZfhzNkvQMXg7xycAt+Z"
        "4rdj8m/rvP/jk62tZjGpCjTZHDt7UqP+0Yg0tWfsC2Ym5MjyRz2wa0YLWxtCw2ZxL3r/1ZmtV9WOHB3KThDWR5IvwMqP69XTdyBs"
        "pqVbEbu2Y2YAY5L2zZZLzeqvALW0tGpZvC346Ulbvizp06ftO7mG5xrrFaDSp3FeECLalrqb4vq03ecS6Akkxs3EIDFIlvl0uNh9"
        "HTA8PGFxNJ5CFAuZIAPsIiv7a5Ol6xtpabGNUcC6xyoZMKChOOCC8Dz9aGqUUGmhn3NMwlGUyaurnS7PzbepCnDz4E4QFiJUzjXW"
        "7h5AB1BOfPu7xGUfFe/dTWd+E5gg+z6deQhoo1H92riZHBTfHV2UswBy+FmWWs/c1JVjjP5Vnyw/8GLFYXM7wc7PQssGSNWvy9FA"
        "F+r1xobp8yi7Mer0w67Cl+XX6zUDDwvxfyX0qENBBsmlxsu6ueHL9dD6rFTf/D2vzABXMIjDzSFa9KBMEGkvzm49awLNvPrOXxgB"
        "Noz3MvMD3MbtCJuunSrNZontdWZMmEyKBaBkifOKHwf09j8JBWEe3PTrDxdr6Yv7I14VTKHLYK1b5yHFpIUtDvHPw3y0Ql+DBXgz"
        "Xp7QuOkw4beBcWCiWn3DUWFHWHyvIfc6+r9fRhplL6uQtwAAAABJRU5ErkJggg=="
    ),
    "report_r20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAACg0lEQVR42q2Uu09UURDGfzPnXthVEEHXxwq7CbEwMXQ2aKOx0cZY"
        "kdhpYmLv/2KhRisTCVTaWRgstIISY0Lia9mVh4giBLjsPWcsdlcWWB4xnuTk5mTmfvm+mW8G/uEYyG6xqDlpFPTSycLtrMm5NTOl"
        "6UcFaxdZ/KLJI5md/T4Cbgj8dkBpgAnY165Ct2vnRxvyrmr20zAVsHpqOKxyI8DHRdzFs3Of5ncD/Suh1NvbU84V5j8c68u3kjOd"
        "K0wsnSxWKrm+LxPd/V0AI+Cac7QFZdehITcG0SS0PYR4DCKDSITcQupvGrztj/2rsWIxMwTetpamRdFV/BVIz0N6D9IrkAqkQEen"
        "02tO5bmHCwPrvC7n832ANED1IE1tJAu8jJG7PvBgjTCZFblIqkMCgbr0aB9rqDW9Zb50x0CO1oiEyonCOKbrAG/2kozVui41qaFx"
        "6yxNwNe+prINoxVD8c5Vp06dyp2xTP9v/AqYVOvBDot1Xavtp2fLE9/2MvYmnLnOJCyvx9FVgyfBJAFc3RshEJwFLQEDBia2dWp2"
        "Apqkq5H1FObKw8DwXt2qgCIN4+/B0Lm2penjxes9jvs/LfzGxNUqaz5j4hIhyc+XblUgHIAh5tONNmfuc2o2rghB6h4TyQqialaW"
        "GkMJ+9YQschp7FidDpJ9bFpd7vIZ9yvdiPOLlfL2bN1Psom5BF2NJXvzEPLUfLSWEGIX6dfPXcVB1+kT571Mzcxs0GKNtWpKomnY"
        "6FsoPQOe7YgvNS0LY63hz5aAtqxGO8czIqOVXGHRMM/m+lLB3OYUSdqpMrgS7AXA5eZ9uNuCbZ6CUJ+SprcdUVn5RRgpzk2/N9Dt"
        "bP/L+QNWlxX0mX5DGQAAAABJRU5ErkJggg=="
    ),
    "keyboard_r20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAACa0lEQVR42tWUT2+UVRTGf8+97/QvFU36zjh25m1AligLEhJXWGNg"
        "R9iQGPeu3Bg/Agv9AH4GN25YgW6kNDERCK4MYcFonIFhmI6yoFQ77bz3cdFpGVtjMGHDSe7ml3OfnPucew68MmEIhmwVMr/gmcgN"
        "B8X0EgoS7KpL4E6tcfIIYWXTDiHJKVgBwEpJjiEpHWJWOR/gKemW+g9vGySDHlaPvVOhvBGgvQ0b4HmskeQRMGu0CZ47zJiJkGVw"
        "YiRdqPfbqwB0F5ufdfPiZ4B+3jgB0Gk0Zn9bLOoA7bz59kH2uFocZ/zMbt689mhx+SsYm1lKpfFmP8+PLMTK/V5teSUMwxdZ8M1u"
        "vb6Yx9h6UCs+mGRzCr90qsXHhmBhy9v7ghEsMV0bDJ49Tdun6v32agzZl9Ml7y31er//kXZONfud65PsT4/eLdY7XwuSjPeqfd7u"
        "sd87I570q8XVN/u/DoZRn3Ty4lNP6f6gWnw7ybanaA2qxbU7nK4YdnRIcByRbEGQPa7V5jBHYyDO/qU3JFXu5vn8Hktb4XWL7OD9"
        "50BOAG89ad8Dzo/p5xO5H/4LOwcdujQrBu8LGizwKmTvc1q96uDyPOHMBmkIBOFkFIVLIxYIMxtOPy4dnbpMq1X2UPqHYLCmLIcV"
        "GMFPPEqN72KIz4wtFDweJCOMU0QKTj+o1RoCdAFJ0+x1plc7dgaP1kT4vrRL440StuKuyZ70KIHK3Z8xI/SaZEV0bog+KtbbV7Q3"
        "eg9qyytz5uLQTknOhMJ/z65TsEbTUtiCG0vr7Sv7O+FlLod9oW8gXuLs/xReA84CaxaUr8ai/ht4cii3RsvvPQAAAABJRU5ErkJg"
        "gg=="
    ),
    "monitor_r20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAB4klEQVR42rWUP09UURTEf3P3vQWeYsG6kA260YRYaGykskJj7Gy1"
        "0NoPoL2amPgJbPwEauysLTZWNtuYKIUaAy5ggv8ixkWWt3cs3i5EQsJC1tOc5p7JnJk5F4Zc6vcGlA4KcqFoXYEZOkOD3s/MlMd/"
        "de6m1tl122Gb+V7lNICsxdJm6c7Ej48/E4FX1jpXE7jdkR8pumQNRt0mdKLyTL7RTvOvwP0EwNGVDfH62Grr1kHW/FStTye4AlAA"
        "SrnkUTOXwJcA1TgI0AILyQkW8xWcGeVbgCo0s3iZG4JgIMAGcBLy5cJdAYRhuzx0wEJDsIpwJ28hNAZcGUga2wfibQ3t1LBxEfJ9"
        "EsoBllAbq7wFGKXWqDi3Uq0/9+6h/m0chcZ3JFFG3Szo0h9zb+tSAD5P1m+OoDMbdoxy6K0hIMq6YhhHftLT3YCxPBJE17Smjh56"
        "qPn5zkB7LVXrD5ar9af7crkBiZlLDEmT2bRZq2XmdNkQwIeBMUN4A+VmrZY1mU2L98VMP4f/6PUMSteguzx5/PIY4XEbtwXCnrKU"
        "CpYMzlC2Trw+vdp60Z/Z+R/Si48Efjcxc6RSys93HJMcCPImwjGqnABlhfxbN3l16vuHtf4M/6t2/fd6zu91RXE3Zn8BgyXAA7aY"
        "1j4AAAAASUVORK5CYII="
    ),
    "touchpad_r20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAACMElEQVR42rWUP09UURDFfzP3rYuIgMpbIeyCWFjaaWVBjaGzt6Tx"
        "A9gBvZ/AyprExsTOAgsbY2JiYQkBsivrqjEKy/57MxbcxZdFhBiZZHLfm5t3cs6ZmQfnHQ7qEM6SaxD+CrYM+g8EJP+e5C8ErDZZ"
        "vjPkWtrPxMHlTyAB8SS4uPFdGttvYlnof+CgAraTVp5cUl1qu3+1U+QI2JDIlZbZi6nGzsMIZniUuXl99kY1nentlqZvn1XuZjo7"
        "WSvNtKtp5V4kFo48S7w36vDti3c2zgo419jaNai5cbVf+w0omgmE8UKhCEhskJyQCkj0PVHR3jHAbvTTVB3wFXBOSTk8kVzzNNd/"
        "AVAziaMgfkIu554HbTgCzDT0AG8Ot7oSOxbPY7mauwPcETs2hwVjXPCk+GNkYrs8nKiZRPkU2+ECQLuYdQD2zGRE1UdVvdkiID6c"
        "B5Tow9KIhrGfbm+9rQpKiGZ1xQsA2tauAKNR2J6QXRa9toctAs/7gM4h76f7bouq2f0eHOAInqhrLxPXxyBll+wR5qEjYgXBNSSd"
        "Zmav1Hl5THJP+YQx1pRs41Z9t5E3upqWN0C0/Ln6YXCPq2llQt3ruQ3iaFtqpcqzi+hCC9t2J4CAuDvcFGcI4WN/GkTIimjlwP39"
        "dGNuYYXXtprbZenPVD2deRCUqbbhuAdEzPG7ImI473BXRLJEEUEaaX1rTcDyGP81BgdTonxZzxXnwQDWB/6X84eM7FyY9eMX5k0M"
        "m2eJfbIAAAAASUVORK5CYII="
    ),
    "mic_r20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAACIUlEQVR42rWUsWtTcRDHP/feS0Wq1tL+3iua/NIh0qVThy6C+g8I"
        "OrjopIKTi4L/geBUcRMHceqSQnXQRRBFkYI4lWJBRdr0pQlJBCsi0uT9ziF9EMprmiLedNx978tx37uDfUzBV5DU518sJdovNiiZ"
        "B1APixdaoV1thsVv9dDe6M1lmexFJuBqUX7WV+8dwh11uuWJPGqrXD7RXF9U8AWSAbs7GwBsGvsgNvZlGt8w9mFsCs8BXkOQVev1"
        "I3aoAL93hPEF/gji+tV4/ZOigvoCiUCC6r4qB/07BEGcgr8AeCJOQQ9E2FWw6QGIaoDgpcOPuyrmAAx4qXh9CbuAT9sA6smzIXhR"
        "iwrnNdGtQLjWdtwCmIbtgZY4HpucqkT56fQqasbebEW23gyLrVpk7wKUwa9E+el4bHJqz2VPV2XD2LmqKSztAHMAn0ulQ7UoGgb4"
        "uBOLTWFpw9i53trMy6iO25k4tJ0VU5wAqOTzh1NM6q+Y4kQc2k513M70vZw0ERtbboV2dXnEju7GLI/Y0VZoV2Njy1lkkjFH+UIp"
        "Nxa2F4DTHdUnbY83ADnHuUDkKvD+eyN36RRf24BKzyplfpMUUA/tlQCut+GMAkPwtgOPJxqV+d3YA72teNze2zR2fpA3ltWhL5BU"
        "w+LFY8Ltn+p+qDIryFFEXx0R7/gv5f7JxvrTrI8TZDcI6lhLfP3gVBBYBk2cyrCKok7WerH/1f4CF5bTIlq3C3EAAAAASUVORK5C"
        "YII="
    ),
    "gauge_r20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAACLUlEQVR42u1TTWsTURQ9783kY6G2pZn3gs3MSzSoVHCjKCoSEMGN"
        "dRl/goI73QlauhFcuXEhiFuR7l10lR+g3QliaChp3ySpacYWi/nqzHWRmZBqqi2uBM/yvvsO595zD3AAzAN8HuD4GxDACDAIMKNa"
        "CTDDGjss2R41dXlCVERO/tRjjPvLxpAZDPAB8C9SFQk05we4wRi4CZQYw1I5Fry5onV7pHcIPo7MtZyrnlSfDdBzn9AhYCMA6R7Q"
        "ZITHZ/pGpSHs2wzwSyMr2YPFcASdsoueVMGmyD5ZxGwcAGrpvFVLp62otymyd79K5WuReTh2fAI4Aawq7bNNqUin7OLI21BBOZ9P"
        "AEBDOO/WhPNUW3bXtbI3fyGNTNDCea8t+9WgNhuP3CSAf4zUCud1UyiPAFML9UALu04omGEvG5Kti5lzrmX3Vi2VDhUP9/sBiAGA"
        "tpz7Lamokjp+CgBWlUpqYW/raXsuUskjYwzwywQs55rVRmh/EBFeAPp16Vw/xvmL7z7dOrlZK5fz+USuWu0ExJYMjgIALOM8xzzA"
        "tyacKVc42pOqvy5nLo0cNfs0ffqoazlvd2S26wr1KNolAawuMxc9qb5py2ltTThTBDBzAQjuJbs9BIlnMY5Y3GctBhANVJIOdieP"
        "mPzODgXwO8FLAjhWVnYZQBsBPMOgBQDtdrLbm9wG/TF+AOCm7GtrqUwhVH6w2A1yOnTrEHkvmPse928+Gvtl9z/+AfwA6yjcGf38"
        "VDsAAAAASUVORK5CYII="
    ),
    "usb_r20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAACY0lEQVR42rWUz0tUURTHP+fNmzExCHXeG9F5bww0w1qGQS2U6F8o"
        "FxoULQr6GyISXLQJIqpdOyOkHxDtivwHbBNhoVGM82bUmcwaRWfUuafFvAExx9FFX7hwL/eec+/3fO/5QgMoWHvN68Heb3MKbIHt"
        "rOs/VdWYFDKjChGBCgeFgoQjApB2vKuLrr+y4Hq5dNy7HJ6J1IuX/ZJ/b+/u64jydcWYIrB6VKRrtWL1df38MQeIgNkd809N5pPJ"
        "Zu082T7b09PUuq1LRaMjqH5E9c+G6ujWlskLKGA1qqkAZB3/XbnjeDZwvGe15weudy+Iey/2YqW71jtvUAVB9FRZ1RXoVED7+2MC"
        "LSI0TYGtEFGQX45/JXD8c1KL251QqzVRgUcCb2yxTiy73TdkZmbTqJYBhqrqmqzj37fEGrPgVSaRGhLQyVAoewdfBejMZ8YBch3e"
        "mSa1JnKuf1ZEKkZVwzOagwvbaEGEXqHSAXCpnighJbtzMTP9bSl9WqB0TOR6BRN87u+P/XZTk7awERG+KDqWXAqeh+wq+36bqoJ3"
        "EO6arOM/abHk/LpRmi35tGnWbyYKhbVDdYqAmeZtdBLEwHoU6Qa91rqUfhleaFOt+WG6ZtBWsLJx/3Ha8V4DzEKT7sOsQbOviYCp"
        "QDGi1ZcUwdQEPBRqXZCLJwcLbmo576bWc/HkYCPXkXoGAZBJJlsjm9ZcFBm3wJTR25WY6fWCYGXnVzsIZRFQq2TiQNut/MCDD/mB"
        "h0CbVTLxMJEcym1CWpp1/IkjIhcBSqrvuwrzI/WcpqEv1uYLCW94IeEN1zOE/4q/ld/0rQm/isgAAAAASUVORK5CYII="
    ),
    "power_r20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAACV0lEQVR42qWUP0wUQRjFf9/MHlwEg0h2ycndXmg0RjvtgVDYGAsN"
        "xEJbEymIBbG1MLGzILExGgtLSDQx1h5aaGGMWhj/EeG4P8LBhSiEoLe7n8XdGSB3cISv2ZmdmTdv3nsz0EIpSO1rOWjVQXJu38W8"
        "57/asoE0mm9aY3Ym1ib2jqh624f3CTgDViAseMu3PRs7geqb+v9ma5oCToEdgmDR84dRvbwUVt4iZhVgkAH2BaggI8DP3t6OUJlG"
        "GA9U1zFaUrDfKVgFqw10bMbQCoSRtj9UeJks5Z6BnJZQXwuEx5n9IxBKAx2lkasCYdH1L0Wij9rDQ8nIbHYEonmUG5EyJ1ZNF2b9"
        "l63MJovFnILUwbcxvFXta7bL747gMcIVt/x1LbRRMgYFhQljuC8qdzvEvJBK7Fr9RE2NqGYu9bTgpe7tYG60RqDo+lcLburHkut2"
        "KshWLf83MuAMQVDo9cePGWeyGAYfQdUggYWVDWEsvbQwv9CTSlgj32wk5xPl7MwU2FEI6zhOvTEIEYAqnzY0vI7igEgk6huRibhW"
        "dSoYeSLwIFHOzig4AsG+rl6+xx/Oef4CQN5NjxXc1PxUNTKtxaaq1YAzRzqeAUesnrPwebUrfUREJ8XqyCiE01W99o7NTk3zXup5"
        "pPLBwClEc8lSbrw+1mid0wxwsCa0QHccLvyFzcWSN6rkLFtMaAmwHtQ50nGI+mNGEpWAk2d5V1Ew0uSl2e3qCUD7Ufpd4yTWIr3Z"
        "V85+yVRdjXYz0dnV4rawcyWK3v9ePjxZC3V44Bc7s9emO+ofEZzsBzBbLEsAAAAASUVORK5CYII="
    ),
    "body_r20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAACAElEQVR42rVUPW8TQRB9b3d9jrEQIJwzxB8ISIFS0PADCEh0FKGg"
        "QqJElPwDfgL/gRYJCQmJBimhSEmbwpBgktgoskVipHPI+XaH4u5k+zhHUZSMdM3czOyb92YGOGNj1iGxT50wXwg4nKdxEhkB6V1t"
        "LJQK6u5+BBUDyE2TKwYSWNeq9nY201wAMNnQUPODdrhNJX8I6Nw+Ie6v41xEhr+q1TvY2xumRc0EVEnCa4Hjs0Z/+9Pky1lrX2su"
        "FaysW6PnCAQJ93nkM9JjKmaJhqIIAVqn1NSDeWrSxtxxLf7Pye9d4hslMdlkc9xILMftTiF4muObWfB1gpgiWnDfAB0tqGVQ9JRg"
        "3rXdN6OhoJxjbsFEAPcCgCX2iS8RgAj4nouk5dX6XggpXB4dSXfc+pTK7UrzOiC2RL7c9ZsPRUSr/zeBAESN6DuKHvwuNavARioW"
        "VwHzAIh2K83HZcX3Qzh3kbqomS9zSp4TYCAuKpMIrDyp97c/rgKGAigCrjvf2NIKny3VmzAUamVHx62YdsbAAwoir0ZOHi30dm5J"
        "OjUdv77S9RsHp93frt846Pj1FQBga3GxWB6EGx558wjylSIeOHssMv1TyLAI3gtFfgSXvCUKYDqVG89LSvSQKCl3wmIplwq8IDg8"
        "dLS1/s+353O+JL4qXDtlkeXxsbVnjvAfiVfNEVE3j48AAAAASUVORK5CYII="
    ),
    "banner": (
        "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"
    ),
}


C = {}
APP_FONT = ["TkDefaultFont"]
ONP = "#fefefe"  # chữ trắng đặt trên nền đỏ (khác "#ffffff" để không bị đổi màu khi chuyển giao diện)

# Bảng màu: mọi màu trong 1 giao diện phải khác nhau (để đổi sáng/tối bằng cách ánh xạ màu cũ -> màu mới)
THEMES = {
    "dark": dict(
        bg="#0d0d10", card="#16161b", card2="#1f1f26", line="#2b2b34", text="#f2f2f5", muted="#9b9bab",
        dim="#5d5d6b", primary="#e5161e", primary_d="#b80f16", glow="#ff4a50",
        ok="#2ecc71", ok_bg="#10301f", warn="#f5a524", warn_bg="#33260a", bad="#ff4d55", bad_bg="#3a1216",
        sel="#3a1418", hover="#2a2a33", scroll="#34343f", scroll_hv="#4a4a58",
        row_warn_bg="#241d0d", row_warn_fg="#f7c873", row_bad_bg="#2a1214", row_bad_fg="#ff8c92"),
    "light": dict(
        bg="#f3f4f8", card="#ffffff", card2="#f0f2f6", line="#dde1ea", text="#151821", muted="#697085",
        dim="#a4abbb", primary="#e5161e", primary_d="#c4121a", glow="#ff3b42",
        ok="#1e9e5a", ok_bg="#e1f5ea", warn="#b86e00", warn_bg="#fff1d6", bad="#d62b35", bad_bg="#fde7e9",
        sel="#fde4e6", hover="#e4e7ef", scroll="#c9cdd9", scroll_hv="#aeb3c2",
        row_warn_bg="#fff7e6", row_warn_fg="#8a5300", row_bad_bg="#fdeced", row_bad_fg="#b3202a"),
}
# Thanh menu bên trái luôn tối ở cả 2 giao diện (nhận diện thương hiệu)
SIDEBAR = dict(side="#09090b", side2="#1a1a20", side_text="#c9c9d3", side_dim="#6d6d7c", side_hi="#ffffff")
THEME_NAME = ["dark"]
UI_STATUS = {"OK": "●  Đạt", "WARN": "▲  Cảnh báo", "FAIL": "✖  Lỗi", "INFO": "ℹ  Thông tin"}
STATUS_COLOR = {}
ICON_CACHE = {}
MONO = "Consolas"


def set_theme(name):
    if name not in THEMES:
        name = "dark"
    C.update(THEMES[name])
    C.update(SIDEBAR)
    THEME_NAME[0] = name
    STATUS_COLOR.update({"OK": C["ok"], "WARN": C["warn"], "FAIL": C["bad"], "INFO": C["muted"]})


set_theme("dark")


# ---- Lưu lựa chọn sáng/tối giữa các lần mở phần mềm ----
def settings_file():
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    d = os.path.join(base, "PCCheckIn")
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        pass
    return os.path.join(d, "settings.json")


def load_settings():
    try:
        with open(settings_file(), "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def save_settings(**kw):
    d = load_settings()
    d.update(kw)
    try:
        with open(settings_file(), "w", encoding="utf-8") as f:
            json.dump(d, f)
    except Exception:
        pass


# ---- Đổi màu toàn bộ widget đang mở khi chuyển sáng/tối ----
COLOR_OPTS = ("bg", "fg", "highlightbackground", "highlightcolor", "insertbackground", "activebackground",
              "activeforeground", "selectbackground", "selectforeground", "troughcolor", "disabledforeground")


def color_map(old, new):
    m = {}
    for k, v in THEMES[old].items():
        nv = THEMES[new][k]
        if v.lower() != nv.lower():
            m[v.lower()] = nv
    return m


def recolor(widget, m, skip=()):
    if widget in skip:
        return
    for opt in COLOR_OPTS:
        try:
            cur = str(widget.cget(opt)).lower()
        except tk.TclError:
            continue
        if cur in m:
            try:
                widget.configure(**{opt: m[cur]})
            except tk.TclError:
                pass
    for ch in widget.winfo_children():
        recolor(ch, m, skip)


def chip_colors(status):
    return {"OK": (C["ok_bg"], C["ok"]), "WARN": (C["warn_bg"], C["warn"]),
            "FAIL": (C["bad_bg"], C["bad"])}.get(status, (C["card2"], C["muted"]))


def ico(name, variant=None):
    # Ảnh icon nhúng sẵn trong code (không cần file ngoài). Giữ tham chiếu để Tk không xóa ảnh.
    key = name if variant is None else "%s_%s" % (name, variant)
    if key not in ICON_CACHE:
        data = ICONS_B64.get(key)
        try:
            ICON_CACHE[key] = tk.PhotoImage(data=data) if data else None
        except Exception:
            ICON_CACHE[key] = None
    return ICON_CACHE[key]


def scan_icon(name):
    n = name.lower()
    for keys, ic in ((("windows",), "windows"), (("thông tin máy",), "info"), (("cpu",), "chip"),
                     (("ram",), "ram"), (("gpu", "card đồ họa"), "gpu"), (("ổ cứng", "dung lượng"), "disk"),
                     (("pin",), "battery"), (("mạng", "internet", "wi-fi"), "wifi"),
                     (("thiết bị lỗi",), "warning"), (("âm thanh", "bluetooth"), "speaker"),
                     (("webcam",), "camera"), (("nhiệt",), "thermo")):
        if any(k in n for k in keys):
            return ic
    return "info"


def pick_font(root):
    fams = set(tkfont.families(root))
    for f in ("Segoe UI", "Inter", "Helvetica Neue", "Arial", "DejaVu Sans"):
        if f in fams:
            return f
    return "TkDefaultFont"


def setup_style(root, ff):
    root.configure(bg=C["bg"])
    root.option_add("*Font", (ff, 10))
    for w in ("Label", "Frame", "Toplevel"):
        root.option_add("*%s.background" % w, C["bg"])
    root.option_add("*Label.foreground", C["text"])
    root.option_add("*TCombobox*Listbox.background", C["card2"])
    root.option_add("*TCombobox*Listbox.foreground", C["text"])
    root.option_add("*TCombobox*Listbox.selectBackground", C["primary"])
    root.option_add("*TCombobox*Listbox.selectForeground", ONP)
    root.option_add("*TCombobox*Listbox.font", (ff, 10))
    s = ttk.Style()
    s.theme_use("clam")
    s.configure(".", font=(ff, 10), background=C["bg"], foreground=C["text"])
    s.configure("TFrame", background=C["bg"])

    def flat(name, bg, fg, border=None, pad=(14, 8), font=None, **extra):
        b = border or bg
        s.configure(name, background=bg, foreground=fg, bordercolor=b, lightcolor=b, darkcolor=b,
                    focuscolor=bg, padding=pad, relief="solid", borderwidth=1, **extra)
        if font:
            s.configure(name, font=font)

    flat("TButton", C["card2"], C["text"], C["line"])
    s.map("TButton", background=[("active", C["hover"]), ("disabled", C["card"])],
          foreground=[("disabled", C["dim"])], bordercolor=[("active", C["primary"])],
          lightcolor=[("active", C["primary"])], darkcolor=[("active", C["primary"])])
    flat("Primary.TButton", C["primary"], ONP, pad=(16, 9), font=(ff, 10, "bold"))
    s.map("Primary.TButton", background=[("active", C["glow"]), ("disabled", C["dim"])],
          foreground=[("disabled", C["card"])], bordercolor=[("active", C["glow"])],
          lightcolor=[("active", C["glow"])], darkcolor=[("active", C["glow"])])
    flat("Good.TButton", C["ok_bg"], C["ok"], C["ok"], pad=(16, 9), font=(ff, 10, "bold"))
    s.map("Good.TButton", background=[("active", C["ok"])], foreground=[("active", ONP)])
    flat("Danger.TButton", C["bad_bg"], C["bad"], C["bad"], pad=(16, 9), font=(ff, 10, "bold"))
    s.map("Danger.TButton", background=[("active", C["bad"])], foreground=[("active", ONP)])
    for name, col in (("Ok", C["ok"]), ("Bad", C["bad"]), ("Skip", C["dim"])):
        flat(name + ".Toolbutton", C["card2"], C["muted"], C["line"], pad=(12, 6))
        s.map(name + ".Toolbutton", background=[("selected", col), ("active", C["hover"])],
              foreground=[("selected", ONP)], bordercolor=[("selected", col)],
              lightcolor=[("selected", col)], darkcolor=[("selected", col)])
    for w in ("TEntry", "TCombobox"):
        s.configure(w, fieldbackground=C["card2"], foreground=C["text"], insertcolor=C["text"],
                    bordercolor=C["line"], lightcolor=C["line"], darkcolor=C["line"], padding=8,
                    selectbackground=C["primary"], selectforeground=ONP)
        s.map(w, bordercolor=[("focus", C["primary"])], lightcolor=[("focus", C["primary"])],
              darkcolor=[("focus", C["primary"])])
    s.configure("TCombobox", background=C["card2"], arrowcolor=C["muted"])
    s.map("TCombobox", fieldbackground=[("readonly", C["card2"])], foreground=[("readonly", C["text"])],
          selectbackground=[("readonly", C["card2"])], selectforeground=[("readonly", C["text"])])
    s.configure("Treeview", rowheight=40, background=C["card"], fieldbackground=C["card"],
                foreground=C["text"], borderwidth=0, font=(ff, 10))
    s.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
    s.configure("Treeview.Heading", background=C["card2"], foreground=C["muted"], font=(ff, 9, "bold"),
                relief="flat", padding=(10, 9), bordercolor=C["line"], lightcolor=C["card2"], darkcolor=C["card2"])
    s.map("Treeview", background=[("selected", C["sel"])], foreground=[("selected", C["text"])])
    s.map("Treeview.Heading", background=[("active", C["hover"])])
    s.configure("Vertical.TScrollbar", background=C["scroll"], troughcolor=C["card"], bordercolor=C["card"],
                arrowcolor=C["muted"], relief="flat", lightcolor=C["scroll"], darkcolor=C["scroll"])
    s.map("Vertical.TScrollbar", background=[("active", C["scroll_hv"])])
    s.configure("Horizontal.TProgressbar", troughcolor=C["line"], background=C["primary"],
                bordercolor=C["line"], lightcolor=C["primary"], darkcolor=C["primary"], thickness=8)


def card(parent, **kw):
    return tk.Frame(parent, bg=C["card"], highlightbackground=C["line"], highlightthickness=1, **kw)


def section(parent, title, icon=None, sub=None, pad=20):
    # Khung nội dung có tiêu đề: vạch đỏ + icon + tên + đường kẻ. Trả về (khung ngoài, vùng chứa nội dung)
    c = card(parent)
    head = tk.Frame(c, bg=C["card"])
    head.pack(fill="x", padx=pad, pady=(14, 0))
    tk.Frame(head, bg=C["primary"], width=4, height=18).pack(side="left", padx=(0, 10))
    if icon and ico(icon, "r20"):
        tk.Label(head, image=ico(icon, "r20"), bg=C["card"]).pack(side="left", padx=(0, 8))
    tk.Label(head, text=title, bg=C["card"], fg=C["text"], font=(APP_FONT[0], 11, "bold")).pack(side="left")
    if sub:
        tk.Label(head, text=sub, bg=C["card"], fg=C["muted"], font=(APP_FONT[0], 9)).pack(side="right")
    tk.Frame(c, bg=C["line"], height=1).pack(fill="x", padx=pad, pady=(12, 0))
    body = tk.Frame(c, bg=C["card"])
    body.pack(fill="both", expand=True, padx=pad, pady=(pad - 4, pad - 2))
    return c, body


def mk_label(parent, text, kind="body", ff=None, **kw):
    ff = ff or APP_FONT[0]
    spec = {"h1": (ff, 19, "bold"), "h2": (ff, 12, "bold"), "bold": (ff, 10, "bold"),
            "muted": (ff, 9), "body": (ff, 10), "mono": (MONO, 9)}[kind]
    fg = C["muted"] if kind in ("muted", "mono") else C["text"]
    return tk.Label(parent, text=text, font=spec, fg=kw.pop("fg", fg), bg=kw.pop("bg", parent["bg"]),
                    anchor=kw.pop("anchor", "w"), **kw)


def mk_text(parent, height=5):
    return tk.Text(parent, height=height, bd=0, relief="flat", bg=C["card2"], fg=C["text"], wrap="word",
                   highlightthickness=1, highlightbackground=C["line"], highlightcolor=C["primary"],
                   padx=12, pady=10, font=(APP_FONT[0], 10), insertbackground=C["text"])


def header_bar(parent, icon, title, subtitle):
    # Thanh tiêu đề cho cửa sổ phụ
    f = tk.Frame(parent, bg=C["card"], highlightbackground=C["line"], highlightthickness=1)
    tk.Frame(f, bg=C["primary"], width=4).pack(side="left", fill="y")
    box = tk.Frame(f, bg=C["card2"], highlightbackground=C["line"], highlightthickness=1)
    box.pack(side="left", padx=(16, 12), pady=14)
    tk.Label(box, image=ico(icon, "r40"), bg=C["card2"]).pack(padx=8, pady=8)
    t = tk.Frame(f, bg=C["card"])
    t.pack(side="left", fill="x", expand=True)
    tk.Label(t, text=title, bg=C["card"], fg=C["text"], font=(APP_FONT[0], 16, "bold"), anchor="w").pack(fill="x")
    tk.Label(t, text=subtitle, bg=C["card"], fg=C["muted"], font=(APP_FONT[0], 9), anchor="w").pack(fill="x")
    return f


class NavItem:
    # Mục menu bên trái: icon + chữ, vạch đỏ bên trái khi đang chọn.
    def __init__(self, parent, icon, text, cmd, ff):
        self.icon = icon
        self.f = tk.Frame(parent, bg=C["side"], cursor="hand2")
        self.bar = tk.Frame(self.f, bg=C["side"], width=4)
        self.bar.pack(side="left", fill="y")
        self.il = tk.Label(self.f, image=ico(icon, "g22"), bg=C["side"], bd=0)
        self.il.pack(side="left", padx=(16, 12), pady=13)
        self.tl = tk.Label(self.f, text=text, bg=C["side"], fg=C["side_text"], font=(ff, 10), anchor="w")
        self.tl.pack(side="left", fill="x", expand=True)
        self.on = False
        self.ff = ff
        for w in (self.f, self.il, self.tl, self.bar):
            w.bind("<Button-1>", lambda e: cmd())
            w.bind("<Enter>", lambda e: self._paint(True))
            w.bind("<Leave>", lambda e: self._paint(False))

    def _paint(self, hover):
        bg = C["side2"] if (self.on or hover) else C["side"]
        for w in (self.f, self.il, self.tl):
            w.config(bg=bg)
        self.bar.config(bg=C["primary"] if self.on else bg)

    def set(self, on):
        self.on = on
        self.il.config(image=ico(self.icon, "r22" if on else "g22"))
        self.tl.config(fg=C["side_hi"] if on else C["side_text"], font=(self.ff, 10, "bold" if on else "normal"))
        self._paint(False)

    def pack(self, **kw):
        self.f.pack(**kw)


class ThemeSwitch:
    # Nút gạt Sáng / Tối
    def __init__(self, parent, on_change, ff):
        self.on_change = on_change
        self.f = tk.Frame(parent, bg=C["card2"], highlightbackground=C["line"], highlightthickness=1)
        self.items = {}
        for name, text in (("light", "☀  Sáng"), ("dark", "☾  Tối")):
            lb = tk.Label(self.f, text=text, font=(ff, 9, "bold"), padx=14, pady=6, cursor="hand2")
            lb.pack(side="left", padx=2, pady=2)
            lb.bind("<Button-1>", lambda e, n=name: self.on_change(n))
            self.items[name] = lb
        self.paint()

    def paint(self):
        self.f.config(bg=C["card2"], highlightbackground=C["line"])
        for n, lb in self.items.items():
            on = n == THEME_NAME[0]
            lb.config(bg=C["primary"] if on else C["card2"], fg=ONP if on else C["muted"])


def stat_tile(parent, caption, color, width=3):
    f = tk.Frame(parent, bg=C["card2"], highlightbackground=C["line"], highlightthickness=1)
    tk.Frame(f, bg=color, height=3).pack(fill="x")
    n = tk.Label(f, text="0", bg=C["card2"], fg=color, font=(MONO, 20, "bold"), width=width)
    n.pack(padx=14, pady=(6, 0))
    tk.Label(f, text=caption, bg=C["card2"], fg=C["muted"], font=(APP_FONT[0], 8, "bold")).pack(pady=(0, 8))
    return f, n


class CheckinReportParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.section = ""
        self.heading = None
        self.cell = None
        self.row = None
        self.in_table = False
        self.data = {"customer": {}, "auto": {}, "manual": {}}

    def handle_starttag(self, tag, attrs):
        if tag == "h2":
            self.heading = []
        elif tag == "table":
            self.in_table = True
        elif self.in_table and tag == "tr":
            self.row = []
        elif self.in_table and tag in ("th", "td"):
            self.cell = []
        elif self.in_table and tag == "br" and self.cell is not None:
            self.cell.append("\n")

    def handle_data(self, data):
        if self.heading is not None:
            self.heading.append(data)
        if self.cell is not None:
            self.cell.append(data)

    def handle_endtag(self, tag):
        if tag == "h2" and self.heading is not None:
            self.section = " ".join("".join(self.heading).split())
            self.heading = None
        elif self.in_table and tag in ("th", "td") and self.cell is not None:
            value = " ".join("".join(self.cell).split())
            if self.row is not None:
                self.row.append(value)
            self.cell = None
        elif self.in_table and tag == "tr" and self.row is not None:
            self._store_row(self.row)
            self.row = None
        elif tag == "table":
            self.in_table = False

    def _store_row(self, cells):
        if self.section == "Thông tin khách hàng" and len(cells) >= 2:
            self.data["customer"][cells[0]] = cells[1]
        elif self.section in ("Kiểm tra tự động", "Kiểm tra thủ công") and len(cells) >= 2:
            if cells[0] == "Hạng mục":
                return
            category = "auto" if self.section == "Kiểm tra tự động" else "manual"
            detail = cells[2] if len(cells) > 2 else ""
            if detail == "Nhập thông tin":
                detail = ""
            self.data[category][cells[0]] = {"status": cells[1], "detail": detail}


class App:
    NAV = [("cust", "user", "Thông tin khách"), ("auto", "chip", "Quét tự động"),
           ("man", "clipboard", "Test lỗi thủ công"), ("rep", "report", "Báo Cáo")]

    def __init__(self, root):
        self.root = root
        root.title(APP_TITLE)
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        w = min(1280, screen_width - 50)
        h = min(860, screen_height - 100)
        x = (screen_width - w) // 2
        y = (screen_height - h) // 2
        root.geometry(f"{w}x{h}+{x}+{y}")
        root.maxsize(1280, 860)
        root.minsize(min(1100, w), min(740, h))
        self.ff = pick_font(root)
        APP_FONT[0] = self.ff
        set_theme(load_settings().get("theme", "dark"))
        setup_style(root, self.ff)
        self.q = queue.Queue()
        self.auto = []
        self.manual = {}
        self.manual_entries = {}
        self.test_windows = {}
        self.test_window_cleanups = {}
        self.info = {}
        self.texts = {}
        self.wavs = {}
        self.pages = {}
        self.titles = {}
        self.hints = {}
        self.row_lbls = {}
        self.man_cards = {}
        self.dot_lbls = {}
        self.chip_lbls = {}
        self.cur = "cust"
        self.nav_btns = {}
        self.build_shell()
        self.build_customer(self.add_page("cust", "user", "Thông tin khách hàng",
                                          "Ghi lại thông tin và ngoại hình máy lúc tiếp nhận"))
        self.build_auto(self.add_page("auto", "chip", "Quét tự động",
                                      "Đọc cấu hình, sức khỏe ổ cứng, pin, mạng, driver, nhiệt độ"))
        self.build_launcher(self.add_page("man", "clipboard", "Test lỗi thủ công",
                                          "Trung tâm test mở ở khung riêng - kiểm tra bằng mắt, tai và tay"))
        self.build_report(self.add_page("rep", "report", "Xuất báo cáo",
                                        "Tạo phiếu tình trạng máy để lưu hồ sơ hoặc gửi khách"))
        self.build_manual_window()
        self.show("cust")
        self.update_summary()
        root.bind_all("<MouseWheel>", self._wheel, add="+")
        threading.Thread(target=self._init_gpus_bg, daemon=True).start()
        self.poll()

    def _init_gpus_bg(self):
        try:
            list_gpus()
            self.q.put(("gpus", None))
        except Exception:
            pass

    # ---------------- Khung chung ----------------
    def build_shell(self):
        root, ff = self.root, self.ff
        root.columnconfigure(1, weight=1)
        root.rowconfigure(0, weight=1)
        side = tk.Frame(root, bg=C["side"], width=252)
        side.grid(row=0, column=0, sticky="ns")
        side.pack_propagate(False)
        self.side = side
        tk.Frame(side, bg=C["primary"], width=2).pack(side="right", fill="y")
        # Logo HAMTECH nhúng sẵn trong code (base64) - không cần file ảnh đi kèm.
        logo = tk.Frame(side, bg="white", highlightthickness=0)
        logo.pack(fill="x", padx=16, pady=(22, 0))
        try:
            self.brand_logo = tk.PhotoImage(data=LOGO_B64)
            tk.Label(logo, image=self.brand_logo, bg="white", bd=0).pack(padx=4, pady=6)
            try:
                root.iconphoto(True, self.brand_logo)
            except Exception:
                pass
        except Exception:
            self.brand_logo = None
            tk.Label(logo, text="HAMTECH", bg="white", fg=C["primary"],
                     font=(ff, 20, "bold"), padx=8, pady=14).pack(fill="x")
        tk.Frame(logo, bg=C["primary"], height=3).pack(fill="x")
        tk.Label(side, text="PC CHECK-IN", bg=C["side"], fg=C["glow"], font=(MONO, 11, "bold")).pack(pady=(14, 0))
        tk.Label(side, text="TIẾP NHẬN & KIỂM TRA MÁY", bg=C["side"], fg=C["side_dim"],
                 font=(ff, 8, "bold")).pack(pady=(0, 20))
        tk.Label(side, text="//  MENU", bg=C["side"], fg=C["side_dim"], font=(MONO, 8, "bold"), anchor="w").pack(
            fill="x", padx=22, pady=(0, 6))
        bottom = tk.Frame(side, bg=C["side"])
        bottom.pack(side="bottom", fill="x", padx=16, pady=16)
        tk.Label(bottom, text="HAMTECH  •  Đánh thức tương lai", bg=C["side"], fg=C["side_dim"],
                 font=(ff, 8)).pack(side="bottom", pady=(12, 0))
        ttk.Button(bottom, text="Xuất báo cáo", style="Primary.TButton",
                   command=lambda: self.show("rep")).pack(side="bottom", fill="x")
        sumbox = tk.Frame(bottom, bg=C["side2"], highlightbackground="#24242c", highlightthickness=1)
        sumbox.pack(side="bottom", fill="x", pady=(0, 12))
        tk.Label(sumbox, text="TRẠNG THÁI PHIÊN", bg=C["side2"], fg=C["side_dim"], font=(MONO, 8, "bold"),
                 anchor="w").pack(fill="x", padx=12, pady=(10, 2))
        self.side_sum = tk.Label(sumbox, text="", bg=C["side2"], fg=C["side_text"], font=(ff, 9),
                                 justify="left", anchor="w")
        self.side_sum.pack(fill="x", padx=12, pady=(0, 10))
        for key, icon, label in self.NAV:
            it = NavItem(side, icon, label, lambda k=key: self.show(k), ff)
            it.pack(fill="x", pady=1)
            self.nav_btns[key] = it

        self.content = tk.Frame(root, bg=C["bg"])
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.columnconfigure(0, weight=1)
        self.content.rowconfigure(1, weight=1)
        top = tk.Frame(self.content, bg=C["bg"])
        top.grid(row=0, column=0, sticky="ew", padx=28, pady=(22, 0))
        tt = tk.Frame(top, bg=C["bg"])
        tt.pack(side="left")
        self.top_title = tk.Label(tt, text="", bg=C["bg"], fg=C["text"], font=(ff, 20, "bold"), anchor="w")
        self.top_title.pack(anchor="w")
        self.top_sub = tk.Label(tt, text="", bg=C["bg"], fg=C["muted"], font=(ff, 10), anchor="w")
        self.top_sub.pack(anchor="w", pady=(2, 0))
        self.theme_sw = ThemeSwitch(top, self.set_theme_mode, ff)
        self.theme_sw.f.pack(side="right", pady=4)
        self.page_wrap = tk.Frame(self.content, bg=C["bg"])
        self.page_wrap.grid(row=1, column=0, sticky="nsew")
        self.page_wrap.columnconfigure(0, weight=1)
        self.page_wrap.rowconfigure(0, weight=1)

    def add_page(self, key, icon, title, subtitle):
        f = tk.Frame(self.page_wrap, bg=C["bg"])
        f.grid(row=0, column=0, sticky="nsew")
        body = tk.Frame(f, bg=C["bg"])
        body.pack(fill="both", expand=True, padx=28, pady=(18, 24))
        self.pages[key] = f
        self.titles[key] = (title, subtitle)
        return body

    def show(self, key):
        for k, b in self.nav_btns.items():
            b.set(k == key)
        self.cur = key
        t, s = self.titles.get(key, ("", ""))
        self.top_title.config(text=t)
        self.top_sub.config(text=s)
        self.pages[key].tkraise()

    def set_theme_mode(self, name):
        if name == THEME_NAME[0]:
            return
        m = color_map(THEME_NAME[0], name)
        set_theme(name)
        setup_style(self.root, self.ff)
        self.root.configure(bg=C["bg"])
        for w in self.root.winfo_children():
            if w.winfo_class() == "Toplevel" and w is not self.man_win:
                continue  # cửa sổ test đang mở giữ màu cũ đến khi đóng
            recolor(w, m, {self.side})
        self.style_tree()
        self.theme_sw.paint()
        self.update_summary()
        self.show_detail()
        save_settings(theme=name)

    def open_tests(self):
        w = self.man_win
        w.deiconify()
        w.lift()
        try:
            w.focus_force()
        except Exception:
            pass

    def open_manual_test(self, key, test_fn):
        old_window = self.test_windows.pop(key, None)
        cleanup = self.test_window_cleanups.pop(key, None)
        if old_window is not None and old_window.winfo_exists():
            if cleanup:
                cleanup()
            if old_window.winfo_exists():
                old_window.destroy()

        existing = set(self.root.winfo_children())
        test_fn()
        created = [widget for widget in self.root.winfo_children()
                   if isinstance(widget, tk.Toplevel) and widget not in existing]
        if created:
            window = created[-1]
            self.test_windows[key] = window
            window.bind("<Destroy>", lambda event, k=key, w=window:
                        self.forget_manual_test_window(k, w) if event.widget is w else None, add="+")

    def forget_manual_test_window(self, key, window):
        if self.test_windows.get(key) is window:
            self.test_windows.pop(key, None)
            self.test_window_cleanups.pop(key, None)

    def _wheel(self, e):
        try:
            if e.widget.winfo_toplevel() is self.man_win:
                self.man_cv.yview_scroll(-1 if e.delta > 0 else 1, "units")
        except Exception:
            pass

    def update_summary(self):
        cnt = {"OK": 0, "WARN": 0, "FAIL": 0}
        for a in self.auto:
            if a["status"] in cnt:
                cnt[a["status"]] += 1
        for k, lbl in self.stat_lbls.items():
            lbl.config(text=str(cnt[k]))
        vals = [sv.get() for _, sv, _ in self.manual.values()]
        done = sum(1 for v in vals if v != "Chưa test")
        bad = vals.count("Lỗi")
        auto_txt = "Tự động: %d lỗi, %d cảnh báo" % (cnt["FAIL"], cnt["WARN"]) if self.auto else "Tự động: chưa quét"
        man_txt = "Thủ công: %d/%d đã test, %d lỗi" % (done, len(vals), bad)
        self.side_sum.config(text=auto_txt + "\n" + man_txt)
        self.man_sum.config(text="Đã test %d/%d hạng mục   |   Lỗi: %d" % (done, len(vals), bad))
        self.man_prog["value"] = done
        self.launch_prog["value"] = done
        self.launch_sum.config(text="%d/%d" % (done, len(vals)))
        self.launch_bad.config(text="%d" % bad, fg=C["bad"] if bad else C["muted"])
        self.rep_sum.config(text=auto_txt + "\n" + man_txt)
        col = {"Đạt": C["ok"], "Lỗi": C["bad"]}
        st_of = {"Đạt": "OK", "Lỗi": "FAIL"}
        for key, (_, sv, _) in self.manual.items():
            v = sv.get()
            if key in self.man_cards:
                self.man_cards[key].config(highlightbackground=col.get(v, C["line"]))
            if key in self.chip_lbls:
                bg, fg = chip_colors(st_of.get(v, "INFO"))
                self.chip_lbls[key].config(text=v, bg=bg, fg=fg if v in st_of else (C["dim"] if v == "Chưa test" else C["muted"]))
            if key in self.dot_lbls:
                dot, st = self.dot_lbls[key]
                dot.config(fg=col.get(v, C["dim"] if v == "Chưa test" else C["muted"]))
                st.config(text=v, fg=col.get(v, C["muted"]))

    # ---------------- Trang 1: Thông tin khách ----------------
    def build_customer(self, body):
        body.columnconfigure(0, weight=5, uniform="cu")
        body.columnconfigure(1, weight=6, uniform="cu")
        body.rowconfigure(0, weight=1)
        left, li = section(body, "Thông tin khách hàng", "user", "Nhập khi tiếp nhận máy")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        li.columnconfigure(0, weight=1)
        
        # Đã bổ sung đầy đủ các trường bao gồm model máy và báo giá
        fields = [("ten", "Tên khách hàng"), ("sdt", "Số điện thoại"), 
                  ("model", "Model Máy"), ("pk", "Phụ kiện kèm theo"),
                  ("ktv", "Kỹ thuật viên nhận máy"), ("gia", "Báo Giá (nếu có)"),]
                  
        for i, (k, label) in enumerate(fields):
            mk_label(li, label, "muted").grid(row=i * 2, column=0, sticky="w", pady=(0 if i == 0 else 10, 4))
            v = tk.StringVar()
            ttk.Entry(li, textvariable=v).grid(row=i * 2 + 1, column=0, sticky="we")
            self.info[k] = v
        right = tk.Frame(body, bg=C["bg"])
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        right.columnconfigure(0, weight=1)
        right.rowconfigure(0, weight=1, uniform="cr")
        right.rowconfigure(1, weight=1, uniform="cr")
        for r, (k, title, ic, sub) in enumerate((
                ("khach_bao", "Khách báo tình trạng / lỗi", "warning", "Khách mô tả vấn đề"),
                ("ngoai_hinh", "Ngoại hình lúc nhận", "clipboard", "Trầy, móp, mất ốc..."))):
            c, inn = section(right, title, ic, sub)
            c.grid(row=r, column=0, sticky="nsew", pady=(0, 0) if r == 0 else (16, 0))
            inn.rowconfigure(0, weight=1)
            inn.columnconfigure(0, weight=1)
            t = mk_text(inn, 4)
            t.grid(row=0, column=0, sticky="nsew")
            self.texts[k] = t

    # ---------------- Trang 2: Quét tự động ----------------
    def build_auto(self, body):
        ff = self.ff
        body.columnconfigure(0, weight=1)
        body.rowconfigure(1, weight=3)
        body.rowconfigure(2, weight=2)
        bar = card(body)
        bar.grid(row=0, column=0, sticky="ew")
        bi = tk.Frame(bar, bg=C["card"])
        bi.pack(fill="x", padx=20, pady=16)
        self.stat_lbls = {}
        for key, txt, col in (("FAIL", "LỖI", C["bad"]), ("WARN", "CẢNH BÁO", C["warn"]), ("OK", "ĐẠT", C["ok"])):
            tile, n = stat_tile(bi, txt, col)
            tile.pack(side="right", padx=(10, 0))
            self.stat_lbls[key] = n
        left = tk.Frame(bi, bg=C["card"])
        left.pack(side="left", fill="x", expand=True)
        row = tk.Frame(left, bg=C["card"])
        row.pack(fill="x")
        self.scan_btn = ttk.Button(row, text="▶  Quét tự động toàn bộ", style="Primary.TButton", command=self.start_scan)
        self.scan_btn.pack(side="left")
        self.prog = ttk.Progressbar(row, length=240, maximum=len(SCANS), mode="determinate")
        self.prog.pack(side="left", padx=16)
        self.scan_lbl = tk.Label(left, text="Bấm nút để bắt đầu quét (khoảng 20-40 giây)", bg=C["card"],
                                 fg=C["muted"], font=(ff, 9), anchor="w")
        self.scan_lbl.pack(fill="x", pady=(10, 0))

        tc = card(body)
        tc.grid(row=1, column=0, sticky="nsew", pady=(14, 0))
        cols = ("name", "status", "detail")
        self.tree = ttk.Treeview(tc, columns=cols, show="tree headings", selectmode="browse", height=6)
        self.tree.heading("#0", text="")
        self.tree.column("#0", width=56, minwidth=56, stretch=False, anchor="center")
        for c, t, w, st in (("name", "Hạng mục", 320, False), ("status", "Kết quả", 150, False),
                            ("detail", "Tóm tắt", 500, True)):
            self.tree.heading(c, text=t, anchor="w")
            self.tree.column(c, width=w, anchor="w", stretch=st)
        self.style_tree()
        sb = ttk.Scrollbar(tc, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.show_detail)

        dc = card(body)
        dc.grid(row=2, column=0, sticky="nsew", pady=(14, 0))
        head = tk.Frame(dc, bg=C["card"])
        head.pack(fill="x", padx=20, pady=(14, 6))
        tk.Frame(head, bg=C["primary"], width=4, height=18).pack(side="left", padx=(0, 10))
        self.d_title = tk.Label(head, text="Chọn một dòng để xem chi tiết", bg=C["card"], fg=C["text"],
                                font=(ff, 11, "bold"), anchor="w")
        self.d_title.pack(side="left")
        self.d_pct = tk.Label(head, text="", bg=C["card"], font=(MONO, 12, "bold"))
        self.d_pct.pack(side="right")
        self.d_chip = tk.Label(head, text="", font=(ff, 8, "bold"), padx=10, pady=3)
        self.d_bar = tk.Canvas(dc, height=8, bg=C["card"], highlightthickness=0)
        self.detail_box = tk.Frame(dc, bg=C["card"])
        self.detail_box.pack(fill="both", expand=True, pady=(0, 10))
        dsb = ttk.Scrollbar(self.detail_box, orient="vertical")
        self.detail = tk.Text(self.detail_box, height=5, bd=0, relief="flat", bg=C["card"], fg=C["text"], wrap="word",
                              state="disabled", padx=20, pady=4, font=(ff, 10), highlightthickness=0,
                              yscrollcommand=dsb.set)
        dsb.config(command=self.detail.yview)
        dsb.pack(side="right", fill="y")
        self.detail.tag_configure("verdict", font=(ff, 10, "bold"))
        self.detail.pack(side="left", fill="both", expand=True)

    def style_tree(self):
        for tag, bg, fg in (("OK", C["ok_bg"], C["ok"]), ("INFO", C["card"], C["text"]),
                            ("WARN", C["row_warn_bg"], C["row_warn_fg"]), ("FAIL", C["row_bad_bg"], C["row_bad_fg"])):
            self.tree.tag_configure(tag, background=bg, foreground=fg)

    def start_scan(self):
        self.scan_btn.config(state="disabled")
        self.tree.delete(*self.tree.get_children())
        self.auto = []
        self.prog["value"] = 0
        self.update_summary()
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        for i, (label, fn) in enumerate(SCANS, 1):
            self.q.put(("prog", "Đang kiểm tra: %s (%d/%d)..." % (label, i, len(SCANS))))
            try:
                items = fn()
            except Exception as e:
                items = [S(label, "WARN", "Không đọc được: %s" % e)]
            for it in items:
                self.q.put(("item", it))
            self.q.put(("step", i))
        self.q.put(("done", None))

    def poll(self):
        try:
            while True:
                kind, data = self.q.get_nowait()
                if kind == "prog":
                    self.scan_lbl.config(text=data)
                elif kind == "step":
                    self.prog["value"] = data
                elif kind == "item":
                    self.auto.append(data)
                    st = UI_STATUS[data["status"]]
                    if data.get("pct") is not None:
                        st += "  %d%%" % data["pct"]
                    elif data.get("temp") is not None:
                        st += "  %.0f°C" % data["temp"]
                    self.tree.insert("", "end", image=ico(scan_icon(data["name"]), "r20") or "",
                                     values=(data["name"], st, data["detail"].split("\n")[0]), tags=(data["status"],))
                    self.update_summary()
                elif kind == "done":
                    self.scan_btn.config(state="normal")
                    self.scan_lbl.config(text="Quét xong. Bấm vào từng dòng để xem chi tiết.")
                    self.refresh_gpu_labels()
                elif kind == "gpus":
                    self.refresh_gpu_labels()
        except queue.Empty:
            pass
        self.root.after(150, self.poll)

    def show_detail(self, _e=None):
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        if idx >= len(self.auto):
            return
        a = self.auto[idx]
        col = STATUS_COLOR[a["status"]]
        cbg, cfg = chip_colors(a["status"])
        self.d_title.config(text=a["name"])
        self.d_chip.config(text=STATUS_TEXT[a["status"]].upper(), bg=cbg, fg=cfg)
        self.d_chip.pack(side="left", padx=(12, 0))
        pct = a.get("pct")
        temp = a.get("temp")
        if pct is not None:
            self.d_pct.config(text="%d%%" % pct, fg=col)
            self.d_bar.config(bg=C["card"])
            self.d_bar.pack(fill="x", padx=20, pady=(2, 8), before=self.detail_box)
            self.d_bar.update_idletasks()
            w = max(self.d_bar.winfo_width(), 50)
            self.d_bar.delete("all")
            self.d_bar.create_rectangle(0, 0, w, 8, fill=C["line"], width=0)
            self.d_bar.create_rectangle(0, 0, w * pct / 100.0, 8, fill=col, width=0)
        elif temp is not None:
            self.d_bar.pack_forget()
            self.d_pct.config(text="%.0f°C" % temp, fg=col)
        else:
            self.d_bar.pack_forget()
            self.d_pct.config(text="", fg=col)
        self.detail.config(state="normal")
        self.detail.delete("1.0", "end")
        lines = a["detail"].split("\n")
        self.detail.tag_configure("verdict", font=(self.ff, 10, "bold"), foreground=col)
        if lines and lines[0].startswith("KẾT LUẬN"):
            self.detail.insert("end", lines[0] + "\n", "verdict")
            lines = lines[1:]
        self.detail.insert("end", "\n".join(lines))
        self.detail.config(state="disabled")

    # ---------------- Trang 3: bảng điều khiển + khung test riêng ----------------
    def tests_def(self):
        return [
            ("kb", "Bàn phím", "Bấm từng phím, phím nào sáng xanh là OK", "keyboard", self.test_keyboard),
            ("screen", "Màn hình", "Điểm chết, hở sáng, ám màu", "monitor", self.test_screen),
            ("touchpad", "Touchpad / Chuột", "Click, double-click, kéo, cuộn", "touchpad", self.test_touchpad),
            ("speaker", "Loa", "Phát riêng trái, phải, cả hai", "speaker", self.test_speaker),
            ("mic", "Micro", "Ghi 4 giây rồi phát lại", "mic", self.test_mic),
            ("cam", "Webcam", "Mở ứng dụng Camera xem hình", "camera", self.test_cam),
            ("ram", "Bộ nhớ RAM", "Ghi/đọc 6 mẫu bit trên RAM trống, phát hiện lỗi bit", "ram", self.test_ram),
            ("gpu0", "GPU 0", "Chưa nhận diện - bấm Mở test hoặc quét tự động", "gpu", lambda: self.test_gpu(0)),
            ("gpu1", "GPU 1", "Chưa nhận diện - bấm Mở test hoặc quét tự động", "gpu", lambda: self.test_gpu(1)),
            ("stress", "Chạy tải CPU", "Xem treo, quá nóng, tự tắt, quạt", "gauge", self.test_stress),
            ("usb", "Cổng kết nối", "USB, jack tai nghe, HDMI, khe thẻ nhớ - tự cắm thử", "usb", None),
            ("charge", "Sạc / nguồn", "Cắm sạc có nhận không, đèn báo sạc", "power", None),
            ("body", "Thân máy", "Nút nguồn, đèn LED, bản lề, quạt kêu bất thường", "body", None),
        ]

    def build_launcher(self, body):
        # Trang 'Test lỗi' trong cửa sổ chính: tóm tắt + nút mở khung test riêng.
        ff = self.ff
        body.columnconfigure(0, weight=1)
        top = card(body)
        top.grid(row=0, column=0, sticky="ew")
        inn = tk.Frame(top, bg=C["card"])
        inn.pack(fill="x", padx=24, pady=20)
        for cap, attr, col, w in (("LỖI", "launch_bad", C["bad"], 4), ("ĐÃ TEST", "launch_sum", C["text"], 6)):
            tile, n = stat_tile(inn, cap, col, w)
            tile.pack(side="right", padx=(10, 0))
            setattr(self, attr, n)
        left = tk.Frame(inn, bg=C["card"])
        left.pack(side="left", fill="x", expand=True)
        mk_label(left, "Khung test lỗi riêng", "h2").pack(fill="x")
        mk_label(left, "Phần test được tách thành một cửa sổ riêng để bạn vừa test vừa xem lại thông tin khách / "
                 "kết quả quét ở cửa sổ chính. Kết quả từng hạng mục tự đồng bộ về đây và vào báo cáo.", "muted",
                 wraplength=520, justify="left").pack(fill="x", pady=(4, 12))
        r = tk.Frame(left, bg=C["card"])
        r.pack(fill="x")
        ttk.Button(r, text="⧉  Mở khung test lỗi", style="Primary.TButton", command=self.open_tests).pack(side="left")
        self.launch_prog = ttk.Progressbar(r, length=220, maximum=len(self.tests_def()), mode="determinate")
        self.launch_prog.pack(side="left", padx=16)

        lst, li = section(body, "Trạng thái các hạng mục", "clipboard", "Cập nhật tự động")
        lst.grid(row=1, column=0, sticky="ew", pady=(14, 0))
        for c in range(3):
            li.columnconfigure(c, weight=1, uniform="lc")
        for i, (key, label, hint, icon, fn) in enumerate(self.tests_def()):
            cell = tk.Frame(li, bg=C["card2"], highlightbackground=C["line"], highlightthickness=1)
            cell.grid(row=i // 3, column=i % 3, sticky="we", padx=5, pady=5)
            tk.Label(cell, image=ico(icon, "r20"), bg=C["card2"]).pack(side="left", padx=(10, 0), pady=9)
            nm = tk.Label(cell, text=label, bg=C["card2"], fg=C["text"], font=(ff, 10), anchor="w")
            nm.pack(side="left", padx=(8, 0))
            st = tk.Label(cell, text="Chưa test", bg=C["card2"], fg=C["muted"], font=(ff, 9))
            st.pack(side="right", padx=(0, 12))
            dot = tk.Label(cell, text="●", bg=C["card2"], fg=C["dim"], font=(ff, 9))
            dot.pack(side="right", padx=(0, 6))
            self.dot_lbls[key] = (dot, st)
            self.dot_lbls[key + "_name"] = nm

    def build_manual_window(self):
        ff = self.ff
        tests = self.tests_def()
        win = tk.Toplevel(self.root)
        win.withdraw()
        win.title("HAMTECH | Trung tâm test lỗi")
        win.geometry("1100x820+90+40")
        win.minsize(900, 600)
        win.configure(bg=C["bg"])
        win.protocol("WM_DELETE_WINDOW", win.withdraw)
        try:
            if self.brand_logo:
                win.iconphoto(False, self.brand_logo)
        except Exception:
            pass
        self.man_win = win
        header_bar(win, "clipboard", "Trung tâm test lỗi",
                   "Bấm 'Mở test' ở từng thẻ, rồi chọn Đạt / Lỗi / Bỏ qua").pack(fill="x", padx=22, pady=(18, 10))
        sb = tk.Frame(win, bg=C["bg"])
        sb.pack(fill="x", padx=24, pady=(0, 8))
        self.man_sum = mk_label(sb, "", "bold")
        self.man_sum.pack(side="left")
        self.man_prog = ttk.Progressbar(sb, length=260, maximum=len(tests), mode="determinate")
        self.man_prog.pack(side="right")
        wrap = tk.Frame(win, bg=C["bg"])
        wrap.pack(fill="both", expand=True, padx=16, pady=(0, 14))
        cv = tk.Canvas(wrap, bg=C["bg"], highlightthickness=0)
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=cv.yview)
        cv.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        cv.pack(side="left", fill="both", expand=True)
        g_ = tk.Frame(cv, bg=C["bg"])
        win_id = cv.create_window((0, 0), window=g_, anchor="nw")
        g_.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>", lambda e: cv.itemconfigure(win_id, width=e.width))
        self.man_cv = cv
        for c in (0, 1):
            g_.columnconfigure(c, weight=1, uniform="tc")
        for r, (key, label, hint, icon, fn) in enumerate(tests):
            cd = card(g_)
            cd.grid(row=r // 2, column=r % 2, sticky="nsew", padx=6, pady=6)
            self.man_cards[key] = cd
            head = tk.Frame(cd, bg=C["card"])
            head.pack(fill="x", padx=14, pady=(14, 6))
            box = tk.Frame(head, bg=C["card2"], highlightbackground=C["line"], highlightthickness=1)
            box.pack(side="left")
            tk.Label(box, image=ico(icon, "r40"), bg=C["card2"]).pack(padx=9, pady=9)
            chip = tk.Label(head, text="Chưa test", font=(ff, 8, "bold"), padx=10, pady=3, bg=C["card2"], fg=C["dim"])
            chip.pack(side="right", anchor="n")
            self.chip_lbls[key] = chip
            txt = tk.Frame(head, bg=C["card"])
            txt.pack(side="left", fill="x", expand=True, padx=(12, 8))
            tl = tk.Label(txt, text=label, bg=C["card"], fg=C["text"], font=(ff, 11, "bold"), anchor="w")
            tl.pack(fill="x")
            hl = tk.Label(txt, text=hint, bg=C["card"], fg=C["muted"], font=(ff, 9), anchor="w",
                          justify="left", wraplength=250)
            hl.pack(fill="x")
            self.row_lbls[key] = tl
            self.hints[key] = hl
            tk.Frame(cd, bg=C["line"], height=1).pack(fill="x", padx=14, pady=(6, 0))
            mid = tk.Frame(cd, bg=C["card"])
            mid.pack(fill="x", padx=14, pady=(10, 6))
            if fn:
                ttk.Button(mid, text="Mở test", style="Primary.TButton",
                           command=lambda k=key, callback=fn: self.open_manual_test(k, callback)).pack(
                    side="left", padx=(0, 12))
            else:
                tk.Label(mid, text="tự kiểm tra", bg=C["card"], fg=C["muted"], font=(MONO, 9)).pack(side="left", padx=(0, 12))
            sv = tk.StringVar(value="Chưa test")
            for text, val, sty in (("Đạt", "Đạt", "Ok"), ("Lỗi", "Lỗi", "Bad"), ("Bỏ qua", "Bỏ qua", "Skip")):
                ttk.Radiobutton(mid, text=text, value=val, variable=sv, style=sty + ".Toolbutton").pack(side="left", padx=1)
            nv = tk.StringVar()
            field = tk.Frame(cd, bg=C["card2"], highlightthickness=1,
                             highlightbackground=C["line"], highlightcolor=C["primary"])
            entry = tk.Entry(field, bg=C["card2"], fg=C["dim"], insertbackground=C["text"],
                             relief="flat", bd=0, highlightthickness=0, font=(ff, 9))
            placeholder = "Nhập thông tin"
            entry.insert(0, placeholder)
            entry.pack(fill="x", padx=10, pady=7)

            def on_entry_focus_in(e, ent=entry, outline=field):
                outline.config(highlightbackground=C["primary"])
                if ent.get() == placeholder:
                    ent.delete(0, "end")
                    ent.config(fg=C["text"])

            def on_entry_change(e, ent=entry, var=nv):
                var.set(ent.get())

            def on_entry_focus_out(e, ent=entry, var=nv, outline=field):
                outline.config(highlightbackground=C["line"])
                var.set(ent.get() if ent.get() != placeholder else "")
                if ent.get() == "":
                    ent.insert(0, placeholder)
                    ent.config(fg=C["dim"])

            entry.bind("<FocusIn>", on_entry_focus_in)
            entry.bind("<KeyRelease>", on_entry_change)
            entry.bind("<FocusOut>", on_entry_focus_out)
            field.pack(fill="x", padx=14, pady=(2, 14))
            sv.trace_add("write", lambda *a: self.update_summary())
            self.manual[key] = (label, sv, nv)
            self.manual_entries[key] = entry

        def release_entry_focus(e):
            if e.widget in self.manual_entries.values():
                return

            def clear_if_needed():
                if self.root.focus_get() in self.manual_entries.values():
                    win.focus_set()

            win.after_idle(clear_if_needed)

        win.bind("<Button-1>", release_entry_focus, add="+")

    def mark(self, key, status, note=None):
        _, sv, nv = self.manual[key]
        sv.set(status)
        if note is not None:
            nv.set(note)
            entry = self.manual_entries[key]
            entry.delete(0, "end")
            entry.insert(0, note or "Nhập thông tin nếu có")
            entry.config(fg=C["text"] if note else C["dim"])

    # ---- Test bàn phím ----
    def test_keyboard(self):
        win = tk.Toplevel(self.root)
        win.title("Test bàn phím - bấm từng phím, phím nào sáng xanh là chạy tốt")
        win.configure(bg="#0f172a")
        win.geometry("1000x420")
        keys, names, pressed = {}, {}, set()
        for row in KB_ROWS:
            f = tk.Frame(win, bg="#0f172a")
            f.pack(pady=4)
            for text, kid_, w in row:
                lb = tk.Label(f, text=text, width=max(2, int(w * 4)), height=2, bg="#e2e8f0", fg="#0f172a",
                              relief="flat", font=("Segoe UI", 9, "bold"))
                lb.pack(side="left", padx=2)
                keys[kid_] = lb
                names[kid_] = text
        info = tk.Label(win, text="Hãy bấm lần lượt tất cả các phím", bg="#0f172a", fg="white", font=("Segoe UI", 11))
        info.pack(pady=10)

        def kid(e):
            return e.keysym if e.keysym in MOD_KEYSYMS else e.keycode

        def refresh(e):
            info.config(text="Vừa bấm: %s (mã %s)   |   Đã nhận %d/%d phím" % (e.keysym, e.keycode, len(pressed), len(keys)))

        def down(e):
            k = kid(e)
            if k in keys:
                pressed.add(k)
                keys[k].config(bg="#fbbf24")
            refresh(e)
            return "break"

        def up(e):
            k = kid(e)
            if k in keys:
                keys[k].config(bg="#22c55e")
            return "break"

        def finish():
            missing = [names[k] for k in keys if k not in pressed]
            if missing:
                self.mark("kb", "Lỗi", "Chưa nhận: " + ", ".join(missing))
            else:
                self.mark("kb", "Đạt", "Tất cả %d phím đều nhận" % len(keys))
            win.destroy()

        win.bind("<KeyPress>", down)
        win.bind("<KeyRelease>", up)
        win.protocol("WM_DELETE_WINDOW", finish)
        ttk.Button(win, text="Xong / Đóng", command=finish).pack()
        win.focus_force()

    # ---- Test màn hình ----
    def test_screen(self):
        colors = ["#000000", "#ffffff", "#ff0000", "#00ff00", "#0000ff", "#808080"]
        win = tk.Toplevel(self.root)
        win.attributes("-fullscreen", True)
        win.focus_force()
        idx = [0]
        hint = tk.Label(win, font=("Segoe UI", 12),
                        text="Click trái / Space / → : màu tiếp theo     |     Click phải / Esc : thoát")

        def paint():
            c = colors[idx[0]]
            win.configure(bg=c)
            hint.config(bg=c, fg="#ffffff" if c in ("#000000", "#0000ff", "#ff0000") else "#000000")

        def nxt(_e=None):
            idx[0] += 1
            if idx[0] >= len(colors):
                win.destroy()
                return
            paint()

        hint.pack(side="bottom", pady=10)
        paint()
        win.bind("<Button-1>", nxt)
        win.bind("<space>", nxt)
        win.bind("<Right>", nxt)
        win.bind("<Button-3>", lambda e: win.destroy())
        win.bind("<Escape>", lambda e: win.destroy())

    # ---- Test touchpad / chuột ----
    def test_touchpad(self):
        win = tk.Toplevel(self.root)
        win.title("Test touchpad / chuột")
        win.geometry("760x520")
        names = {"left": "Click trái", "right": "Click phải", "mid": "Click giữa", "dbl": "Double-click",
                 "drag": "Kéo (giữ trái + di)", "up": "Cuộn lên", "down": "Cuộn xuống"}
        lbls, done = {}, set()
        bar = tk.Frame(win)
        bar.pack(fill="x")
        for k, t in names.items():
            lb = tk.Label(bar, text=t, bg=C["card2"], fg=C["text"], padx=6, pady=6, relief="flat")
            lb.pack(side="left", padx=3, pady=4)
            lbls[k] = lb
        cv = tk.Canvas(win, bg=C["card"], highlightthickness=0)
        cv.pack(fill="both", expand=True)
        last = [None]

        def ok(k):
            done.add(k)
            lbls[k].config(bg="#22c55e", fg="#ffffff")

        def motion(e):
            if last[0]:
                cv.create_line(last[0][0], last[0][1], e.x, e.y, fill="#4b5563")
            last[0] = (e.x, e.y)

        def drag(e):
            if last[0]:
                cv.create_line(last[0][0], last[0][1], e.x, e.y, fill=C["primary"], width=3)
            last[0] = (e.x, e.y)
            ok("drag")

        cv.bind("<Motion>", motion)
        cv.bind("<B1-Motion>", drag)
        cv.bind("<Button-1>", lambda e: ok("left"))
        cv.bind("<Button-3>", lambda e: ok("right"))
        cv.bind("<Button-2>", lambda e: ok("mid"))
        cv.bind("<Double-Button-1>", lambda e: ok("dbl"))
        cv.bind("<MouseWheel>", lambda e: ok("up" if e.delta > 0 else "down"))

        def finish():
            miss = [names[k] for k in names if k not in done]
            if miss:
                self.mark("touchpad", "Lỗi", "Chưa nhận: " + ", ".join(miss))
            else:
                self.mark("touchpad", "Đạt", "Đủ click/kéo/cuộn")
            win.destroy()

        win.protocol("WM_DELETE_WINDOW", finish)
        tk.Label(win, text="Di chuột, click, double-click, kéo và cuộn. Nhiều máy không có chuột giữa -> có thể bỏ qua mục đó.",
                 fg=C["muted"]).pack()
        ttk.Button(win, text="Xong / Đóng", command=finish).pack(pady=4)

    # ---- Test loa ----
    def _wav(self, name, left, right):
        if name in self.wavs:
            return self.wavs[name]
        path = os.path.join(tempfile.gettempdir(), "pcc_%s.wav" % name)
        rate, dur, freq = 44100, 1.2, 440
        frames = bytearray()
        for i in range(int(rate * dur)):
            v = int(20000 * math.sin(2 * math.pi * freq * i / rate))
            frames += struct.pack("<hh", v if left else 0, v if right else 0)
        with wave.open(path, "wb") as w:
            w.setnchannels(2)
            w.setsampwidth(2)
            w.setframerate(rate)
            w.writeframes(bytes(frames))
        self.wavs[name] = path
        return path

    def test_speaker(self):
        win = tk.Toplevel(self.root)
        win.title("Test loa")
        win.geometry("460x190")
        tk.Label(win, text="Bấm từng nút, nghe đúng bên, không rè, không rạn.", pady=10).pack()
        row = tk.Frame(win)
        row.pack()
        for name, l, r, text in (("l", 1, 0, "Loa TRÁI"), ("r", 0, 1, "Loa PHẢI"), ("both", 1, 1, "CẢ HAI")):
            ttk.Button(row, text=text, command=lambda n=name, a=l, b=r: winsound.PlaySound(
                self._wav(n, a, b), winsound.SND_FILENAME | winsound.SND_ASYNC)).pack(side="left", padx=6)

        def done(status):
            cancel()
            self.mark("speaker", status)

        def cancel():
            try:
                winsound.PlaySound(None, winsound.SND_PURGE)
            except Exception:
                pass
            win.destroy()

        row2 = tk.Frame(win)
        row2.pack(pady=18)
        ttk.Button(row2, style="Good.TButton", text="Loa tốt", command=lambda: done("Đạt")).pack(side="left", padx=6)
        ttk.Button(row2, style="Danger.TButton", text="Loa lỗi", command=lambda: done("Lỗi")).pack(side="left", padx=6)
        win.protocol("WM_DELETE_WINDOW", cancel)
        self.test_window_cleanups["speaker"] = cancel

    # ---- Test micro ----
    def test_mic(self):
        win = tk.Toplevel(self.root)
        win.title("Test micro")
        win.geometry("460x210")
        cancel_recording = threading.Event()
        lbl = tk.Label(win, text="Bấm 'Ghi âm', nói vài câu trong 4 giây.", pady=10)
        lbl.pack()

        def mci(cmd):
            buf = ctypes.create_unicode_buffer(256)
            return ctypes.windll.winmm.mciSendStringW(cmd, buf, 255, 0)

        def set_lbl(text):
            if lbl.winfo_exists():
                lbl.config(text=text)

        def worker():
            path = os.path.join(tempfile.gettempdir(), "pcc_mic.wav")
            mci("close mic")
            if mci("open new type waveaudio alias mic") != 0:
                self.root.after(0, lambda: set_lbl("Không mở được micro (kiểm tra Cài đặt > Quyền riêng tư > Micro)."))
                return
            mci("record mic")
            if cancel_recording.wait(4):
                mci("stop mic")
                mci("close mic")
                return
            mci("stop mic")
            mci('save mic "%s"' % path)
            mci("close mic")
            self.root.after(0, lambda: set_lbl("Đang phát lại..."))
            winsound.PlaySound(path, winsound.SND_FILENAME)
            self.root.after(0, lambda: set_lbl("Nghe lại có tiếng mình không?"))

        def rec():
            set_lbl("Đang ghi âm 4 giây... hãy nói.")
            threading.Thread(target=worker, daemon=True).start()

        def done(status):
            cancel_recording.set()
            self.mark("mic", status)
            win.destroy()

        def cancel():
            cancel_recording.set()
            try:
                winsound.PlaySound(None, winsound.SND_PURGE)
            except Exception:
                pass
            try:
                mci("stop mic")
                mci("close mic")
            except Exception:
                pass
            win.destroy()

        ttk.Button(win, text="●  Ghi âm", style="Primary.TButton", command=rec).pack(pady=6)
        row = tk.Frame(win)
        row.pack(pady=8)
        ttk.Button(row, style="Good.TButton", text="Micro tốt", command=lambda: done("Đạt")).pack(side="left", padx=6)
        ttk.Button(row, style="Danger.TButton", text="Micro lỗi", command=lambda: done("Lỗi")).pack(side="left", padx=6)
        win.protocol("WM_DELETE_WINDOW", cancel)
        self.test_window_cleanups["mic"] = cancel

    # ---- Webcam ----
    def test_cam(self):
        try:
            os.startfile("microsoft.windows.camera:")
        except Exception:
            messagebox.showinfo("Webcam", "Không mở được ứng dụng Camera. Hãy mở thủ công từ Start > Camera.")
        if messagebox.askyesno("Webcam", "Sau khi xem hình trong ứng dụng Camera:\nWebcam hiện hình rõ, bình thường?"):
            self.mark("cam", "Đạt")
        else:
            self.mark("cam", "Lỗi", "Không lên hình / mờ / lỗi")

    # ---- Test RAM ----
    def test_ram(self):
        win = tk.Toplevel(self.root)
        win.title("Test RAM - ghi / đọc lại / so sánh")
        win.geometry("680x560")
        total, avail = mem_status()
        tk.Label(win, justify="left", wraplength=640, text=(
            "Ghi %d mẫu bit (toàn 0, toàn 1, 10101010, 01010101, ngẫu nhiên, theo địa chỉ) lên phần RAM đang trống "
            "rồi đọc lại so sánh. Bắt được lỗi bit, thanh RAM hỏng, lỗi tiếp xúc khe.\n"
            "RAM tổng %s, đang trống %s. Chỉ test được phần RAM còn trống nên hãy đóng bớt chương trình khác. "
            "Để quét toàn bộ RAM, dùng Windows Memory Diagnostic (nút bên dưới, cần khởi động lại)."
        ) % (len(RAM_PATTERNS), gb(total), gb(avail))).pack(padx=16, pady=(12, 8), anchor="w")
        row = tk.Frame(win)
        row.pack(pady=4)
        tk.Label(row, text="Dùng bao nhiêu % RAM trống:").pack(side="left")
        cb = ttk.Combobox(row, values=["50%", "70%", "80%"], state="readonly", width=6)
        cb.set("70%")
        cb.pack(side="left", padx=6)
        pb = ttk.Progressbar(win, length=620, maximum=100)
        pb.pack(pady=8)
        stv = tk.StringVar(value="Chưa chạy")
        tk.Label(win, textvariable=stv, fg=C["primary"], wraplength=640, justify="left").pack(anchor="w", padx=16)
        log = tk.Text(win, height=12, bd=0, bg=C["card2"], fg=C["text"], state="disabled", highlightthickness=1,
                      highlightbackground=C["line"], font=("Consolas", 9))
        log.pack(fill="both", expand=True, padx=16, pady=8)

        def put(msg):
            log.config(state="normal")
            log.insert("end", msg + "\n")
            log.see("end")
            log.config(state="disabled")

        q = mp.Queue()
        procs = []
        st = dict(workers=0, prog={}, done={}, errors=0, mb=0, t0=0, running=False, pat="", fail=0)

        def stop_all():
            st["running"] = False
            for p in procs:
                try:
                    p.terminate()
                except Exception:
                    pass
            procs.clear()

        def finish():
            st["running"] = False
            secs = time.time() - st["t0"]
            if st["mb"] == 0:
                stv.set("Không test được (không đủ RAM trống). Hãy đóng bớt chương trình rồi thử lại.")
                btn.config(state="normal")
                return
            note = "Đã test %.1f GB RAM trống trong %d giây, %d mẫu bit, %d khối lỗi" % (
                st["mb"] / 1024.0, secs, len(RAM_PATTERNS), st["errors"])
            if st["errors"]:
                stv.set("KẾT QUẢ: PHÁT HIỆN %d KHỐI LỖI - RAM hỏng/không ổn định. " % st["errors"] + note)
                self.mark("ram", "Lỗi", note)
            else:
                stv.set("KẾT QUẢ: ĐẠT, không có lỗi bit. " + note)
                self.mark("ram", "Đạt", note)
            put(stv.get())
            btn.config(state="normal")

        def poll():
            if not win.winfo_exists():
                return
            try:
                while True:
                    m = q.get_nowait()
                    if m[0] == "prog":
                        st["prog"][m[1]] = m[2]
                        st["pat"] = m[3]
                    elif m[0] == "err":
                        put("LỖI worker %d: %s" % (m[1], m[2]))
                    elif m[0] == "done":
                        st["done"][m[1]] = True
                        st["mb"] += m[2]
                        st["errors"] += m[3]
                    elif m[0] == "fail":
                        st["done"][m[1]] = True
                        st["fail"] += 1
                        put("Worker %d: %s" % (m[1], m[2]))
            except queue.Empty:
                pass
            if st["running"]:
                avg = sum(st["prog"].get(i, 0) for i in range(st["workers"])) / max(1, st["workers"])
                pb["value"] = avg * 100
                stv.set("Đang test: mẫu '%s' - %.0f%% - lỗi hiện tại: %d" % (st["pat"], avg * 100, st["errors"]))
                if len(st["done"]) >= st["workers"]:
                    pb["value"] = 100
                    stop_all()
                    finish()
                    return
                win.after(300, poll)

        def start():
            pct = int(cb.get().rstrip("%"))
            _, avail_now = mem_status()
            workers = min(4, os.cpu_count() or 2)
            per = int(avail_now * pct / 100.0 / workers / (1 << 20)) // 32 * 32
            if sys.maxsize <= 2 ** 32:
                per = min(per, 320)
            if per < 64:
                messagebox.showwarning("Test RAM", "RAM trống quá ít để test. Hãy đóng bớt chương trình.", parent=win)
                return
            st.update(workers=workers, prog={}, done={}, errors=0, mb=0, t0=time.time(), running=True, fail=0)
            log.config(state="normal")
            log.delete("1.0", "end")
            log.config(state="disabled")
            put("Bắt đầu: %d tiến trình x %d MB = %.1f GB" % (workers, per, workers * per / 1024.0))
            for i in range(workers):
                p = mp.Process(target=ram_worker, args=(i, per, q), daemon=True)
                p.start()
                procs.append(p)
            btn.config(state="disabled")
            poll()

        def mdsched():
            if messagebox.askyesno("Windows Memory Diagnostic",
                                   "Công cụ này kiểm tra TOÀN BỘ RAM nhưng cần KHỞI ĐỘNG LẠI máy.\n"
                                   "Hãy lưu hết công việc trước. Mở công cụ ngay bây giờ?", parent=win):
                try:
                    subprocess.Popen(["mdsched.exe"])
                    put("Đã mở Windows Memory Diagnostic. Sau khi máy khởi động lại, chạy lại 'Quét tự động' để xem kết quả "
                        "ở mục 'RAM - lịch sử lỗi'.")
                except Exception as e:
                    put("Không mở được mdsched.exe: %s" % e)

        def close():
            stop_all()
            win.destroy()

        brow = tk.Frame(win)
        brow.pack(pady=(0, 12))
        btn = ttk.Button(brow, text="▶  Bắt đầu test RAM", style="Primary.TButton", command=start)
        btn.pack(side="left", padx=4)
        ttk.Button(brow, text="Windows Memory Diagnostic (toàn bộ RAM)", command=mdsched).pack(side="left", padx=4)
        ttk.Button(brow, text="Dừng & đóng", command=close).pack(side="left", padx=4)
        win.protocol("WM_DELETE_WINDOW", close)
        self.test_window_cleanups["ram"] = close

    # ---- Test GPU (từng card: GPU 0 / GPU 1) ----
    def get_gpus(self):
        if not GPU_CACHE:
            self.root.config(cursor="watch")
            self.root.update()
            try:
                list_gpus()
            finally:
                self.root.config(cursor="")
        return GPU_CACHE

    def refresh_gpu_labels(self):
        for n in (0, 1):
            key = "gpu%d" % n
            if key not in self.hints:
                continue
            old = self.manual[key]
            if n < len(GPU_CACHE):
                x = GPU_CACHE[n]
                title = "GPU %d (card %s)" % (n, GPU_CLS_TEXT[x["cls"]])
                hint = x["name"]
                self.manual[key] = (title, old[1], old[2])
                if old[1].get() == "Bỏ qua" and old[2].get() == "Máy không có GPU %d" % n:
                    self.mark(key, "Chưa test", "")
            else:
                title = "GPU %d (không có)" % n
                hint = "Máy chỉ có %d GPU (không có GPU %d)" % (len(GPU_CACHE), n)
                self.manual[key] = (title, old[1], old[2])
                if old[1].get() == "Chưa test":
                    self.mark(key, "Bỏ qua", "Máy không có GPU %d" % n)
            self.row_lbls[key].config(text=title)
            if key + "_name" in self.dot_lbls:
                self.dot_lbls[key + "_name"].config(text=title)
            self.hints[key].config(text=hint[:58])

    def test_gpu(self, n):
        key = "gpu%d" % n
        gpus = self.get_gpus()
        self.refresh_gpu_labels()
        if n >= len(gpus):
            messagebox.showinfo("GPU %d" % n, "Máy chỉ có %d GPU nên không có GPU %d.\nMục này được đánh dấu 'Bỏ qua'." % (
                len(gpus), n))
            self.mark(key, "Bỏ qua", "Máy không có GPU %d" % n)
            return
        tg = gpus[n]
        classes = {x["cls"] for x in gpus}
        pref = {"igpu": "1", "dgpu": "2"}.get(tg["cls"]) if len(classes) > 1 and tg["cls"] in ("igpu", "dgpu") else None
        exe_b = find_browser()
        if not exe_b:
            messagebox.showerror("Test GPU", "Không tìm thấy Microsoft Edge hoặc Google Chrome trên máy này.")
            return
        is_nv = "nvidia" in tg["name"].lower()
        smi = find_nvsmi() if is_nv else None

        win = tk.Toplevel(self.root)
        win.title("Test GPU %d" % n)
        win.geometry("700x720")
        win.configure(bg=C["bg"])
        mk_label(win, "GPU %d: %s" % (n, tg["name"]), "h2", wraplength=650, justify="left").pack(fill="x", padx=22, pady=(18, 0))
        mk_label(win, "Card %s%s" % (GPU_CLS_TEXT[tg["cls"]], "" if pref else " - máy không có 2 loại card khác nhau nên không cần ép"),
                 "muted").pack(fill="x", padx=22, pady=(2, 8))
        mk_label(win, (
            "Bước 1: Xem hiển thị - màn hình chuyển động nhiều màu, tìm sọc, nhiễu, đốm màu, nhấp nháy.\n"
            "Bước 2: Chạy tải GPU thật - phần mềm ép trình duyệt chạy ĐÚNG card này rồi mở cảnh 3D. "
            "Trang tự báo tên GPU đang render, FPS, và đỏ lên nếu GPU bị reset.\n"
            "Chọn mức tải trước khi chạy; mức Nặng dùng 30 lớp/khung hình. Chạy khoảng 2-3 phút, "
            "đóng cửa sổ test rồi chọn kết quả ở đây."),
            "body", wraplength=650, justify="left").pack(fill="x", padx=22)
        row = tk.Frame(win, bg=C["bg"])
        row.pack(fill="x", padx=22, pady=(10, 0))
        mk_label(row, "Mức tải:", "body").pack(side="left")
        lv = ttk.Combobox(row, values=["Nhẹ", "Vừa", "Nặng"], state="readonly", width=8)
        lv.set("Vừa")
        lv.pack(side="left", padx=8)
        ttk.Button(row, text="1. Xem hiển thị", command=lambda: anim()).pack(side="left", padx=(16, 6))
        ttk.Button(row, text="▶  2. Chạy tải GPU thật", style="Primary.TButton", command=lambda: start()).pack(side="left", padx=6)
        box = card(win)
        box.pack(fill="both", expand=True, padx=22, pady=12)
        out = tk.Label(box, text="Chưa chạy test GPU.", bg=C["card"], fg=C["text"], justify="left", anchor="nw",
                       wraplength=620, font=(self.ff, 10))
        out.pack(fill="both", expand=True, padx=14, pady=12)
        st = dict(stats={}, proc=None, srv=None, prev="-", dir=None, on=False, ticking=False, t0=0, level="",
                  tmax=None, pmax=None, umax=None, vmax=None, last=None)

        def sampler():
            while st["on"]:
                rows = nvsmi_query(smi)
                if rows:
                    r = max(rows, key=lambda x: num(x["temperature.gpu"]) or 0)
                    st["last"] = r
                    for k_, f in (("tmax", "temperature.gpu"), ("pmax", "power.draw"),
                                  ("umax", "utilization.gpu"), ("vmax", "memory.used")):
                        v = num(r[f])
                        if v is not None and (st[k_] is None or v > st[k_]):
                            st[k_] = v
                time.sleep(2)

        def verdict():
            """-> (văn bản hiển thị, mã: ok | wrong | soft | lost | err | wait | unk)"""
            s = st["stats"]
            if not s:
                return "Đang chờ cửa sổ test gửi dữ liệu...", "wait"
            lines, code = [], "ok"
            if s.get("error"):
                return "LỖI: %s\nGPU/driver không chạy được WebGL - rất đáng nghi." % s["error"], "err"
            r = str(s.get("renderer", ""))
            lines.append("GPU thực tế đang render: %s" % r)
            if s.get("fps") is not None:
                lines.append("FPS hiện tại %.0f | thấp nhất %.0f | đã chạy %s giây (mức tải %s)" % (
                    s.get("fps", 0), s.get("min", 0), s.get("secs", 0), st["level"] or "-"))
            if s.get("lost"):
                lines.append("[LỖI] GPU BỊ RESET (mất ngữ cảnh WebGL) - GPU/driver mất ổn định.")
                code = "lost"
            low = r.lower()
            if any(k in low for k in ("swiftshader", "llvmpipe", "software", "basic render", "microsoft basic")):
                lines.append("[CẢNH BÁO] Đang render bằng PHẦN MỀM (CPU): GPU không được dùng hoặc không hoạt động.")
                code = "soft" if code == "ok" else code
            else:
                w = gpu_which(r, gpus)
                if w == n:
                    lines.append("[OK] Đã chạy đúng trên GPU %d." % n)
                elif w is not None:
                    lines.append("[CẢNH BÁO] Trình duyệt chạy trên GPU %d (%s), KHÔNG phải GPU %d - kết quả không phản ánh card này." % (
                        w, gpus[w]["name"], n))
                    code = "wrong" if code == "ok" else code
                else:
                    lines.append("[?] Không đối chiếu được tên GPU, hãy so Renderer ở trên với tên GPU %d." % n)
                    code = "unk" if code == "ok" else code
            if st["last"]:
                r2 = st["last"]
                lines.append("Theo dõi nvidia-smi: nhiệt %s°C (cao nhất %s) | tải %s%% | điện %s W | VRAM %s/%s MB" % (
                    r2["temperature.gpu"], "?" if st["tmax"] is None else "%.0f°C" % st["tmax"], r2["utilization.gpu"],
                    r2["power.draw"], r2["memory.used"], r2["memory.total"]))
            elif not is_nv:
                lines.append("Card này không đọc được nhiệt độ/xung bằng phần mềm (Windows không cung cấp) - dùng HWiNFO/GPU-Z nếu cần.")
            elif not smi:
                lines.append("Không tìm thấy nvidia-smi nên không đọc được nhiệt độ/xung (driver NVIDIA chưa đầy đủ?).")
            return "\n".join(lines), code

        def cleanup():
            st["on"] = False
            p = st["proc"]
            if p is not None and p.poll() is None:
                try:
                    subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True, timeout=10,
                                   creationflags=NO_WINDOW)
                except Exception:
                    pass
            if st["srv"]:
                try:
                    st["srv"].shutdown()
                    st["srv"].server_close()
                except Exception:
                    pass
                st["srv"] = None
            if st["prev"] != "-":
                restore_gpu_pref(exe_b, st["prev"])
                st["prev"] = "-"
            if st["dir"]:
                shutil.rmtree(st["dir"], ignore_errors=True)
                st["dir"] = None

        def page():
            draws = {"Nhẹ": 4, "Vừa": 10, "Nặng": 30}[st["level"]]
            return (GPU_HTML.replace("__DRAWS__", str(draws)).replace("__LEVEL__", st["level"])
                    .replace("__PREF__", "low-power" if tg["cls"] == "igpu" else "high-performance"))

        def start():
            p = st["proc"]
            if p is not None and p.poll() is None:
                messagebox.showinfo("Test GPU", "Cửa sổ test đang chạy. Hãy đóng nó trước khi chạy lại.", parent=win)
                return
            cleanup()
            st.update(stats={}, level=lv.get(), t0=time.time(), tmax=None, pmax=None, umax=None, vmax=None, last=None)
            st["dir"] = tempfile.mkdtemp(prefix="pcc_gpu_")
            try:
                st["srv"], port = start_gpu_server(st["stats"], page)
                if pref:
                    st["prev"] = set_gpu_pref(exe_b, pref)
                st["proc"] = subprocess.Popen([exe_b, "--user-data-dir=" + st["dir"], "--no-first-run",
                                               "--no-default-browser-check", "--start-maximized",
                                               "--app=http://127.0.0.1:%d/" % port])
            except Exception as e:
                cleanup()
                out.config(text="Không mở được test: %s" % e)
                return
            if smi:
                st["on"] = True
                threading.Thread(target=sampler, daemon=True).start()
            out.config(text="Đã mở cửa sổ test, đang chờ dữ liệu...")
            if not st["ticking"]:
                st["ticking"] = True
                tick()

        def tick():
            if not win.winfo_exists():
                return
            p = st["proc"]
            if p is not None:
                text, _ = verdict()
                if p.poll() is not None:
                    text = (text if st["stats"] else "Cửa sổ test đã đóng hoặc không mở được. Bấm 'Chạy tải GPU thật' để thử lại.") \
                        + ("\n(Cửa sổ test đã đóng.)" if st["stats"] else "")
                out.config(text=text)
            win.after(1000, tick)

        def anim():
            a = tk.Toplevel(win)
            a.attributes("-fullscreen", True)
            a.configure(bg="black")
            cv = tk.Canvas(a, bg="black", highlightthickness=0)
            cv.pack(fill="both", expand=True)
            a.update_idletasks()
            w, h = a.winfo_width(), a.winfo_height()
            cols = ["#ff0000", "#00ff00", "#0000ff", "#ffff00", "#00ffff", "#ff00ff", "#ffffff", "#808080"]
            nb = 16
            bars = [cv.create_rectangle(i * w / nb, 0, (i + 1) * w / nb, h, fill=cols[i % len(cols)], width=0)
                    for i in range(nb)]
            txt = cv.create_text(w // 2, 30, fill="white", font=("Segoe UI", 14, "bold"),
                                 text="Quan sát sọc/nhiễu/đốm màu/nhấp nháy. Click hoặc Esc để thoát.")
            tk_ = [0]

            def step():
                if not a.winfo_exists():
                    return
                tk_[0] += 1
                for i, b in enumerate(bars):
                    cv.itemconfig(b, fill=cols[(i + tk_[0] // 6) % len(cols)])
                cv.tag_raise(txt)
                a.after(33, step)

            a.bind("<Button-1>", lambda e: a.destroy())
            a.bind("<Escape>", lambda e: a.destroy())
            a.focus_force()
            step()

        def result(ok):
            text, code = verdict()
            s = st["stats"]
            if ok and code in ("wrong", "soft", "lost", "err"):
                if not messagebox.askyesno("Kết quả chưa đáng tin",
                                           text + "\n\nVẫn ghi GPU %d là ĐẠT?" % n, parent=win):
                    return
            parts = []
            if s and s.get("renderer"):
                parts.append(short_renderer(str(s["renderer"])))
                parts.append("tải %s, FPS thấp nhất %.0f" % (st["level"] or "-", s.get("min", 0)))
            elif not st["t0"]:
                parts.append("Chưa chạy tải GPU")
            if st["t0"]:
                parts.append("%d giây" % (time.time() - st["t0"]))
            if st["tmax"] is not None:
                parts.append("nhiệt cao nhất %.0f°C" % st["tmax"])
            if st["pmax"] is not None:
                parts.append("điện cao nhất %.0f W" % st["pmax"])
            flag = {"wrong": "CHẠY SAI GPU", "soft": "RENDER PHẦN MỀM", "lost": "GPU BỊ RESET", "err": "LỖI WEBGL"}.get(code)
            if flag:
                parts.append(flag)
            if ok and st["tmax"] is not None and st["tmax"] >= 90:
                parts.append("LƯU Ý: nhiệt rất cao, nên vệ sinh/thay keo")
            cleanup()
            self.mark(key, "Đạt" if ok else "Lỗi", ", ".join(parts))
            win.destroy()

        def close():
            cleanup()
            win.destroy()

        r2 = tk.Frame(win, bg=C["bg"])
        r2.pack(fill="x", padx=22, pady=(0, 18))
        ttk.Button(r2, style="Good.TButton", text="GPU %d tốt" % n, command=lambda: result(True)).pack(side="left")
        ttk.Button(r2, style="Danger.TButton", text="GPU %d lỗi" % n, command=lambda: result(False)).pack(side="left", padx=8)
        ttk.Button(r2, text="Đóng (chưa kết luận)", command=close).pack(side="right")
        win.bind("<Destroy>", lambda e: cleanup() if e.widget is win else None)
        win.protocol("WM_DELETE_WINDOW", close)
        self.test_window_cleanups[key] = close

    # ---- Stress CPU ----
    # ---- Stress CPU (hiển thị nhiệt độ Realtime) ----
    def test_stress(self):
        win = tk.Toplevel(self.root)
        win.title("Chạy tải CPU (Stress Test)")
        win.geometry("500x340")
        win.configure(bg=C["bg"])
        tk.Label(win, text="Chạy 100% tất cả nhân CPU. Quan sát: máy có đơ, tự tắt, quạt kêu bất thường, nóng quá mức?",
                 wraplength=460, pady=10, bg=C["bg"], fg=C["text"]).pack()

        # Khung hiển thị nhiệt độ trực tiếp (Realtime)
        tbox = card(win)
        tbox.pack(fill="x", padx=20, pady=(0, 10))
        trow = tk.Frame(tbox, bg=C["card"])
        trow.pack(fill="x", padx=14, pady=(10, 4))

        cur_lbl = tk.Label(trow, text="Hiện tại: --°C", bg=C["card"], fg=C["ok"],
                           font=(MONO, 16, "bold"))
        cur_lbl.pack(side="left")
        max_lbl = tk.Label(trow, text="Cao nhất: --°C", bg=C["card"], fg=C["muted"],
                           font=(MONO, 13, "bold"))
        max_lbl.pack(side="right")

        cores_lbl = tk.Label(tbox, text="Đang kết nối Core Temp...", bg=C["card"], fg=C["muted"],
                             font=(self.ff, 9), wraplength=430, justify="left", anchor="w")
        cores_lbl.pack(fill="x", padx=14, pady=(0, 10))

        # Chọn thời gian chạy tải
        cfg_row = tk.Frame(win, bg=C["bg"])
        cfg_row.pack(pady=4)
        tk.Label(cfg_row, text="Thời gian test:", bg=C["bg"], fg=C["text"]).pack(side="left", padx=(0, 6))
        cb = ttk.Combobox(cfg_row, values=["30", "60", "120", "300"], state="readonly", width=6)
        cb.set("60")
        cb.pack(side="left")
        tk.Label(cfg_row, text="giây", bg=C["bg"], fg=C["text"]).pack(side="left", padx=(6, 0))

        status = tk.StringVar(value="Chưa chạy tải (đang theo dõi nhiệt độ lúc nghỉ)")
        tk.Label(win, textvariable=status, fg=C["primary"], bg=C["bg"],
                 font=(self.ff, 10, "bold"), wraplength=460).pack(pady=8)

        procs = []
        st = {"end": 0, "running": False, "max": None, "sec": 60}

        # Tự bật ngầm Core Temp nếu chưa mở
        threading.Thread(target=get_coretemp_readings, daemon=True).start()

        def temp_color(t):
            return C["ok"] if t < 70 else (C["warn"] if t < 85 else C["bad"])

        def update_live_temp():
            if not win.winfo_exists():
                return
            temps = _read_coretemp_memory()
            if temps:
                t_cur = max(temps)
                t_avg = sum(temps) / len(temps)
                if st["max"] is None or t_cur > st["max"]:
                    st["max"] = t_cur
                cur_lbl.config(text="Hiện tại: %.0f°C" % t_cur, fg=temp_color(t_cur))
                max_lbl.config(text="Cao nhất: %.0f°C" % st["max"], fg=temp_color(st["max"]))
                cores_txt = ", ".join("%.0f°" % t for t in temps[:16])
                if len(temps) > 16:
                    cores_txt += "..."
                cores_lbl.config(text="TB: %.0f°C  |  %d nhân: %s" % (t_avg, len(temps), cores_txt))
            else:
                cur_lbl.config(text="Hiện tại: --°C", fg=C["muted"])
                cores_lbl.config(text="Chưa đọc được Core Temp (kiểm tra tools\\Core Temp\\Core Temp.exe)")

            if st["running"]:
                left = st["end"] - time.time()
                if left <= 0:
                    finish()
                    return
                status.set("🔥 Đang chạy 100%% CPU... còn %d giây" % int(math.ceil(left)))

            win.after(500, update_live_temp)

        def stop_all():
            st["running"] = False
            for p in procs:
                try:
                    p.terminate()
                except Exception:
                    pass
            procs.clear()

        def finish():
            stop_all()
            if not win.winfo_exists():
                return
            temp = "không đọc được nhiệt độ" if st["max"] is None else "nhiệt độ cao nhất %.0f°C" % st["max"]
            note = "Chạy %ds, %s" % (st["sec"], temp)
            status.set("Đã chạy xong (%s)" % temp)
            ok = messagebox.askyesno(
                "Kết quả",
                "Test xong (%s).\nMáy chạy ổn định, không đơ/tự tắt/quạt bất thường?" % temp,
                parent=win
            )
            self.mark("stress", "Đạt" if ok else "Lỗi", note)
            win.destroy()

        def start():
            st["sec"] = int(cb.get())
            n = os.cpu_count() or 2
            for _ in range(n):
                p = mp.Process(target=burn, args=(st["sec"],), daemon=True)
                p.start()
                procs.append(p)
            # Reset lại mốc cao nhất để tính riêng trong lúc full-load
            temps = _read_coretemp_memory()
            st.update(end=time.time() + st["sec"], running=True, max=max(temps) if temps else None)
            btn.config(state="disabled")
            cb.config(state="disabled")

        brow = tk.Frame(win, bg=C["bg"])
        brow.pack(pady=4)
        btn = ttk.Button(brow, text="▶  Bắt đầu", style="Primary.TButton", command=start)
        btn.pack(side="left", padx=6)

        def cancel():
            stop_all()
            win.destroy()

        ttk.Button(brow, text="Dừng & đóng", command=cancel).pack(side="left", padx=6)
        win.protocol("WM_DELETE_WINDOW", cancel)
        tk.Label(win, text="Nếu máy tự tắt giữa chừng -> ghi 'Lỗi: tự tắt khi tải' ở khung Test lỗi.",
                 fg=C["muted"], bg=C["bg"]).pack(pady=(6, 0))
        self.test_window_cleanups["stress"] = cancel

        update_live_temp()

    # ---------------- Trang 4 ----------------
    def build_report(self, body):
        ff = self.ff
        body.columnconfigure(0, weight=2, uniform="rp")
        body.columnconfigure(1, weight=3, uniform="rp")
        body.rowconfigure(0, weight=1)
        left, li = section(body, "Tóm tắt & Quản lý báo cáo", "report", "Phiên làm việc")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.rep_sum = tk.Label(li, text="", bg=C["card"], fg=C["text"], justify="left", anchor="w", font=(ff, 10))
        self.rep_sum.pack(fill="x")
        
        ttk.Button(li, text="Tạo báo cáo và nhúng mã QR", style="Primary.TButton", command=self.make_report).pack(
            fill="x", pady=(20, 8))
        ttk.Button(li, text="Mở thư mục báo cáo", command=self.open_folder).pack(fill="x", pady=(0, 8))
        ttk.Button(li, text="So sánh 2 báo cáo", command=self.compare_reports).pack(fill="x")
        
        self.rep_lbl = tk.Label(li, text="", bg=C["card"], fg=C["ok"], anchor="w", wraplength=330, justify="left",
                                font=(ff, 9))
        self.rep_lbl.pack(fill="x", pady=(12, 0))
        mk_label(li, "Báo cáo là file HTML mở bằng trình duyệt. Phiếu xuất ra sẽ tự động đi kèm 1 Mã QR Tình Trạng Máy. "
                 "Khách hàng có thể dùng Zalo quét mã QR này để xem trực tuyến thông số và lỗi của máy mà không sợ mất giấy biên nhận.",
                 "muted", wraplength=330, justify="left").pack(fill="x", pady=(14, 0))
        right, ri = section(body, "Ghi chú chung", "clipboard", "Hiện trong báo cáo")
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        t = mk_text(ri, 8)
        t.pack(fill="both", expand=True)
        self.texts["ghichu"] = t

    def report_dir(self):
        base = os.path.dirname(sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__))
        d = os.path.join(base, "BaoCao")
        try:
            os.makedirs(d, exist_ok=True)
            test = os.path.join(d, ".w")
            open(test, "w").close()
            os.remove(test)
        except Exception:
            d = os.path.join(os.path.expanduser("~"), "Documents", "PCCheckIn_BaoCao")
            os.makedirs(d, exist_ok=True)
        return d

    def open_folder(self):
        os.startfile(self.report_dir())

    def compare_reports(self):
        win = tk.Toplevel(self.root)
        win.title("So sánh báo cáo")
        win.geometry("760x300")
        win.minsize(650, 270)
        win.configure(bg=C["bg"])
        win.transient(self.root)
        header_bar(win, "report", "So sánh 2 báo cáo", "Chọn hai phiếu HTML đã xuất").pack(
            fill="x", padx=20, pady=(18, 14))

        form = tk.Frame(win, bg=C["bg"])
        form.pack(fill="x", padx=24)
        form.columnconfigure(1, weight=1)
        paths = []

        def choose_file(path_var):
            selected = filedialog.askopenfilename(
                parent=win, title="Chọn báo cáo HTML", initialdir=self.report_dir(),
                filetypes=(("Báo cáo HTML", "*.html"), ("Tất cả tệp", "*.*")))
            if selected:
                path_var.set(selected)

        for row, label in enumerate(("Báo cáo cũ", "Báo cáo mới")):
            path_var = tk.StringVar()
            paths.append(path_var)
            mk_label(form, label, "bold").grid(row=row, column=0, sticky="w", padx=(0, 12), pady=8)
            ttk.Entry(form, textvariable=path_var, state="readonly").grid(
                row=row, column=1, sticky="ew", pady=8)
            ttk.Button(form, text="Chọn tệp...", command=lambda value=path_var: choose_file(value)).grid(
                row=row, column=2, padx=(8, 0), pady=8)

        ttk.Button(win, text="So sánh", style="Primary.TButton",
                   command=lambda: self.create_report_comparison(paths[0].get(), paths[1].get(), win)).pack(
            anchor="e", padx=24, pady=(16, 20))
        win.bind("<Escape>", lambda _event: win.destroy())

    def create_report_comparison(self, old_path, new_path, parent):
        if not old_path or not new_path:
            messagebox.showwarning("So sánh báo cáo", "Hãy chọn đủ báo cáo cũ và báo cáo mới.", parent=parent)
            return
        if os.path.normcase(os.path.abspath(old_path)) == os.path.normcase(os.path.abspath(new_path)):
            messagebox.showwarning("So sánh báo cáo", "Hãy chọn hai báo cáo khác nhau.", parent=parent)
            return

        def read_report(path):
            parser = CheckinReportParser()
            with open(path, "r", encoding="utf-8-sig", errors="replace") as report_file:
                parser.feed(report_file.read())
            if not any(parser.data[category] for category in ("customer", "auto", "manual")):
                raise ValueError("Không nhận diện được nội dung báo cáo PC Check-in.")
            return parser.data

        try:
            old_data = read_report(old_path)
            new_data = read_report(new_path)
        except (OSError, ValueError) as error:
            messagebox.showerror("So sánh báo cáo", "Không đọc được báo cáo:\n%s" % error, parent=parent)
            return

        e = html.escape
        comparisons = {"unchanged": 0, "changed": 0, "added": 0, "removed": 0}
        categories = (("auto", "Kiểm tra tự động"), ("manual", "Kiểm tra thủ công"))
        sections = []
        for category, title in categories:
            old_items = old_data[category]
            new_items = new_data[category]
            names = list(old_items) + [name for name in new_items if name not in old_items]
            rows = []
            for name in names:
                old_item = old_items.get(name)
                new_item = new_items.get(name)
                if old_item is None:
                    change, css_class = "Mục mới", "added"
                elif new_item is None:
                    change, css_class = "Không còn", "removed"
                elif old_item == new_item:
                    change, css_class = "Không đổi", "unchanged"
                else:
                    status_changed = old_item["status"] != new_item["status"]
                    detail_changed = old_item["detail"] != new_item["detail"]
                    if status_changed and detail_changed:
                        change = "Đổi kết quả và ghi chú"
                    elif status_changed:
                        change = "Đổi kết quả"
                    else:
                        change = "Ghi chú thay đổi"
                    css_class = "changed"
                comparisons[css_class] += 1
                old_item = old_item or {}
                new_item = new_item or {}
                rows.append("<tr class='%s'><th>%s</th><td>%s</td><td>%s</td><td>%s</td>"
                            "<td>%s</td><td>%s</td></tr>" % (
                    css_class, e(name), e(old_item.get("status", "—")), e(new_item.get("status", "—")),
                    e(old_item.get("detail", "—")).replace("\n", "<br>"),
                    e(new_item.get("detail", "—")).replace("\n", "<br>"), e(change)))
            if rows:
                sections.append("<h2>%s</h2><table><thead><tr><th>Hạng mục</th><th>Báo cáo cũ</th>"
                                "<th>Báo cáo mới</th><th>Chi tiết cũ</th><th>Chi tiết mới</th>"
                                "<th>Đối chiếu</th></tr></thead><tbody>%s</tbody></table>" % (title, "".join(rows)))
            else:
                sections.append("<h2>%s</h2><p>Hai báo cáo không có dữ liệu ở mục này.</p>" % title)

        customer_rows = []
        customer_names = list(old_data["customer"]) + [
            name for name in new_data["customer"] if name not in old_data["customer"]]
        for name in customer_names:
            old_value = old_data["customer"].get(name, "—")
            new_value = new_data["customer"].get(name, "—")
            change = "Không đổi" if old_value == new_value else "Thay đổi"
            if change == "Thay đổi":
                comparisons["changed"] += 1
            customer_rows.append("<tr class='%s'><th>%s</th><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                "unchanged" if change == "Không đổi" else "changed", e(name), e(old_value), e(new_value), e(change)))
        if customer_rows:
            sections.insert(0, "<h2>Thông tin khách hàng và máy</h2><table><thead><tr><th>Thông tin</th>"
                            "<th>Báo cáo cũ</th><th>Báo cáo mới</th><th>Đối chiếu</th></tr></thead><tbody>%s</tbody></table>"
                            % "".join(customer_rows))

        now = datetime.datetime.now()
        summary = ("<div class='summary'><b>%d thay đổi</b><span>%d mục mới</span>"
                   "<span>%d mục không còn</span><span>%d mục không đổi</span></div>" % (
                       comparisons["changed"], comparisons["added"], comparisons["removed"],
                       comparisons["unchanged"]))
        document = "".join((
            "<!DOCTYPE html><html lang='vi'><head><meta charset='utf-8'>"
            "<title>So sánh báo cáo PC Check-in</title><style>",
            "body{font-family:'Segoe UI',sans-serif;max-width:1200px;margin:28px auto;padding:0 20px;color:#20242b}",
            "h1{font-size:24px;margin:0}h2{margin-top:28px;border-bottom:2px solid #d71920;padding-bottom:7px}",
            ".meta{color:#596273;margin:8px 0 20px}.summary{display:flex;gap:22px;flex-wrap:wrap;"
            "background:#f3f5f7;padding:14px;margin:18px 0}.summary b{color:#c5161d}",
            "table{width:100%;border-collapse:collapse;margin:12px 0 24px}th,td{border:1px solid #d8dce2;"
            "padding:9px;text-align:left;vertical-align:top}thead th{background:#20242b;color:#fff}"
            "tbody th{width:18%}.changed{background:#fff2d5}.added{background:#e7f5eb}"
            ".removed{background:#fde9e9}.unchanged{color:#596273}",
            "@media print{body{margin:0;max-width:none;padding:0 8px}tr{break-inside:avoid}}",
            "</style></head><body><h1>Đối chiếu hai báo cáo PC Check-in</h1>",
            "<p class='meta'>Báo cáo cũ: %s<br>Báo cáo mới: %s<br>Ngày so sánh: %s</p>" % (
                e(os.path.basename(old_path)), e(os.path.basename(new_path)), now.strftime("%d/%m/%Y %H:%M")),
            summary, "".join(sections), "</body></html>"))
        output_path = os.path.join(self.report_dir(), "SoSanh_%s.html" % now.strftime("%Y%m%d_%H%M%S"))
        try:
            with open(output_path, "w", encoding="utf-8") as output_file:
                output_file.write(document)
            self.rep_lbl.config(text="Đã lưu kết quả so sánh: " + output_path)
            os.startfile(output_path)
            parent.destroy()
        except OSError as error:
            messagebox.showerror("So sánh báo cáo", "Không lưu/mở được kết quả:\n%s" % error, parent=parent)

    def make_report(self):
        e = html.escape
        now = datetime.datetime.now()
        info = {k: v.get().strip() for k, v in self.info.items()}
        txt = {k: t.get("1.0", "end").strip() for k, t in self.texts.items()}
        colors = {"Đạt": "#2e7d32", "Lỗi": "#c62828", "Cảnh báo": "#ef6c00", "Thông tin": "#455a64",
                  "Chưa test": "#9e9e9e", "Bỏ qua": "#9e9e9e"}

        def badge(s):
            return '<span class="b" style="background:%s">%s</span>' % (colors.get(s, "#555"), e(s))

        fails = sum(1 for a in self.auto if a["status"] == "FAIL") + sum(1 for _, sv, _ in self.manual.values() if sv.get() == "Lỗi")
        warns = sum(1 for a in self.auto if a["status"] == "WARN")

        model_name = info.get("model", "Không rõ")
        bao_gia = info.get("gia", "Chưa có")

        # Nội dung mã QR gọn gàng, chuẩn thông tin tiệm
        qr_text = (
            "HAMTECH - Tiep Nhan May\n"
            "Hotline: 0888 123 223\n"
            "Date: %s\n"
            "KH: %s\n"
            "SDT: %s\n"
            "Model: %s\n"
            "Error: %d, Warning: %d\n"
            "Phu Kien: %s\n"
            "KTV: %s\n"
            "Bao gia: %s\n"
        ) % (
            now.strftime("%d/%m/%Y %H:%M"),
            info.get("ten", "Khách lẻ"),
            info.get("sdt", "Không có"),
            model_name,
            fails,
            warns,
            info.get("pk", "Không có"),
            info.get("ktv", "KTV"),
            bao_gia
        )

        qrious_code = ""
        js_path = find_qrious_js()
        if js_path and os.path.isfile(js_path):
            try:
                with open(js_path, "r", encoding="utf-8", errors="ignore") as jf:
                    qrious_code = jf.read()
            except Exception:
                pass

        h = ["<!DOCTYPE html><html lang='vi'><head><meta charset='utf-8'><title>Phiếu kiểm tra máy</title>",
             # Nhúng trực tiếp mã nguồn qrious cục bộ vào thẻ script để chạy offline 100%
             "<script>%s</script>" % qrious_code,
             "<style>",
             "body{font-family:Segoe UI,Arial,sans-serif;max-width:900px;margin:20px auto;color:#222;padding:0 12px}",
             "h1{margin:0;font-size:22px}h2{border-bottom:2px solid #d0121b;padding-bottom:4px;margin-top:26px}",
             ".brand{display:flex;align-items:center;justify-content:space-between;border-bottom:4px solid #d0121b;padding-bottom:12px;margin-bottom:6px}",
             ".brand-left{display:flex;align-items:center;gap:18px}",
             ".brand img{height:78px}.brand p{margin:4px 0 0;color:#555}",
             ".qr-box{text-align:center;font-size:12px;font-weight:bold;color:#333}",
             ".qr-box canvas{width:130px!important;height:130px!important;display:block;margin:0 auto 4px}",
             "table{width:100%;border-collapse:collapse}td,th{border:1px solid #ccc;padding:6px 8px;vertical-align:top;font-size:14px}",
             ".bar{height:10px;background:#e0e0e0;border-radius:5px;margin-top:6px}.bar i{display:block;height:10px;border-radius:5px}",
             "th{background:#f6eeee;text-align:left}.b{color:#fff;padding:2px 8px;border-radius:10px;font-size:12px;white-space:nowrap}",
             ".sign{display:flex;gap:40px;margin-top:50px}.sign div{flex:1;text-align:center;border-top:1px solid #333;padding-top:6px}",
             "@media print{body{margin:0}}</style></head><body>",
             "<div class='brand'><div class='brand-left'><img alt='HAMTECH' src='data:image/png;base64,%s'><div>"
             "<h1>PHIẾU KIỂM TRA MÁY KHI NHẬN</h1><p>HAMTECH - Đánh thức tương lai &nbsp;|&nbsp; Ngày giờ: %s</p>"
             "</div></div><div class='qr-box'><canvas id='qrcode'></canvas>Mã QR điện tử</div></div>" % (LOGO_B64, now.strftime("%d/%m/%Y %H:%M"))]
        
        h.append("<h2>Thông tin khách hàng</h2><table>")
        for k, label in (("ten", "Tên khách hàng"), ("sdt", "Số điện thoại"), ("ma", "Mã phiếu / Mã máy"),
                         ("model", "Model Máy"), ("pk", "Phụ kiện kèm theo"), ("ktv", "Kỹ thuật viên"), ("gia", "Báo Giá")):
            val = info.get(k, "")
            if val:
                h.append("<tr><th width='30%%'>%s</th><td>%s</td></tr>" % (label, e(val)))
        
        h.append("<tr><th>Khách báo tình trạng</th><td>%s</td></tr>" % e(txt.get("khach_bao", "")).replace("\n", "<br>"))
        h.append("<tr><th>Ngoại hình lúc nhận</th><td>%s</td></tr></table>" % e(txt.get("ngoai_hinh", "")).replace("\n", "<br>"))
        h.append("<h2>Tóm tắt</h2><p>Hạng mục <b style='color:#c62828'>lỗi</b>: %d &nbsp;|&nbsp; "
                 "<b style='color:#ef6c00'>cảnh báo</b>: %d</p>" % (fails, warns))
        h.append("<h2>Kiểm tra tự động</h2>")
        if self.auto:
            h.append("<table><tr><th>Hạng mục</th><th>Kết quả</th><th>Chi tiết</th></tr>")
            for a in self.auto:
                bar = ""
                if a.get("pct") is not None:
                    col = {"OK": "#2e7d32", "WARN": "#ef6c00", "FAIL": "#c62828"}.get(a["status"], "#455a64")
                    bar = "<div class='bar'><i style='width:%d%%;background:%s'></i></div>" % (a["pct"], col)
                h.append("<tr><td>%s</td><td>%s</td><td>%s%s</td></tr>" % (
                    e(a["name"]), badge(STATUS_TEXT[a["status"]]), e(a["detail"]).replace("\n", "<br>"), bar))
            h.append("</table>")
        else:
            h.append("<p><i>Chưa chạy quét tự động.</i></p>")
        h.append("<h2>Kiểm tra thủ công</h2><table><tr><th>Hạng mục</th><th>Kết quả</th><th>Ghi chú</th></tr>")
        for label, sv, nv in self.manual.values():
            h.append("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (e(label), badge(sv.get()), e(nv.get())))
        h.append("</table>")
        if txt.get("ghichu"):
            h.append("<h2>Ghi chú chung</h2><p>%s</p>" % e(txt["ghichu"]).replace("\n", "<br>"))
        h.append("<p style='margin-top:20px;font-size:13px;color:#555'>Khách hàng xác nhận tình trạng máy như trên "
                 "tại thời điểm giao nhận, trước khi vệ sinh/sửa chữa.</p>")
        h.append("<div class='sign'><div>Khách hàng ký</div><div>Kỹ thuật viên ký</div></div>")
        
        # Render mã QR ngoại tuyến với kích thước lớn (size: 260)
        h.append("<script>new QRious({element: document.getElementById('qrcode'), value: %s, size: 260});</script>" % json.dumps(qr_text))
        h.append("</body></html>")

        name = "".join(c for c in (info.get("ma") or info.get("ten") or "may") if c.isalnum() or c in "-_") or "may"
        path = os.path.join(self.report_dir(), "%s_%s.html" % (name, now.strftime("%Y%m%d_%H%M%S")))
        with open(path, "w", encoding="utf-8") as f:
            f.write("".join(h))
        
        # Bổ sung cảnh báo nhẹ nếu lỡ quên chép file qrious.min.js vào tools
        if not qrious_code:
            self.rep_lbl.config(text="Đã lưu báo cáo (Thiếu qrious.min.js trong tools!): " + path)
        else:
            self.rep_lbl.config(text="Đã lưu báo cáo kèm QR Offline chuẩn: " + path)
        os.startfile(path)


def main():
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    mp.freeze_support()
    main()
