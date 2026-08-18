module binary_tailor.ape;

import std.algorithm : min;
import std.array : appender;
import std.conv : to;
import std.regex;

/// Decode APE shell `printf '\177ELF...'` octal blobs in the first 8 KiB.
/// See Cosmopolitan `ape/specification.md`.
ubyte[][] decodePrintfElfHeaders(const(ubyte)[] page)
{
    ubyte[][] outHdrs;
    auto n = min(page.length, 8192);
    auto text = cast(string) page[0 .. n];
    // printf '....'
    auto rx = regex(`printf\s+'((?:\\[0-7]{1,3}|[^'\\])*)'`);
    foreach (c; matchAll(text, rx))
    {
        auto decoded = decodeOctalCString(c.hit.length > 0 ? c[1] : "");
        if (decoded.length >= 16 && decoded[0] == 0x7f && decoded[1] == 'E' && decoded[2] == 'L'
            && decoded[3] == 'F')
            outHdrs ~= decoded;
    }
    return outHdrs;
}

ubyte[] decodeOctalCString(string s)
{
    auto buf = appender!(ubyte[]);
    size_t i;
    while (i < s.length)
    {
        if (s[i] == '\\' && i + 1 < s.length && s[i + 1] >= '0' && s[i + 1] <= '7')
        {
            int c = 0;
            int k;
            i++;
            while (k < 3 && i < s.length && s[i] >= '0' && s[i] <= '7')
            {
                c = c * 8 + (s[i] - '0');
                i++;
                k++;
            }
            buf.put(cast(ubyte) c);
        }
        else
        {
            buf.put(cast(ubyte) s[i]);
            i++;
        }
    }
    return buf.data;
}

struct DdWindow
{
    ulong bs;
    ulong skip;
    ulong count;
}

/// Parse `dd ... bs=N skip=N count=N` from the APE stub (Mach-O x86-64 header copy).
DdWindow[] decodeDdWindows(const(ubyte)[] page)
{
    DdWindow[] windows;
    auto n = min(page.length, 8192);
    auto text = cast(string) page[0 .. n];
    auto rx = regex(
        `bs=(?:['"] *)?(?:\$\(\( *)?(\d+)(?: *\)\))?(?: *['"])? +skip=(?:['"] *)?(?:\$\(\( *)?(\d+)(?: *\)\))?(?: *['"])? +count=(?:['"] *)?(?:\$\(\( *)?(\d+)`);
    foreach (c; matchAll(text, rx))
    {
        DdWindow w;
        w.bs = c[1].to!ulong;
        w.skip = c[2].to!ulong;
        w.count = c[3].to!ulong;
        windows ~= w;
    }
    return windows;
}

ubyte[] sliceDd(const(ubyte)[] file, DdWindow w)
{
    const off = w.bs * w.skip;
    const len = w.bs * w.count;
    if (off > file.length || off + len > file.length)
        throw new Exception("APE dd window exceeds file");
    return file[cast(size_t) off .. cast(size_t)(off + len)].dup;
}

/// Rewrite a copy of `file` so the host loader sees a conventional ELF or Mach-O header at offset 0.
ubyte[] assimilate(const(ubyte)[] file, string os, string arch)
{
    auto page = file[0 .. min(file.length, 8192)];
    auto outb = file.dup;
    if (os == "linux" || os == "freebsd" || os == "openbsd" || os == "netbsd")
    {
        auto hdrs = decodePrintfElfHeaders(page);
        if (hdrs.length == 0)
            throw new Exception("no embedded ELF printf header in APE stub");
        auto want = (arch == "arm64") ? 0xB7 : 0x3E; // EM_AARCH64 / EM_X86_64
        ubyte[] picked;
        foreach (h; hdrs)
        {
            if (h.length >= 19)
            {
                auto em = h[18] | (h[19] << 8);
                if (em == want)
                {
                    picked = h;
                    break;
                }
            }
        }
        if (picked.length == 0)
            picked = hdrs[0];
        if (picked.length > outb.length)
            throw new Exception("ELF header longer than file");
        outb[0 .. picked.length] = picked;
        return outb;
    }
    if (os == "macos")
    {
        auto dds = decodeDdWindows(page);
        if (dds.length)
        {
            auto hdr = sliceDd(file, dds[0]);
            if (hdr.length > outb.length)
                throw new Exception("Mach-O header longer than file");
            outb[0 .. hdr.length] = hdr;
            return outb;
        }
        throw new Exception(
            "no Mach-O dd window in APE stub (ARM64 APE often uses the ELF header; try linux assimilate or pack payloads)");
    }
    if (os == "windows")
    {
        // Already MZ/PE. Optionally blank the shell-script comment after the stub
        // so heuristic scanners see fewer polyglot strings. Keep a valid PE.
        return outb;
    }
    throw new Exception("unsupported assimilate target " ~ os ~ "-" ~ arch);
}

ushort elfMachine(const(ubyte)[] ehdr)
{
    if (ehdr.length < 20)
        return 0;
    return cast(ushort)(ehdr[18] | (ehdr[19] << 8));
}
