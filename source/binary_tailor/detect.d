module binary_tailor.detect;

import std.algorithm : canFind, min;
import std.conv : to;
import std.string : startsWith;

enum Kind
{
    unknown,
    ape,
    pe,
    elf,
    macho,
    machoFat,
    zip,
    pack, // our ZIP + manifest.sdl
}

struct Scan
{
    Kind[] kinds;
    bool apeMz;
    bool apeUnix;
    bool apeDbg;
    bool pe;
    bool elf;
    bool macho;
    bool machoFat;
    bool zip;
    bool pack;
    size_t elfOff = size_t.max;
    size_t machoOff = size_t.max;
    size_t peOff = size_t.max;
    string summary;
}

bool magicEq(const(ubyte)[] b, string s)
{
    if (b.length < s.length)
        return false;
    return b[0 .. s.length] == cast(const(ubyte)[]) s;
}

Scan scan(const(ubyte)[] bytes)
{
    Scan s;
    if (bytes.length >= 8)
    {
        if (magicEq(bytes, "MZqFpD='"))
        {
            s.apeMz = true;
            s.kinds ~= Kind.ape;
        }
        else if (magicEq(bytes, "jartsr='"))
        {
            s.apeUnix = true;
            s.kinds ~= Kind.ape;
        }
        else if (magicEq(bytes, "APEDBG='"))
        {
            s.apeDbg = true;
            s.kinds ~= Kind.ape;
        }
    }
    if (bytes.length >= 2 && bytes[0] == 'M' && bytes[1] == 'Z')
    {
        s.pe = true;
        s.peOff = 0;
        if (!s.kinds.canFind(Kind.ape))
            s.kinds ~= Kind.pe;
    }
    if (bytes.length >= 4 && bytes[0] == 0x7f && bytes[1] == 'E' && bytes[2] == 'L' && bytes[3] == 'F')
    {
        s.elf = true;
        s.elfOff = 0;
        s.kinds ~= Kind.elf;
    }
    if (bytes.length >= 4)
    {
        const m = (cast(uint) bytes[0]) | (cast(uint) bytes[1] << 8) | (cast(uint) bytes[2] << 16) | (
                cast(uint) bytes[3] << 24);
        if (m == 0xfeedfacf || m == 0xcffaedfe || m == 0xfeedface)
        {
            s.macho = true;
            s.machoOff = 0;
            s.kinds ~= Kind.macho;
        }
        if (m == 0xcafebabe || m == 0xbebafeca || m == 0xcafebabf || m == 0xbfbafeca)
        {
            s.machoFat = true;
            s.machoOff = 0;
            s.kinds ~= Kind.machoFat;
        }
    }
    // ZIP local header or EOCD anywhere near the end
    if (bytes.length >= 4)
    {
        foreach (i; 0 .. min(bytes.length - 3, 64))
        {
            if (bytes[i] == 'P' && bytes[i + 1] == 'K' && bytes[i + 2] == 3 && bytes[i + 3] == 4)
            {
                s.zip = true;
                break;
            }
        }
        if (!s.zip && bytes.length >= 22)
        {
            auto tail = bytes[$ - min(bytes.length, 65557) .. $];
            foreach (i; 0 .. tail.length - 3)
            {
                if (tail[i] == 'P' && tail[i + 1] == 'K' && tail[i + 2] == 5 && tail[i + 3] == 6)
                {
                    s.zip = true;
                    break;
                }
            }
        }
        if (s.zip)
            s.kinds ~= Kind.zip;
    }
    s.summary = describe(s);
    return s;
}

string describe(Scan s)
{
    string[] bits;
    if (s.apeMz)
        bits ~= "APE(MZ)";
    if (s.apeUnix)
        bits ~= "APE(unix)";
    if (s.apeDbg)
        bits ~= "APE(debug)";
    if (s.pe && !s.apeMz)
        bits ~= "PE";
    if (s.elf)
        bits ~= "ELF@" ~ s.elfOff.to!string;
    if (s.machoFat)
        bits ~= "MachO-fat";
    else if (s.macho)
        bits ~= "MachO";
    if (s.zip)
        bits ~= "ZIP";
    if (bits.length == 0)
        return "unknown";
    if (bits.length > 1)
        return "chord:" ~ bits.join("+");
    return bits[0];
}

private string join(string[] a, string sep)
{
    if (a.length == 0)
        return "";
    string r = a[0];
    foreach (x; a[1 .. $])
        r ~= sep ~ x;
    return r;
}
