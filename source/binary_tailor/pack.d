module binary_tailor.pack;

import binary_tailor.target;
import std.algorithm : canFind, startsWith;
import std.array : appender, split;
import std.exception : enforce;
import std.string : indexOf, strip;
import std.zip;

struct Payload
{
    string triplet;
    string nameInZip;
    ubyte[] bytes;
}

struct PackManifest
{
    string name = "app";
    string ver = "0.0.0";
    Payload[] payloads;
}

string defaultManifest(PackManifest m)
{
    auto buf = appender!string;
    buf.put("pack {\n");
    buf.put("  name \"" ~ m.name ~ "\"\n");
    buf.put("  version \"" ~ m.ver ~ "\"\n");
    foreach (p; m.payloads)
        buf.put("  payload \"" ~ p.triplet ~ "\" file=\"" ~ p.nameInZip ~ "\"\n");
    buf.put("}\n");
    return buf.data;
}

PackManifest parseManifest(string text)
{
    PackManifest m;
    foreach (line; text.split('\n'))
    {
        auto s = line.strip;
        if (s.startsWith("name "))
            m.name = unquote(s[5 .. $]);
        else if (s.startsWith("version "))
            m.ver = unquote(s[8 .. $]);
        else if (s.startsWith("payload "))
        {
            Payload p;
            auto rest = s[8 .. $].strip;
            p.triplet = unquote(rest);
            auto f = rest.indexOf("file=");
            if (f >= 0)
                p.nameInZip = unquote(rest[f + 5 .. $]);
            else
                p.nameInZip = "payloads/" ~ p.triplet;
            m.payloads ~= p;
        }
    }
    return m;
}

private string unquote(string s)
{
    s = s.strip;
    auto q = s.indexOf('"');
    if (q < 0)
        return s.split(' ')[0];
    auto q2 = s.indexOf('"', q + 1);
    if (q2 < 0)
        return s[q + 1 .. $];
    return s[q + 1 .. q2];
}


ubyte[] makeZip(PackManifest m)
{
    auto zip = new ZipArchive;
    auto man = defaultManifest(m);
    {
        auto m2 = new ArchiveMember;
        m2.name = "manifest.sdl";
        m2.expandedData = cast(ubyte[]) man;
        m2.compressionMethod = CompressionMethod.deflate;
        zip.addMember(m2);
    }
    foreach (p; m.payloads)
    {
        auto mem = new ArchiveMember;
        mem.name = p.nameInZip;
        mem.expandedData = p.bytes;
        mem.compressionMethod = CompressionMethod.deflate;
        zip.addMember(mem);
    }
    return cast(ubyte[]) zip.build();
}

PackManifest openPack(const(ubyte)[] bytes)
{
    auto zip = new ZipArchive(bytes.dup);
    PackManifest m;
    if ("manifest.sdl" in zip.directory)
    {
        auto mem = zip.directory["manifest.sdl"];
        zip.expand(mem);
        m = parseManifest(cast(string) mem.expandedData);
        foreach (ref p; m.payloads)
        {
            enforce(p.nameInZip in zip.directory, "missing zip member " ~ p.nameInZip);
            auto pm = zip.directory[p.nameInZip];
            zip.expand(pm);
            p.bytes = pm.expandedData;
        }
        return m;
    }
    // APE/zip without our manifest: treat each stored file as a payload named after the member.
    foreach (name, mem; zip.directory)
    {
        if (name[$ - 1] == '/')
            continue;
        zip.expand(mem);
        Payload p;
        p.nameInZip = name;
        p.triplet = guessTriplet(name);
        p.bytes = mem.expandedData;
        m.payloads ~= p;
    }
    m.name = "zip";
    return m;
}

string guessTriplet(string name)
{
    auto n = name;
    foreach (t; [
        "windows-x64", "windows-arm64", "linux-x64", "linux-arm64",
        "macos-arm64", "freebsd-x64", "freebsd-arm64", "openbsd-x64", "netbsd-x64"
    ])
        if (n.canFind(t))
            return t;
    if (n.canFind(".exe") || n.canFind(".dll"))
        return "windows-x64";
    if (n.canFind(".dylib"))
        return "macos-arm64";
    return name;
}

ubyte[] pickPayload(PackManifest m, Target t)
{
    const want = triplet(t);
    foreach (p; m.payloads)
        if (p.triplet == want)
            return p.bytes;
    foreach (p; m.payloads)
        if (p.triplet.startsWith(t.os))
            return p.bytes;
    throw new Exception("pack has no payload for " ~ want);
}
