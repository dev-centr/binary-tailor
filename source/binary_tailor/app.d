module binary_tailor.app;

import binary_tailor.ape;
import binary_tailor.detect;
import binary_tailor.pack;
import binary_tailor.target;
import macho_memload;
import std.exception : enforce;
import std.file : read, write;
import std.getopt;
import std.path : baseName, stripExtension;
import std.stdio;
import std.string : toLower, fromStringz;

int main(string[] args)
{
    if (args.length < 2)
    {
        usage();
        return 2;
    }
    const cmd = args[1].toLower;
    auto rest = args[0] ~ args[2 .. $];
    try
    {
        switch (cmd)
        {
        case "inspect":
            return cmdInspect(rest);
        case "tailor":
            return cmdTailor(rest);
        case "pack":
            return cmdPack(rest);
        case "assimilate":
            return cmdAssimilate(rest);
        case "graft":
            return cmdGraft(rest);
        case "memload":
            return cmdMemload(rest);
        case "-h":
        case "--help":
        case "help":
            usage();
            return 0;
        default:
            stderr.writeln("unknown command: ", cmd);
            usage();
            return 2;
        }
    }
    catch (Exception e)
    {
        stderr.writeln("binary-tailor: ", e.msg);
        return 1;
    }
}

void usage()
{
    stdout.write(
        "binary-tailor — one download, host-shaped binary\n" ~
        "\n" ~
        "  inspect     FILE                 Show PE/ELF/Mach-O/APE/ZIP chord\n" ~
        "  tailor      FILE [-o OUT] [--target os-arch]\n" ~
        "                                   Strip to the host (or given) slice\n" ~
        "  pack        -o OUT [--name N] [--version V] TRIPLET=FILE ...\n" ~
        "                                   ZIP pack + manifest.sdl\n" ~
        "  assimilate  FILE [-o OUT] [--target os-arch]\n" ~
        "                                   Rewrite APE headers like Cosmo assimilate\n" ~
        "  graft       -o OUT [--stub APE] TRIPLET=FILE ...\n" ~
        "                                   Native slices into a pack (optional APE stub)\n" ~
        "  memload     FILE                 Map Mach-O via macho-memload (no exec)\n" ~
        "\n" ~
        "Targets: windows-x64, windows-arm64, linux-x64, linux-arm64,\n" ~
        "         macos-arm64, freebsd-x64, freebsd-arm64, openbsd-x64, netbsd-x64\n" ~
        "macOS x64 GitHub runners are not used (Apple Silicon only).\n"
    );
}

int cmdInspect(string[] args)
{
    string path;
    getopt(args, std.getopt.config.passThrough);
    enforce(args.length >= 2, "inspect FILE");
    path = args[1];
    auto bytes = cast(ubyte[]) read(path);
    auto s = scan(bytes);
    writeln(path, ": ", s.summary);
    auto hdrs = decodePrintfElfHeaders(bytes);
    if (hdrs.length)
        writeln("  embedded ELF printf headers: ", hdrs.length);
    auto dds = decodeDdWindows(bytes);
    if (dds.length)
        writeln("  Mach-O dd windows: ", dds.length);
    if (s.zip)
    {
        auto pack = openPack(bytes);
        writeln("  zip payloads:");
        foreach (p; pack.payloads)
            writeln("    ", p.triplet, "  ", p.nameInZip, "  ", p.bytes.length, " bytes");
    }
    return 0;
}

int cmdTailor(string[] args)
{
    string output;
    string targetStr;
    getopt(args,
        "o|output", &output,
        "target", &targetStr);
    enforce(args.length >= 2, "tailor FILE");
    auto input = args[1];
    auto bytes = cast(ubyte[]) read(input);
    auto t = parseTriplet(targetStr);
    auto outPath = output.length ? output : defaultOutPath(input, t);
    auto tailored = tailorBytes(bytes, t);
    write(outPath, tailored);
    writeln("wrote ", outPath, " (", tailored.length, " bytes) for ", triplet(t));
    return 0;
}

int cmdAssimilate(string[] args)
{
    string output;
    string targetStr;
    getopt(args, "o|output", &output, "target", &targetStr);
    enforce(args.length >= 2, "assimilate FILE");
    auto input = args[1];
    auto bytes = cast(ubyte[]) read(input);
    auto t = parseTriplet(targetStr);
    auto outb = assimilate(bytes, t.os, t.arch);
    auto outPath = output.length ? output : defaultOutPath(input, t);
    write(outPath, outb);
    writeln("assimilated ", outPath, " as ", triplet(t));
    return 0;
}

int cmdPack(string[] args)
{
    string output;
    string name = "app";
    string ver = "0.1.0";
    getopt(args, "o|output", &output, "name", &name, "version", &ver);
    enforce(output.length, "pack -o OUT TRIPLET=FILE ...");
    PackManifest m;
    m.name = name;
    m.ver = ver;
    foreach (a; args[1 .. $])
    {
        auto eq = a.indexOfEq();
        enforce(eq > 0, "payload args look like linux-x64=./app");
        Payload p;
        p.triplet = a[0 .. eq];
        parseTriplet(p.triplet); // validate
        p.nameInZip = "payloads/" ~ p.triplet;
        p.bytes = cast(ubyte[]) read(a[eq + 1 .. $]);
        m.payloads ~= p;
    }
    enforce(m.payloads.length, "no payloads");
    auto zip = makeZip(m);
    write(output, zip);
    writeln("packed ", m.payloads.length, " slices -> ", output);
    return 0;
}

int cmdGraft(string[] args)
{
    string stub;
    getopt(args, "stub", &stub);
    if (stub.length)
        stderr.writeln(
            "note: --stub is reserved for APE launcher merge; v0 writes a ZIP pack of native slices. ",
            "That is the graft Cosmopolitan issue #377 asked for without overlapping PE/ELF/Mach-O. ",
            "Surgical header transplant is documented in general-knowledge polyglot-distribution.");
    return cmdPack(args);
}

int cmdMemload(string[] args)
{
    enforce(args.length >= 2, "memload FILE");
    auto bytes = cast(ubyte[]) read(args[1]);
    memload_image img;
    auto rc = memload_map(bytes.ptr, bytes.length, &img);
    if (rc != MEMLOAD_OK)
    {
        stderr.writeln(memload_strerror(rc));
        return 1;
    }
    writeln("mapped ", img.size, " bytes  cpu=", img.cputype, "  entry=", img.entry);
    memload_unmap(&img);
    return 0;
}

ubyte[] tailorBytes(const(ubyte)[] bytes, Target t)
{
    auto s = scan(bytes);
    if (s.zip)
    {
        try
        {
            auto pack = openPack(bytes);
            if (pack.payloads.length)
                return pickPayload(pack, t);
        }
        catch (Exception)
        {
        }
    }
    if (s.apeMz || s.apeUnix || s.apeDbg)
        return assimilate(bytes, t.os, t.arch);
    if (s.machoFat && t.os == "macos")
    {
        // Delegate slice pick to macho-memload parse (map copies the thin image).
        memload_image img;
        const want = t.arch == "arm64" ? CPU_TYPE_ARM64 : CPU_TYPE_X86_64;
        auto rc = memload_map_cpu(bytes.ptr, bytes.length, want, &img);
        enforce(rc == MEMLOAD_OK, memload_strerror(rc).fromStringz);
        // Mapping is not a file image. For fat, copy the selected slice via parse.
        memload_unmap(&img);
        import macho_memload.parse : FatArch, selectFatSlice;

        FatArch arch;
        rc = selectFatSlice(bytes.ptr, bytes.length, want, &arch);
        enforce(rc == MEMLOAD_OK, "fat slice missing");
        return bytes[arch.offset .. arch.offset + arch.size].dup;
    }
    // Already a single-target file.
    return bytes.dup;
}

string defaultOutPath(string input, Target t)
{
    auto base = stripExtension(baseName(input));
    if (t.os == "windows")
        return base ~ ".exe";
    return base ~ "-" ~ triplet(t);
}

private ptrdiff_t indexOfEq(string s)
{
    foreach (i, c; s)
        if (c == '=')
            return cast(ptrdiff_t) i;
    return -1;
}
