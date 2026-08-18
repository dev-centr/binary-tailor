module binary_tailor.target;

import std.string : toLower;

struct Target
{
    string os;   // windows, linux, macos, freebsd, openbsd, netbsd
    string arch; // x64, arm64
}

string triplet(Target t)
{
    return t.os ~ "-" ~ t.arch;
}

Target parseTriplet(string s)
{
    auto p = s.toLower;
    Target t;
    if (p.length == 0)
        return hostTarget();
    auto dash = p.lastIndexOf('-');
    if (dash <= 0 || dash + 1 >= p.length)
        throw new Exception("target must be os-arch, e.g. windows-x64");
    t.os = p[0 .. dash];
    t.arch = p[dash + 1 .. $];
    if (t.os == "darwin" || t.os == "osx" || t.os == "mac")
        t.os = "macos";
    if (t.os == "win")
        t.os = "windows";
    if (t.arch == "amd64" || t.arch == "x86_64")
        t.arch = "x64";
    if (t.arch == "aarch64" || t.arch == "arm")
        t.arch = "arm64";
    if (t.os == "macos" && t.arch == "x64")
        throw new Exception("macos-x64 is not a GitHub-hosted target; use macos-arm64");
    return t;
}

Target hostTarget()
{
    Target t;
    version (Windows)
        t.os = "windows";
    else version (OSX)
        t.os = "macos";
    else version (FreeBSD)
        t.os = "freebsd";
    else version (OpenBSD)
        t.os = "openbsd";
    else version (NetBSD)
        t.os = "netbsd";
    else version (linux)
        t.os = "linux";
    else
        t.os = "unknown";

    version (X86_64)
        t.arch = "x64";
    else version (AArch64)
        t.arch = "arm64";
    else
        t.arch = "unknown";
    return t;
}

private ptrdiff_t lastIndexOf(string s, char c)
{
    foreach_reverse (i, ch; s)
        if (ch == c)
            return cast(ptrdiff_t) i;
    return -1;
}
