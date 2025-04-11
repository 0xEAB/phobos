// Written in the D programming language.

/++
    Linux entropy providers.

    While the syscall was introduced in Linux 3.17 (Q4 2014) already,
    corresponding libc wrappers where added much later. The GNU C library
    only added it with the release of v2.25 (Q1 2017).

    While a few LTS distributions did backport the syscall function to even
    older kernel branches, the C library wrapper did usually not receive the
    same treatment and is still sometimes unavailable on systems in the wild.

    License:   $(HTTP www.boost.org/LICENSE_1_0.txt, Boost License 1.0).
    Authors:   Elias Batek
    Source:    $(PHOBOSSRC std/internal/entropy/linux.d)
 +/
module std.internal.entropy.windows;

version (Windows):
@nogc nothrow:

import core.sys.windows.bcrypt : BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG;
import core.sys.windows.windef : HMODULE, PUCHAR, ULONG;
import core.sys.windows.ntdef : NT_SUCCESS;
import std.internal.entropy.common;

package(std.internal.entropy):

EntropyResult getEntropyViaBCryptGenRandom(void[] buffer) @system
{
    const loaded = loadBcrypt();
    if (loaded != EntropyStatus.ok)
        return EntropyResult(loaded, EntropySource.bcryptGenRandom);

    const status = callBcryptGenRandom(buffer);
    return EntropyResult(status, EntropySource.bcryptGenRandom);
}

private:

EntropyStatus callBcryptGenRandom(void[] buffer) @system
{
    assert(buffer.length < ULONG.max);

    const gotRandom = ptrBCryptGenRandom(
        null,
        cast(PUCHAR) buffer.ptr,
        cast(ULONG) buffer.length,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    );

    return NT_SUCCESS(gotRandom)
        ? EntropyStatus.ok
        : EntropyStatus.readError;
}

static
{
    HMODULE hBcrypt = null;
    typeof(BCryptGenRandom)* ptrBCryptGenRandom;
}

EntropyStatus loadBcrypt() @system
{
    import core.sys.windows.winbase : GetProcAddress, LoadLibraryA;

    if (hBcrypt !is null)
        return EntropyStatus.ok;

    hBcrypt = LoadLibraryA("Bcrypt.dll");
    if (!hBcrypt)
        return EntropyStatus.unavailableLibrary;

    ptrBCryptGenRandom = cast(typeof(ptrBCryptGenRandom)) GetProcAddress(hBcrypt , "BCryptGenRandom");
    if (!ptrBCryptGenRandom)
        return EntropyStatus.unavailable;

    return EntropyStatus.ok;
}

// Will free `Bcrypt.dll`.
void freeBcrypt() @system
{
    import core.sys.windows.winbase : FreeLibrary;

    if (hBcrypt is null)
        return;

    if (!FreeLibrary(hBcrypt))
    {
        return; // Error
    }

    hBcrypt = null;
    ptrBCryptGenRandom = null;
}

static ~this() @system
{
    freeBcrypt();
}
