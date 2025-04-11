// Written in the D programming language.

/++
    Entropy framework prototype.

    This code has not been audited.
    Do not use for cryptographic purposes.

    License:   $(HTTP www.boost.org/LICENSE_1_0.txt, Boost License 1.0).
    Authors:   Elias Batek
    Source:    $(PHOBOSSRC std/internal/entropy/entropy.d)
 +/
module std.internal.entropy.entropy;

public import std.internal.entropy.common;

import std.internal.entropy.linux;
import std.internal.entropy.posix;
import std.internal.entropy.windows;
import std.meta;

version (linux):
@nogc nothrow:

// Flagship function
EntropyResult getEntropy(void[] buffer) @system
{
    return getEntropyImpl(buffer);
}

// Convenience overload
EntropyResult getEntropy(ubyte[] buffer) @trusted
{
    return getEntropy(cast(void[]) buffer);
}

// Convenience wrapper
EntropyResult getEntropy(void* buffer, size_t length) @system
{
    return getEntropy(buffer[0 .. length]);
}

void forceEntropySource(EntropySource source) @safe
{
    _entropySource = source;
}

/+
    (In-)Convenience wrapper.

    In general, it’s a bad idea to let users pick sources themselves.
    A sane option should be used by default instead.

    See_also:
        Use `forceEntropySource` instead.
 +/
EntropyResult getEntropy(void* buffer, size_t length, EntropySource source) @system
{
    const sourcePrevious = _entropySource;
    scope (exit) _entropySource = sourcePrevious;

    _entropySource = source;
    return getEntropy(buffer[0 .. length]);
}

package(std):

pragma(inline, true) void crashOnError(const EntropyResult value) pure @safe
{
    if (value.isOK)
        return;

    assert(false, value.toString());
}

private:

struct SrcFunPair(EntropySource source, alias func)
{
    enum  src = source;
    alias fun = func;
}

template isValidSupportedSource(SupportedSource)
{
    import std.traits;

    enum isValidSupportedSource = (
        is(SupportedSource == SrcFunPair!Args, Args...) &&
        SupportedSource.src != EntropySource.tryAll &&
        SupportedSource.src != EntropySource.none
    );
}

mixin template entropyImpl(EntropySource defaultSource, SupportedSources...)
if (allSatisfy!(isValidSupportedSource, SupportedSources))
{
    enum defaultEntropySource = defaultSource;

    EntropyResult getEntropyImpl(void[] buffer) @system
    {
        switch (_entropySource)
        {
            static foreach(source; SupportedSources)
            {
                case source.src:
                    return source.fun(buffer);
            }

        case EntropySource.tryAll:
            {
                const result = _tryEntropySources(buffer);
                result.saveSourceForNextUse();
                return result;
            }
        
        case EntropySource.none:
            return getEntropyViaNone(buffer);

        default:
            return EntropyResult(EntropyStatus.unavailablePlatform, _entropySource);
        }
    }

    EntropyResult _tryEntropySources(void[] buffer) @system
    {
        EntropyResult result;

        static foreach(source; SupportedSources)
        {
            result = source.fun(buffer);
            if (!result.isUnavailable)
                return result;
        }

        result = EntropyResult(
            EntropyStatus.unavailable,
            EntropySource.none,
        );

        return result;
    }
}

version (linux) mixin entropyImpl!(
    EntropySource.getrandom,
    SrcFunPair!(EntropySource.getrandom, getEntropyViaGetrandom),
    SrcFunPair!(EntropySource.charDevURandom, getEntropyViaCharDevURandom),
    SrcFunPair!(EntropySource.charDevRandom, getEntropyViaCharDevRandom),
);
else version (Posix) mixin entropyImpl!(
    EntropySource.charDevURandom,
    SrcFunPair!(EntropySource.charDevURandom, getEntropyViaCharDevURandom),
    SrcFunPair!(EntropySource.charDevRandom, getEntropyViaCharDevRandom),
);
else version (Windows) mixin entropyImpl!(
    EntropySource.bcryptGenRandom,
    SrcFunPair!(EntropySource.bcryptGenRandom, getEntropyViaBCryptGenRandom),
    // TODO: SrcFunPair!(EntropySource.cryptGenRandom, getEntropyViaCryptGenRandom),
);
else mixin entropyImpl!(
    EntropySource.none,
);

static EntropySource _entropySource = defaultEntropySource;

void saveSourceForNextUse(const EntropyResult result) @safe
{
    if (!result.isOK)
        return;

    _entropySource = result.source;
}

EntropyResult getEntropyViaNone(void[])
{
    return EntropyResult(EntropyStatus.unavailable, EntropySource.none);
}
