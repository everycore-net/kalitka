using System.Security.Cryptography;

namespace KalitkaAgent;

/// <summary>
/// The agent's signing key, held in a Windows key-storage provider — the Microsoft Platform
/// Crypto Provider (TPM-backed) when the machine has one, else the software KSP. The private
/// key never leaves the provider: we export only the SubjectPublicKeyInfo (SPKI) and ask the
/// provider to sign. Signatures are IEEE P1363 (r‖s, exactly 64 bytes), which is precisely
/// what Core's <c>ecdsa-p256</c> suite verifies — CNG produces this natively, so there is no
/// DER round-trip and no format sniffing.
/// </summary>
public sealed class PlatformKey : IDisposable
{
    private readonly ECDsaCng _ecdsa;

    /// <summary>Where the key actually lives, as a local <i>claim</i> for Core's UI
    /// (<c>windows-platform</c> = TPM-capable provider, <c>software</c> = fallback). Core never
    /// trusts this for policy; only attestation could, and that does not exist yet.</summary>
    public string ProviderHint { get; }

    private PlatformKey(ECDsaCng ecdsa, string providerHint)
    {
        _ecdsa = ecdsa;
        ProviderHint = providerHint;
    }

    /// <summary>Open the named key, creating it on first use. The TPM provider is tried first
    /// and the software provider is the fallback, so a machine without a TPM still works (with
    /// an honest <c>software</c> hint). <paramref name="machineKey"/> is on in production (the
    /// service runs as LocalSystem/gMSA and the key must be the machine's); a machine key needs
    /// admin rights to create, so tests pass it off to use a per-user key.</summary>
    public static PlatformKey OpenOrCreate(string keyName, bool preferSoftware = false, bool machineKey = true)
    {
        foreach (var (provider, hint) in Providers(preferSoftware))
        {
            try { return new PlatformKey(new ECDsaCng(OpenOrCreate(keyName, provider, machineKey)), hint); }
            catch (CryptographicException) { /* provider unavailable — try the next */ }
        }
        throw new InvalidOperationException("no usable CNG key storage provider (neither TPM nor software)");
    }

    private static CngKey OpenOrCreate(string keyName, CngProvider provider, bool machineKey)
    {
        var open = machineKey ? CngKeyOpenOptions.MachineKey : CngKeyOpenOptions.None;
        if (CngKey.Exists(keyName, provider, open)) return CngKey.Open(keyName, provider, open);
        return CngKey.Create(CngAlgorithm.ECDsaP256, keyName, new CngKeyCreationParameters
        {
            Provider = provider,
            KeyCreationOptions = machineKey ? CngKeyCreationOptions.MachineKey : CngKeyCreationOptions.None,
            ExportPolicy = CngExportPolicies.None,   // private key is non-exportable, by policy
        });
    }

    private static IEnumerable<(CngProvider provider, string hint)> Providers(bool preferSoftware)
    {
        if (!preferSoftware)
            yield return (CngProvider.MicrosoftPlatformCryptoProvider, "windows-platform");
        yield return (CngProvider.MicrosoftSoftwareKeyStorageProvider, "software");
    }

    /// <summary>base64 of the key's SPKI — the exact form Core stores and fingerprints.</summary>
    public string PublicKeySpkiBase64() => Convert.ToBase64String(_ecdsa.ExportSubjectPublicKeyInfo());

    /// <summary>The key id as Core computes it: <c>base64url(SHA-256(SPKI))</c>. Sent as
    /// <c>X-Kalitka-Key-Id</c> so Core can pick the right key without trying them all.</summary>
    public string KeyId()
    {
        var spki = _ecdsa.ExportSubjectPublicKeyInfo();
        return Convert.ToBase64String(SHA256.HashData(spki)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    /// <summary>Sign the canonical bytes; SHA-256 + P1363 (r‖s, 64 bytes).</summary>
    public string SignBase64(ReadOnlySpan<byte> message) =>
        Convert.ToBase64String(_ecdsa.SignData(message.ToArray(), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

    /// <summary>Delete a persisted key (test cleanup; also useful for a deliberate rotation).</summary>
    public static void Delete(string keyName, bool preferSoftware = false, bool machineKey = true)
    {
        var open = machineKey ? CngKeyOpenOptions.MachineKey : CngKeyOpenOptions.None;
        foreach (var (provider, _) in Providers(preferSoftware))
        {
            try
            {
                if (CngKey.Exists(keyName, provider, open))
                    CngKey.Open(keyName, provider, open).Delete();
            }
            catch (CryptographicException) { }
        }
    }

    public void Dispose() => _ecdsa.Dispose();
}
