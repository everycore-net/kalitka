using System.Globalization;

namespace Kalitka;

/// <summary>
/// The verifiable top of the audit chain. Verifying the chain proves nothing was altered between
/// events; a <b>signed checkpoint</b> over the current head — seq + hash + time, signed with the
/// server key — lets a customer pin "the log ended here, signed by us at this moment", so a later
/// truncation (dropping recent events) is caught too, not just an in-place edit. Together they turn
/// "we logged it" into an exportable, checkable proof.
/// </summary>
public sealed class AuditIntegrity
{
    private const string KeyId = "audit-checkpoint:v1";

    private readonly IAuditStore _audit;
    private readonly TokenSigner _signer;
    private readonly TimeProvider _clock;

    public AuditIntegrity(IAuditStore audit, TokenSigner signer, TimeProvider? clock = null)
    {
        _audit = audit;
        _signer = signer;
        _clock = clock ?? TimeProvider.System;
    }

    /// <summary>A signed statement about the current head of the chain.</summary>
    public sealed record Checkpoint(long Seq, string Hash, DateTimeOffset SignedAt, string Token);

    public Task<AuditVerification> Verify(CancellationToken ct) => _audit.VerifyChain(ct);

    /// <summary>Verify the chain and sign its head. Returns null if the chain is broken — we never
    /// sign a head sitting on top of a tampered log.</summary>
    public async Task<Checkpoint?> SignHead(CancellationToken ct)
    {
        var v = await _audit.VerifyChain(ct);
        if (!v.Intact) return null;
        var now = _clock.GetUtcNow();
        var token = _signer.Sign(Payload(v.HeadSeq, v.HeadHash, now), KeyId);
        return new Checkpoint(v.HeadSeq, v.HeadHash, now, token);
    }

    /// <summary>Verify a previously issued checkpoint token was signed by this server and matches
    /// the claimed head — the check a customer runs on an exported checkpoint.</summary>
    public bool VerifyCheckpoint(Checkpoint c) =>
        _signer.Verify(c.Token, KeyId, out var payload) && payload == Payload(c.Seq, c.Hash, c.SignedAt);

    private static string Payload(long seq, string hash, DateTimeOffset at) =>
        string.Join('\n', "kalitka-audit-checkpoint",
            seq.ToString(CultureInfo.InvariantCulture), hash, at.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));
}
