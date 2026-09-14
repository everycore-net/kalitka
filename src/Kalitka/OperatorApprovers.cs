using System.Text.Json;

namespace Kalitka;

/// <summary>
/// Approve rights granted at runtime, by e-mail — the piece that makes device enrolment
/// (<see cref="EnrollService"/>) end to end: an invited operator can be given the ability to approve
/// without editing the deployment's <see cref="GateOptions.ApproverEmails"/> env list. Composes with
/// that static list (the union is what <see cref="AdminAuth.ResolvePermissions"/> grants), so the two
/// never fight; this one is just the mutable half. One JSON set in the shared config store, like
/// operator principals and passkeys.
/// </summary>
public sealed class OperatorApprovers
{
    private const string Key = "operator-approvers";
    private readonly IConfigStore _config;
    private readonly IAuditStore _audit;
    private readonly TimeProvider _clock;

    public OperatorApprovers(IConfigStore config, IAuditStore audit, TimeProvider? clock = null)
    {
        _config = config;
        _audit = audit;
        _clock = clock ?? TimeProvider.System;
    }

    public IReadOnlyList<string> All() => Parse(_config.Get(Key)).OrderBy(e => e, StringComparer.Ordinal).ToList();

    public bool Contains(string email) =>
        Parse(_config.Get(Key)).Contains(Norm(email));

    public async Task Grant(string email, string actor, CancellationToken ct)
    {
        var e = Norm(email);
        if (e.Length == 0) return;
        var added = false;
        _config.Mutate(Key, cur =>
        {
            var set = Parse(cur);
            added = set.Add(e);
            return JsonSerializer.Serialize(set);
        });
        if (added) await _audit.Append(Ev(AuditEvents.ApproverGranted, actor, e), ct);
    }

    public async Task<bool> Revoke(string email, string actor, CancellationToken ct)
    {
        var e = Norm(email);
        var removed = false;
        _config.Mutate(Key, cur =>
        {
            var set = Parse(cur);
            removed = set.Remove(e);
            return JsonSerializer.Serialize(set);
        });
        if (removed) await _audit.Append(Ev(AuditEvents.ApproverRevoked, actor, e), ct);
        return removed;
    }

    private static string Norm(string email) => (email ?? "").Trim().ToLowerInvariant();

    private static HashSet<string> Parse(string? blob) =>
        string.IsNullOrWhiteSpace(blob)
            ? new(StringComparer.Ordinal)
            : new(JsonSerializer.Deserialize<List<string>>(blob) ?? new(), StringComparer.Ordinal);

    private AuditEvent Ev(string type, string actor, string email) =>
        new(Guid.NewGuid().ToString("N"), _clock.GetUtcNow(), type, actor,
            Subject: email, Resource: "", RequestId: "", GrantId: "", Channel: "admin", Metadata: "");
}
