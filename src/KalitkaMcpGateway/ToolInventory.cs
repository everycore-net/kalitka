using System.Security.Cryptography;

namespace KalitkaMcpGateway;

/// <summary>One tool in an inventory snapshot: its name and the canonical bytes of its input
/// schema. The <b>contract hash</b> (schema identity, revision-independent) drives classification
/// and drift; the <b>contract id</b> (schema + inventory revision) goes into the call fingerprint.</summary>
public sealed record InventoryTool(string Name, byte[] SchemaCanonical)
{
    /// <summary>SHA-256 of the canonical schema, hex — the revision-independent identity used to
    /// key classification and to diff snapshots.</summary>
    public string ContractHashHex { get; } = Convert.ToHexString(SHA256.HashData(SchemaCanonical));
}

/// <summary>What changed between two inventory snapshots — for operator visibility and audit.
/// (Safety does not depend on this: an added/renamed/retyped tool is unclassified anyway, since
/// classification is bound to the contract hash.)</summary>
public sealed record InventoryDiff(string[] Added, string[] Removed, string[] Changed)
{
    public bool Any => Added.Length + Removed.Length + Changed.Length > 0;
}

/// <summary>
/// A snapshot of an upstream's tools at one <see cref="Revision"/>. The revision is part of every
/// tool's <c>tool_contract_id</c>, so bumping it (on any drift) invalidates every not-yet-approved
/// request against the old inventory — an inventory change never silently rides on an old approval.
/// </summary>
public sealed class ToolInventory
{
    public string UpstreamAlias { get; }
    public string UpstreamId { get; }
    public long Revision { get; }
    private readonly Dictionary<string, InventoryTool> _tools;

    private ToolInventory(string alias, string upstreamId, long revision, Dictionary<string, InventoryTool> tools)
    {
        UpstreamAlias = alias;
        UpstreamId = upstreamId;
        Revision = revision;
        _tools = tools;
    }

    public static ToolInventory Empty(string alias, string upstreamId) =>
        new(alias, upstreamId, 0, new Dictionary<string, InventoryTool>(StringComparer.Ordinal));

    /// <summary>Build a snapshot at <paramref name="revision"/> from the upstream's advertised
    /// tools, canonicalising each schema (a malformed schema rejects the whole snapshot — fail
    /// closed).</summary>
    public static ToolInventory Build(string alias, string upstreamId, long revision, IEnumerable<UpstreamTool> tools)
    {
        var map = new Dictionary<string, InventoryTool>(StringComparer.Ordinal);
        foreach (var t in tools)
            map[t.Name] = new InventoryTool(t.Name, Jcs.Canonicalize(t.InputSchemaJson));
        return new ToolInventory(alias, upstreamId, revision, map);
    }

    public bool TryGet(string tool, out InventoryTool value) => _tools.TryGetValue(tool, out value!);

    public IReadOnlyCollection<string> ToolNames => _tools.Keys;

    /// <summary>The tool's contract id for the fingerprint: SHA-256(upstreamId ‖ tool ‖ revision ‖
    /// canonical(inputSchema)).</summary>
    public byte[] ContractId(string tool) =>
        CallFingerprint.ToolContractId(UpstreamId, tool, _tools[tool].SchemaCanonical, Revision);

    /// <summary>Would this set of tools differ from the current snapshot (by name and contract
    /// hash)? Used to decide whether a refresh bumps the revision.</summary>
    public bool DiffersFrom(IEnumerable<UpstreamTool> tools) => Diff(this, Build(UpstreamAlias, UpstreamId, Revision, tools)).Any;

    public static InventoryDiff Diff(ToolInventory old, ToolInventory @new)
    {
        var added = @new._tools.Keys.Where(n => !old._tools.ContainsKey(n)).OrderBy(n => n, StringComparer.Ordinal).ToArray();
        var removed = old._tools.Keys.Where(n => !@new._tools.ContainsKey(n)).OrderBy(n => n, StringComparer.Ordinal).ToArray();
        var changed = @new._tools.Where(kv => old._tools.TryGetValue(kv.Key, out var o) && o.ContractHashHex != kv.Value.ContractHashHex)
            .Select(kv => kv.Key).OrderBy(n => n, StringComparer.Ordinal).ToArray();
        return new InventoryDiff(added, removed, changed);
    }
}
