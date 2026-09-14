using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace KalitkaMcpGateway;

/// <summary>One tool in an inventory snapshot: its name and the canonical bytes of its input schema.
/// <see cref="ContractHashHex"/> (schema identity) keys classification and diffs snapshots.</summary>
public sealed record InventoryTool(string Name, byte[] SchemaCanonical)
{
    public byte[] SchemaHash { get; } = SHA256.HashData(SchemaCanonical);
    public string ContractHashHex => Convert.ToHexString(SchemaHash);
}

/// <summary>What changed between two snapshots — for operator visibility and audit. Safety does not
/// depend on it: an added/renamed/retyped tool is unclassified anyway (classification binds the
/// contract hash), and the epoch shift invalidates all in-flight grants regardless.</summary>
public sealed record InventoryDiff(string[] Added, string[] Removed, string[] Changed)
{
    public bool Any => Added.Length + Removed.Length + Changed.Length > 0;
}

/// <summary>
/// A snapshot of an upstream's tools. The <see cref="Epoch"/> is a <b>digest of the whole snapshot</b>
/// (every tool's name + schema), folded into each <c>tool_contract_id</c>: any inventory change —
/// a tool added, removed, or retyped anywhere — shifts the epoch and so invalidates every
/// not-yet-redeemed grant on the upstream. A digest is deterministic and restart-stable (unlike a
/// local counter), which matters once inventories are persisted. <see cref="Revision"/> is a
/// human-facing counter only.
/// </summary>
public sealed class ToolInventory
{
    public string UpstreamAlias { get; }
    public string UpstreamId { get; }
    public long Revision { get; }
    public string Epoch { get; }
    private readonly Dictionary<string, InventoryTool> _tools;

    private ToolInventory(string alias, string upstreamId, long revision, Dictionary<string, InventoryTool> tools)
    {
        UpstreamAlias = alias;
        UpstreamId = upstreamId;
        Revision = revision;
        _tools = tools;
        Epoch = ComputeEpoch(tools);
    }

    public static ToolInventory Empty(string alias, string upstreamId) =>
        new(alias, upstreamId, 0, new Dictionary<string, InventoryTool>(StringComparer.Ordinal));

    /// <summary>Build a snapshot from the upstream's advertised tools. The upstream is not trusted:
    /// a duplicate tool name, a malformed schema, or a schema that is not a JSON object rejects the
    /// whole snapshot (fail closed) rather than silently letting the last one win.</summary>
    public static ToolInventory Build(string alias, string upstreamId, long revision, IEnumerable<UpstreamTool> tools)
    {
        var map = new Dictionary<string, InventoryTool>(StringComparer.Ordinal);
        foreach (var t in tools)
        {
            var canonical = Jcs.Canonicalize(t.InputSchemaJson);
            if (canonical.Length == 0 || canonical[0] != (byte)'{')
                throw new JcsException($"tool '{t.Name}': inputSchema must be a JSON object");
            if (!map.TryAdd(t.Name, new InventoryTool(t.Name, canonical)))
                throw new JcsException($"duplicate tool name from upstream: {t.Name}");
        }
        return new ToolInventory(alias, upstreamId, revision, map);
    }

    public bool TryGet(string tool, out InventoryTool value) => _tools.TryGetValue(tool, out value!);

    public IReadOnlyCollection<string> ToolNames => _tools.Keys;

    /// <summary>The tool's contract id for the fingerprint: SHA-256(upstreamId ‖ tool ‖ epoch ‖
    /// canonical(inputSchema)), each length-prefixed.</summary>
    public byte[] ContractId(string tool) =>
        CallFingerprint.ToolContractId(UpstreamId, tool, Epoch, _tools[tool].SchemaCanonical);

    /// <summary>Would this set of tools differ from the current snapshot (by name and contract
    /// hash)? Used to decide whether a refresh bumps the revision/epoch.</summary>
    public bool DiffersFrom(IEnumerable<UpstreamTool> tools) =>
        Diff(this, Build(UpstreamAlias, UpstreamId, Revision, tools)).Any;

    public static InventoryDiff Diff(ToolInventory old, ToolInventory @new)
    {
        var added = @new._tools.Keys.Where(n => !old._tools.ContainsKey(n)).OrderBy(n => n, StringComparer.Ordinal).ToArray();
        var removed = old._tools.Keys.Where(n => !@new._tools.ContainsKey(n)).OrderBy(n => n, StringComparer.Ordinal).ToArray();
        var changed = @new._tools.Where(kv => old._tools.TryGetValue(kv.Key, out var o) && o.ContractHashHex != kv.Value.ContractHashHex)
            .Select(kv => kv.Key).OrderBy(n => n, StringComparer.Ordinal).ToArray();
        return new InventoryDiff(added, removed, changed);
    }

    // A deterministic digest of the whole snapshot: for each tool sorted by name, length-prefixed
    // name ‖ schema hash. Same tools ⇒ same epoch, across processes and restarts.
    private static string ComputeEpoch(Dictionary<string, InventoryTool> tools)
    {
        var buf = new ArrayBufferWriter<byte>();
        foreach (var t in tools.Values.OrderBy(t => t.Name, StringComparer.Ordinal))
        {
            var name = Encoding.UTF8.GetBytes(t.Name);
            var len = buf.GetSpan(4);
            BinaryPrimitives.WriteUInt32BigEndian(len, (uint)name.Length);
            buf.Advance(4);
            buf.Write(name);
            buf.Write(t.SchemaHash);
        }
        return Convert.ToHexString(SHA256.HashData(buf.WrittenSpan));
    }
}
