namespace KalitkaMcpGateway;

/// <summary>How a tool is classified for approval — always decided by kalitka's policy, never
/// taken from the guarded server's own annotations (trusting <c>readOnlyHint</c>/<c>destructiveHint</c>
/// from the thing being gated is the same mistake as reading the signature algorithm off the
/// request). Anything not classified is <see cref="Unclassified"/> and can never be auto-allowed.</summary>
public enum ClassKind { NoApproval, NeedsApproval, Unclassified }

/// <summary>A tool's approval class. <see cref="RequiredApprovals"/> applies to
/// <see cref="ClassKind.NeedsApproval"/>.</summary>
public sealed record ToolClass(ClassKind Kind, int RequiredApprovals = 1)
{
    public static readonly ToolClass Unclassified = new(ClassKind.Unclassified);
    public static readonly ToolClass NoApproval = new(ClassKind.NoApproval);
    public static ToolClass Approval(int required = 1) => new(ClassKind.NeedsApproval, Math.Max(1, required));
}

/// <summary>
/// Resolves a tool's class from policy, bound to the exact tool <b>contract</b> an admin
/// classified (the hash of its canonical input schema). This is how inventory drift stays safe:
/// a new tool, a renamed tool, or a tool whose schema changed all resolve to
/// <see cref="ToolClass.Unclassified"/> — which the gate never auto-allows — until an admin
/// classifies that specific contract. Classifying by name alone would let a retyped tool inherit
/// the old tool's trust.
/// </summary>
public interface IToolClassifier
{
    ToolClass Classify(string upstreamAlias, string tool, string contractHashHex);
}

/// <summary>A table-driven classifier keyed by <c>alias/tool/contract-hash</c>. Absent ⇒
/// unclassified.</summary>
public sealed class DictionaryToolClassifier : IToolClassifier
{
    private readonly Dictionary<string, ToolClass> _table = new(StringComparer.Ordinal);

    public DictionaryToolClassifier Set(string upstreamAlias, string tool, string contractHashHex, ToolClass cls)
    {
        _table[Key(upstreamAlias, tool, contractHashHex)] = cls;
        return this;
    }

    public ToolClass Classify(string upstreamAlias, string tool, string contractHashHex) =>
        _table.TryGetValue(Key(upstreamAlias, tool, contractHashHex), out var c) ? c : ToolClass.Unclassified;

    private static string Key(string alias, string tool, string hash) => alias + "/" + tool + "@" + hash;
}
