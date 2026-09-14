using System.Security.Cryptography;
using System.Text;

namespace KalitkaAgent;

/// <summary>
/// The client half of the <c>kalitka-agent-sig-v1</c> wire scheme. Kept as its own tiny type
/// so it is trivially testable for byte-for-byte parity with Core's <c>AgentSignatures</c>:
/// the canonical string binds method, path, body hash, timestamp and nonce, newline-joined
/// with the scheme first, so no field can be smuggled into another and a signature cannot be
/// replayed against a different request.
/// </summary>
public static class Wire
{
    public const string Scheme = "kalitka-agent-sig-v1";

    public static string Sha256Hex(ReadOnlySpan<byte> body) =>
        Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant();

    public static byte[] CanonicalString(string method, string pathAndQuery, string bodyHashHex, string timestamp, string nonce) =>
        Encoding.UTF8.GetBytes(string.Join('\n', Scheme, method.ToUpperInvariant(), pathAndQuery, bodyHashHex, timestamp, nonce));
}
