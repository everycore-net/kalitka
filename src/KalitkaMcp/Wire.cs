using System.Security.Cryptography;
using System.Text;

namespace KalitkaMcp;

/// <summary>
/// The client half of the <c>kalitka-agent-sig-v1</c> wire scheme — the same canonical string
/// Core verifies (method, path, body hash, timestamp, nonce, newline-joined, scheme first).
/// Kept tiny and separate so it is trivially tested for byte-for-byte parity with Core's
/// <c>AgentSignatures</c>: the MCP server is just another signed <c>/agent/*</c> client.
/// </summary>
public static class Wire
{
    public const string Scheme = "kalitka-agent-sig-v1";

    public static string Sha256Hex(ReadOnlySpan<byte> body) =>
        Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant();

    public static byte[] CanonicalString(string method, string pathAndQuery, string bodyHashHex, string timestamp, string nonce) =>
        Encoding.UTF8.GetBytes(string.Join('\n', Scheme, method.ToUpperInvariant(), pathAndQuery, bodyHashHex, timestamp, nonce));
}
