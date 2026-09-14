using System.Security.Cryptography;
using System.Text;

namespace KalitkaMcpGateway;

/// <summary>Whether a human can actually review the arguments, or they are too large/opaque to show
/// honestly. Truncating a huge payload down to a few lines and leaving an ordinary Approve button
/// beside it is forbidden — it fakes review; such a call is <see cref="TooLarge"/>.</summary>
public enum Reviewability { Reviewable, TooLarge }

/// <summary>The gateway's verdict on whether an argument payload can be shown for a real decision,
/// with the honest facts (size, digest, a bounded preview). Recorded so it is later provable whether
/// the approver could even see what they approved.</summary>
public sealed record ArgumentReview(Reviewability Verdict, int SizeBytes, string Sha256Hex, string Preview, bool Truncated);

/// <summary>
/// Decides whether canonical arguments are reviewable and produces the honest summary a human sees.
/// Small payloads are shown in full; a large one is not silently trimmed under an Approve button —
/// it is marked <see cref="Reviewability.TooLarge"/> with its size, SHA-256 and a bounded preview,
/// and a tool with <c>require_reviewable_arguments</c> refuses it (or routes it to a dedicated
/// artifact-review flow) rather than letting a human rubber-stamp what they cannot see.
/// </summary>
public static class ArgumentReviewer
{
    public const int DefaultMaxReviewableBytes = 8 * 1024;
    public const int DefaultPreviewChars = 2 * 1024;

    public static ArgumentReview Review(
        ReadOnlySpan<byte> canonicalArgs, int maxReviewableBytes = DefaultMaxReviewableBytes, int previewChars = DefaultPreviewChars)
    {
        var size = canonicalArgs.Length;
        var sha = Convert.ToHexString(SHA256.HashData(canonicalArgs));
        var text = Encoding.UTF8.GetString(canonicalArgs);

        if (size <= maxReviewableBytes)
            return new ArgumentReview(Reviewability.Reviewable, size, sha, text, Truncated: false);

        var preview = text.Length > previewChars ? text[..previewChars] : text;
        return new ArgumentReview(Reviewability.TooLarge, size, sha, preview, Truncated: true);
    }
}
