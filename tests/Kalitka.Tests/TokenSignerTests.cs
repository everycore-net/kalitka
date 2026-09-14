using Kalitka;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The per-purpose signer on its own: purpose isolation (a token minted for one
/// key id never verifies under another) and the rotation overlap (the previous
/// master is accepted on verification only, so rotating the secret does not
/// invalidate tokens already in flight).
/// </summary>
public class TokenSignerTests
{
    private const string OldSecret = "old-master-aaaaaaaaaaaaaaaaaaaa";
    private const string NewSecret = "new-master-bbbbbbbbbbbbbbbbbbbb";

    [Fact]
    public void Sign_then_verify_round_trips_the_payload()
    {
        var s = new TokenSigner("unit-test-master-0123456789");
        var token = s.Sign("hello", "admin:v1");
        Assert.True(s.Verify(token, "admin:v1", out var payload));
        Assert.Equal("hello", payload);
    }

    [Fact]
    public void A_token_minted_for_one_purpose_never_verifies_under_another()
    {
        var s = new TokenSigner("unit-test-master-0123456789");
        var token = s.Sign("hello", "admin:v1");
        Assert.False(s.Verify(token, "admin-state:v1", out _));
    }

    [Fact]
    public void Tampered_token_is_rejected()
    {
        var s = new TokenSigner("unit-test-master-0123456789");
        var token = s.Sign("hello", "admin:v1");
        var tampered = token[..^1] + (token[^1] == 'a' ? 'b' : 'a');
        Assert.False(s.Verify(tampered, "admin:v1", out _));
    }

    // ---- rotation overlap -------------------------------------------------------

    [Fact]
    public void A_token_from_the_previous_master_still_verifies_during_the_overlap()
    {
        var oldToken = new TokenSigner(OldSecret).Sign("hello", "admin:v1");
        var rotated = new TokenSigner(NewSecret, previousMaster: OldSecret);
        Assert.True(rotated.Verify(oldToken, "admin:v1", out var payload));
        Assert.Equal("hello", payload);
    }

    [Fact]
    public void A_new_token_is_signed_with_the_current_master_only()
    {
        var rotated = new TokenSigner(NewSecret, previousMaster: OldSecret);
        var fresh = rotated.Sign("hello", "admin:v1");

        Assert.True(new TokenSigner(NewSecret).Verify(fresh, "admin:v1", out _));
        Assert.False(new TokenSigner(OldSecret).Verify(fresh, "admin:v1", out _));
    }

    [Fact]
    public void Once_the_overlap_closes_previous_tokens_are_rejected()
    {
        var oldToken = new TokenSigner(OldSecret).Sign("hello", "admin:v1");
        Assert.False(new TokenSigner(NewSecret).Verify(oldToken, "admin:v1", out _));
    }

    [Fact]
    public void Purpose_isolation_holds_across_the_overlap()
    {
        // A previous-master token still must not cross purposes during the window.
        var oldToken = new TokenSigner(OldSecret).Sign("hello", "admin:v1");
        var rotated = new TokenSigner(NewSecret, previousMaster: OldSecret);
        Assert.False(rotated.Verify(oldToken, "admin-state:v1", out _));
    }
}
