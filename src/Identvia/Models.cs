using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Identvia;

/// <summary>The parts of <c>/.well-known/openid-configuration</c> the SDK uses.</summary>
public sealed record ProviderMetadata
{
    [JsonPropertyName("issuer")] public required string Issuer { get; init; }
    [JsonPropertyName("authorization_endpoint")] public required string AuthorizationEndpoint { get; init; }
    [JsonPropertyName("token_endpoint")] public required string TokenEndpoint { get; init; }
    [JsonPropertyName("userinfo_endpoint")] public string? UserinfoEndpoint { get; init; }
    [JsonPropertyName("jwks_uri")] public required string JwksUri { get; init; }
    [JsonPropertyName("revocation_endpoint")] public string? RevocationEndpoint { get; init; }
    [JsonPropertyName("introspection_endpoint")] public string? IntrospectionEndpoint { get; init; }
    [JsonPropertyName("end_session_endpoint")] public string? EndSessionEndpoint { get; init; }
    [JsonPropertyName("code_challenge_methods_supported")] public string[]? CodeChallengeMethodsSupported { get; init; }
    [JsonPropertyName("grant_types_supported")] public string[]? GrantTypesSupported { get; init; }
    [JsonPropertyName("authorization_response_iss_parameter_supported")] public bool AuthorizationResponseIssParameterSupported { get; init; }
    /// <summary>Stage 5 (server 2026-10-21_5+).</summary>
    [JsonPropertyName("authorization_details_types_supported")] public string[]? AuthorizationDetailsTypesSupported { get; init; }
    /// <summary>Stage 5 (server 2026-10-21_5+): CIBA.</summary>
    [JsonPropertyName("backchannel_authentication_endpoint")] public string? BackchannelAuthenticationEndpoint { get; init; }
    [JsonPropertyName("backchannel_token_delivery_modes_supported")] public string[]? BackchannelTokenDeliveryModesSupported { get; init; }
}

/// <summary>The signed-in user, from the validated ID token. <c>Sub</c> is pairwise: stable for your app only.</summary>
public sealed record IdentviaUser
{
    public required string Sub { get; init; }
    public string? Email { get; init; }
    public bool? EmailVerified { get; init; }
    public string? Name { get; init; }
    public string? GivenName { get; init; }
    public string? FamilyName { get; init; }
    public string? Picture { get; init; }
    public string? Locale { get; init; }
    public long? AuthTime { get; init; }
    /// <summary>All ID token claims, as JSON.</summary>
    public required JsonObject Claims { get; init; }

    internal static IdentviaUser From(JsonObject c) => new()
    {
        Sub = c.Str("sub") ?? "", Email = c.Str("email"), EmailVerified = c.Bool("email_verified"), Name = c.Str("name"),
        GivenName = c.Str("given_name"), FamilyName = c.Str("family_name"), Picture = c.Str("picture"), Locale = c.Str("locale"),
        AuthTime = c.Num("auth_time") is double d ? (long)d : null, Claims = c,
    };
}

public sealed record TokenSet
{
    public required string AccessToken { get; init; }
    public string TokenType { get; init; } = "Bearer";
    public required DateTimeOffset ExpiresAt { get; init; }
    public string? RefreshToken { get; init; }
    public string? IdToken { get; init; }
    public string? Scope { get; init; }
    /// <summary>RFC 9396 details the user approved (server 2026-10-21_5+).</summary>
    public JsonArray? AuthorizationDetails { get; init; }
    /// <summary>RFC 8693 <c>issued_token_type</c> (token exchange only).</summary>
    public string? IssuedTokenType { get; init; }
}

public sealed record IdentviaSession(IdentviaUser User, TokenSet Tokens);

/// <summary>One RFC 9396 authorization detail. Requires server 2026-10-21_5+.</summary>
public sealed record AuthorizationDetail(string Type, IReadOnlyDictionary<string, JsonNode?>? Fields = null)
{
    /// <summary>An <c>agent_task</c> detail, shown to the user on the consent screen.</summary>
    public static AuthorizationDetail AgentTask(string description, IEnumerable<string>? actions = null, IEnumerable<string>? locations = null)
    {
        if (string.IsNullOrWhiteSpace(description)) throw new ArgumentException("agentTask needs a description.", nameof(description));
        var f = new Dictionary<string, JsonNode?> { ["description"] = description };
        if (actions is not null) f["actions"] = new JsonArray(actions.Select(a => (JsonNode?)a).ToArray());
        if (locations is not null) f["locations"] = new JsonArray(locations.Select(a => (JsonNode?)a).ToArray());
        return new AuthorizationDetail("agent_task", f);
    }

    public JsonObject ToJson()
    {
        var o = new JsonObject();
        foreach (var (k, v) in Fields ?? new Dictionary<string, JsonNode?>()) o[k] = v?.DeepClone();
        o["type"] = Type;
        return o;
    }

    internal static string Encode(IEnumerable<AuthorizationDetail> d) => new JsonArray(d.Select(x => (JsonNode)x.ToJson()).ToArray()).ToJsonString();
}

/// <summary>What one sign-in attempt remembers between opening the browser and handling the redirect.</summary>
public sealed record AuthorizationTransaction(string State, string Nonce, string CodeVerifier, string RedirectUri, int? MaxAge);

internal static class JsonExt
{
    public static string? Str(this JsonObject o, string k) => o.TryGetPropertyValue(k, out var v) && v is JsonValue jv && jv.GetValueKind() == JsonValueKind.String ? jv.GetValue<string>() : null;
    public static double? Num(this JsonObject o, string k) => o.TryGetPropertyValue(k, out var v) && v is JsonValue jv && jv.GetValueKind() == JsonValueKind.Number ? jv.GetValue<double>() : null;
    public static bool? Bool(this JsonObject o, string k) => o.TryGetPropertyValue(k, out var v) && v is JsonValue jv && jv.GetValueKind() is JsonValueKind.True or JsonValueKind.False ? jv.GetValue<bool>() : null;
    public static JsonObject? ParseObject(string s) { try { return JsonNode.Parse(s) as JsonObject; } catch (JsonException) { return null; } }
}

[JsonSerializable(typeof(ProviderMetadata))]
[JsonSerializable(typeof(IdentviaSession))]
internal sealed partial class IdentviaJson : JsonSerializerContext;
