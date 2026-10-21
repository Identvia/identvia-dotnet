namespace Identvia;

/// <summary>Base class for every error the SDK throws.</summary>
public class IdentviaException : Exception
{
    public IdentviaException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>The SDK was set up wrongly (issuer, client ID, redirect URI).</summary>
public sealed class IdentviaConfigurationException(string message) : IdentviaException(message);

/// <summary>The user closed the browser, or the sign-in timed out.</summary>
public sealed class IdentviaCancelledException(string message = "Sign-in was cancelled.") : IdentviaException(message);

/// <summary>The redirect didn't belong to this sign-in (state, iss or redirect mismatch).</summary>
public sealed class IdentviaInvalidStateException(string message) : IdentviaException(message);

/// <summary>Identvia sent an error to the redirect URI, for example <c>access_denied</c>.</summary>
public sealed class IdentviaAuthorizationException(string error, string? description)
    : IdentviaException($"Authorization failed: {error}{(description is null ? "" : $" ({description})")}")
{
    public string Error { get; } = error;
    public string? Description { get; } = description;
}

/// <summary>The token, userinfo, introspection or CIBA endpoint returned an error.</summary>
public sealed class IdentviaTokenException(string error, string? description, int status)
    : IdentviaException($"Token request failed ({status}): {error}{(description is null ? "" : $" ({description})")}")
{
    public string Error { get; } = error;
    public string? Description { get; } = description;
    public int Status { get; } = status;
}

/// <summary>An ID token or response failed validation.</summary>
public sealed class IdentviaValidationException(string message) : IdentviaException(message);

/// <summary>The server doesn't support this yet. Stage-5 features need server 2026-10-21_5+.</summary>
public sealed class IdentviaUnsupportedException(string message) : IdentviaException(message);

/// <summary>The session ended (refresh token expired, revoked or reused). Sign in again.</summary>
public sealed class IdentviaLoginRequiredException() : IdentviaException("The session has ended; sign in again.");

public sealed class IdentviaNetworkException(string message, Exception? inner = null) : IdentviaException(message, inner);
