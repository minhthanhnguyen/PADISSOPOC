using System.ComponentModel.DataAnnotations;
using Padi.Services.Authentication.Domain.Identity;

namespace Padi.Services.Authentication.Api.Contracts;

/// <summary>
/// Request bodies. The annotations are enforced by <c>[ApiController]</c>, which returns a
/// 400 with <c>ValidationProblemDetails</c> before the action runs — so a controller only
/// ever sees a body that is structurally valid. Rules that need domain knowledge, such as
/// the Cognito username pattern, still live in the Application layer.
/// </summary>
/// <summary>
/// Every field is optional, matching the pool: none of these attributes is required, so an
/// empty body is a no-op rather than an error and a caller can set one without supplying
/// the others. Sending an empty string clears the attribute.
/// </summary>
public sealed class UpdateProfileRequest
{
    [MaxLength(2048)]
    public string? GivenName { get; init; }

    /// <summary>A single character, stored in the standard <c>middle_name</c> attribute.</summary>
    [MaxLength(1, ErrorMessage = "Middle initial must be a single character.")]
    public string? MiddleInitial { get; init; }

    [MaxLength(2048)]
    public string? FamilyName { get; init; }

    [RegularExpression(BirthdateRules.Pattern, ErrorMessage = "Date of birth must be YYYY-MM-DD.")]
    public string? Birthdate { get; init; }
}

public sealed class ChangeUsernameRequest
{
    [Required(AllowEmptyStrings = false)]
    [MaxLength(128)]
    public string Username { get; init; } = "";
}

public sealed class ChangeEmailRequest
{
    [Required(AllowEmptyStrings = false)]
    [EmailAddress]
    public string Email { get; init; } = "";
}

public sealed class ConfirmEmailRequest
{
    [Required(AllowEmptyStrings = false)]
    public string Code { get; init; } = "";
}

public sealed class SetAttributesRequest
{
    [Required]
    [MinLength(1, ErrorMessage = "At least one attribute is required.")]
    public Dictionary<string, string> Attributes { get; init; } = [];
}

public sealed class SetUsernameRequest
{
    [Required(AllowEmptyStrings = false)]
    [MaxLength(128)]
    public string Username { get; init; } = "";
}

public sealed class RegisterRequest
{
    [Required(AllowEmptyStrings = false)]
    [MaxLength(128)]
    public string Username { get; init; } = "";

    [Required(AllowEmptyStrings = false)]
    [MaxLength(256)]
    public string Password { get; init; } = "";

    [Required(AllowEmptyStrings = false)]
    [EmailAddress]
    public string Email { get; init; } = "";

    // Optional, like the pool's attributes: a sign-up supplying none of these is valid.
    [MaxLength(2048)]
    public string? GivenName { get; init; }

    [MaxLength(1, ErrorMessage = "Middle initial must be a single character.")]
    public string? MiddleInitial { get; init; }

    [MaxLength(2048)]
    public string? FamilyName { get; init; }

    [RegularExpression(BirthdateRules.Pattern, ErrorMessage = "Date of birth must be YYYY-MM-DD.")]
    public string? Birthdate { get; init; }
}

public sealed class LoginRequest
{
    [Required(AllowEmptyStrings = false)]
    [MaxLength(128)]
    public string Username { get; init; } = "";

    [Required(AllowEmptyStrings = false)]
    [MaxLength(256)]
    public string Password { get; init; } = "";
}

public sealed class ForgotPasswordRequest
{
    [Required(AllowEmptyStrings = false)]
    [MaxLength(128)]
    public string Username { get; init; } = "";
}

public sealed class ResetPasswordRequest
{
    [Required(AllowEmptyStrings = false)]
    [MaxLength(128)]
    public string Username { get; init; } = "";

    [Required(AllowEmptyStrings = false)]
    public string Code { get; init; } = "";

    [Required(AllowEmptyStrings = false)]
    [MaxLength(256)]
    public string NewPassword { get; init; } = "";
}

public sealed class ConfirmRegistrationRequest
{
    /// <summary>The opaque id returned by sign-up, not the name the user chose.</summary>
    [Required(AllowEmptyStrings = false)]
    public string AccountId { get; init; } = "";

    [Required(AllowEmptyStrings = false)]
    public string Code { get; init; } = "";
}

public sealed class ResendCodeRequest
{
    [Required(AllowEmptyStrings = false)]
    public string AccountId { get; init; } = "";
}

/// <summary>Query parameters for the user listing.</summary>
public sealed class ListUsersQuery
{
    /// <summary>A single Cognito <c>attribute ^= "value"</c> clause. Free text is rejected.</summary>
    public string? Filter { get; init; }

    [Range(1, 60)]
    public int Limit { get; init; } = 25;

    public string? NextToken { get; init; }
}
