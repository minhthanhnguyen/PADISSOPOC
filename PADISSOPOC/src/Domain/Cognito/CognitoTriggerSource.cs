namespace Padi.Services.Authentication.Domain.Cognito;

/// <summary>
/// A Cognito custom-sender trigger source. The short name (the part after the
/// <c>CustomEmailSender_</c> prefix) is the key used to look up a message template.
/// </summary>
public readonly record struct CognitoTriggerSource(string Value)
{
    private const string EmailSenderPrefix = "CustomEmailSender_";

    public string? TemplateName =>
        Value.StartsWith(EmailSenderPrefix, StringComparison.Ordinal)
            ? Value[EmailSenderPrefix.Length..]
            : null;

    public override string ToString() => Value;
}
