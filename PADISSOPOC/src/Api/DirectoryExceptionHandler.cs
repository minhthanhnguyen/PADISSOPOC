using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Api;

/// <summary>
/// Translates the Application layer's exception types into status codes.
///
/// Without this every rejected username and every unknown user is a 500, which is both wrong
/// and actively misleading when the caller is a browser. Anything not listed here is left to
/// the default handler and stays a 500 — an unrecognised failure should look like a failure,
/// not be flattened into a tidy 400.
/// </summary>
public sealed class DirectoryExceptionHandler(IAuditLog audit) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(
        HttpContext http, Exception exception, CancellationToken ct)
    {
        var (status, title) = exception switch
        {
            DirectoryValidationException e => (StatusCodes.Status400BadRequest, e.Message),
            AliasAlreadyTakenException e => (StatusCodes.Status409Conflict, e.Message),
            UserNotFoundInDirectoryException e => (StatusCodes.Status404NotFound, e.Message),
            _ => (0, ""),
        };

        if (status == 0)
        {
            audit.Error($"{http.Request.Method} {http.Request.Path} failed: {exception}");
            return false;
        }

        http.Response.StatusCode = status;
        await http.Response.WriteAsJsonAsync(
            new ProblemDetails { Status = status, Title = title }, ct);

        return true;
    }
}
