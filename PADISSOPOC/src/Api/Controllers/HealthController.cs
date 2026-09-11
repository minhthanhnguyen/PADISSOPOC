using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Padi.Services.Authentication.Api.Contracts;

namespace Padi.Services.Authentication.Api.Controllers;

/// <summary>
/// Liveness only. Must never report anything useful to an unauthenticated caller — no pool
/// ids, no dependency state.
///
/// Lives under `/public` rather than at `/health` so it is matched by the same greedy
/// `{proxy+}` gateway resource as every other public route. A dedicated non-greedy resource
/// reached the Lambda with the custom domain's base path still on the front of the request
/// path, and ASP.NET routing then found nothing — the endpoint 404'd in AWS while working
/// locally.
/// </summary>
[ApiController]
[Route("public/health")]
[AllowAnonymous]
[Produces("application/json")]
public sealed class HealthController : ControllerBase
{
    [HttpGet]
    [ProducesResponseType(typeof(HealthResponse), StatusCodes.Status200OK)]
    public ActionResult<HealthResponse> Get() => Ok(new HealthResponse("ok"));
}
