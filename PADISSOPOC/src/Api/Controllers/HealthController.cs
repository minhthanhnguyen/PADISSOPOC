using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Padi.Services.Authentication.Api.Contracts;

namespace Padi.Services.Authentication.Api.Controllers;

/// <summary>
/// Liveness only. Mapped in API Gateway as its own resource with no authorizer, so it must
/// stay anonymous — and must never report anything that would be useful to an unauthenticated
/// caller, such as pool ids or dependency state.
/// </summary>
[ApiController]
[Route("health")]
[AllowAnonymous]
[Produces("application/json")]
public sealed class HealthController : ControllerBase
{
    [HttpGet]
    [ProducesResponseType(typeof(HealthResponse), StatusCodes.Status200OK)]
    public ActionResult<HealthResponse> Get() => Ok(new HealthResponse("ok"));
}
