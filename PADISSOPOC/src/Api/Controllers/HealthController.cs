using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Padi.Services.Authentication.Api.Contracts;

namespace Padi.Services.Authentication.Api.Controllers;

/// <summary>
/// Liveness only. Must never report anything useful to an unauthenticated caller — no pool
/// ids, no dependency state.
///
/// An open route: listed in the gateway's openRoutes in PadiSsoApiStack, which is what lets
/// it skip the Cognito authorizer. Reachable at /health in AWS only because the API strips
/// the custom domain's base path (API_BASE_PATH) — a named gateway resource forwards it.
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
