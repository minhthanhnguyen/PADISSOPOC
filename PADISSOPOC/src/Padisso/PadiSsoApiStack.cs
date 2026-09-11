using System.Collections.Generic;
using System.Linq;
using Amazon.CDK;
using Amazon.CDK.AWS.APIGateway;
// Aliased: the v2 namespace differs from v1 only by casing (Apigatewayv2 vs APIGateway),
// which is too easy to misread at a glance.
using ApiGwV2 = Amazon.CDK.AWS.Apigatewayv2;
using Amazon.CDK.AWS.Cognito;
using Amazon.CDK.AWS.IAM;
using Amazon.CDK.AWS.Lambda;
using Constructs;

namespace Padi.Services.Authentication
{
    public sealed class PadiSsoApiStackProps : StackProps
    {
        /// <summary>Passed by reference rather than imported by name, so CDK orders the two stacks.</summary>
        public IUserPool UserPool { get; set; }

        public IUserPoolClient UserPoolClient { get; set; }
    }

    /// <summary>
    /// REST API in front of the ASP.NET Core management API.
    ///
    /// REST (v1) rather than HTTP (v2) because only REST APIs can be associated with AWS WAF,
    /// and this fronts authentication data. The extra per-request cost buys WAF, request
    /// validation and usage plans. WAF attaches to the stage with a REGIONAL-scoped web ACL
    /// regardless of the endpoint type below.
    /// </summary>
    public class PadiSsoApiStack : Stack
    {
        public RestApi RestApi { get; }
        public Function ApiFunction { get; }

        internal PadiSsoApiStack(Construct scope, string id, PadiSsoApiStackProps props)
            : base(scope, id, props)
        {
            var apiName          = (string)Node.TryGetContext("apiName") ?? "padi-sso-poc-api";
            var stageName        = (string)Node.TryGetContext("apiStageName") ?? "v1";
            // An existing custom domain, owned outside this stack, plus the base path to
            // claim under it. Leave apiDomainName empty and the API is reachable only at
            // its execute-api URL.
            var domainName       = (string)Node.TryGetContext("apiDomainName");
            var basePath         = (string)Node.TryGetContext("apiBasePath") ?? "";

            // Edge-optimized routes through a service-managed CloudFront POP; regional
            // resolves straight to this region. The choice is not free-standing — it has to
            // agree with the custom domain the API is mapped under.
            var endpointTypeName = ((string)Node.TryGetContext("apiEndpointType") ?? "edge")
                .Trim().ToLowerInvariant();
            var endpointType = endpointTypeName switch
            {
                "edge" or "edge-optimized" => EndpointType.EDGE,
                "regional" => EndpointType.REGIONAL,
                _ => throw new System.InvalidOperationException(
                    $"apiEndpointType must be 'edge' or 'regional', not '{endpointTypeName}'."),
            };
            var adminGroup       = (string)Node.TryGetContext("adminGroupName") ?? "padi-sso-admins";
            var allowedOrigins   = ((object[])Node.TryGetContext("apiAllowedOrigins") ?? System.Array.Empty<object>())
                .Select(o => o.ToString()).ToArray();
            var throttleRate     = System.Convert.ToDouble(Node.TryGetContext("apiThrottleRatePerSecond") ?? 50);
            var throttleBurst    = System.Convert.ToDouble(Node.TryGetContext("apiThrottleBurst") ?? 100);

            // Membership of this group is what the API checks before allowing an /admin route.
            new CfnUserPoolGroup(this, "AdminGroup", new CfnUserPoolGroupProps
            {
                UserPoolId = props.UserPool.UserPoolId,
                GroupName = adminGroup,
                Description = "May call the /admin routes of the management API.",
            });

            ApiFunction = new Function(this, "ApiFn", new FunctionProps
            {
                FunctionName = "padi-sso-poc-api",
                Runtime = Runtime.DOTNET_10,
                // ASP.NET Core hosted in Lambda: the whole pipeline is one handler.
                Handler = "Api",
                Code = Code.FromAsset("src/Api/bin/Release/net10.0/linux-x64/publish"),
                // Larger than the triggers: an ASP.NET Core cold start does noticeably more
                // work, and CPU is allocated in proportion to memory.
                MemorySize = 1024,
                Timeout = Duration.Seconds(30),
                Environment = new Dictionary<string, string>
                {
                    ["USER_POOL_ID"] = props.UserPool.UserPoolId,
                    ["USER_POOL_CLIENT_ID"] = props.UserPoolClient.UserPoolClientId,
                    ["ADMIN_GROUP"] = adminGroup,
                    // The gateway's CORS config only answers preflight; the app has to put
                    // the header on the real response, so it needs the same origin list.
                    ["ALLOWED_ORIGINS"] = string.Join(",", allowedOrigins),
                    ["ASPNETCORE_ENVIRONMENT"] = "Production",
                },
            });

            // Scoped to this pool. Deliberately excludes AdminDeleteUser and
            // AdminSetUserPassword: neither is reachable from the API, and a permission the
            // code cannot use is a permission waiting to be misused.
            ApiFunction.AddToRolePolicy(new PolicyStatement(new PolicyStatementProps
            {
                Actions = new[]
                {
                    "cognito-idp:ListUsers",
                    "cognito-idp:AdminGetUser",
                    "cognito-idp:AdminUpdateUserAttributes",
                    "cognito-idp:AdminEnableUser",
                    "cognito-idp:AdminDisableUser",
                    "cognito-idp:AdminResetUserPassword",
                    "cognito-idp:AdminListGroupsForUser",
                    "cognito-idp:AdminAddUserToGroup",
                    "cognito-idp:AdminRemoveUserFromGroup",
                    // Backs /public/login via ADMIN_USER_PASSWORD_AUTH.
                    "cognito-idp:AdminInitiateAuth",
                },
                Resources = new[] { props.UserPool.UserPoolArn },
            }));

            RestApi = new RestApi(this, "PADISSOPOCRestApi", new RestApiProps
            {
                RestApiName = apiName,
                Description = "PADI SSO management API",
                DeployOptions = new StageOptions
                {
                    StageName = stageName,
                    ThrottlingRateLimit = throttleRate,
                    ThrottlingBurstLimit = throttleBurst,
                    MetricsEnabled = true,
                },
                DefaultCorsPreflightOptions = allowedOrigins.Length > 0
                    ? new CorsOptions
                    {
                        AllowOrigins = allowedOrigins,
                        AllowMethods = Cors.ALL_METHODS,
                        AllowHeaders = new[] { "Authorization", "Content-Type" },
                        AllowCredentials = false,
                    }
                    : null,
                // Everything is JSON; binary media types would break the proxy payload.
                // Must match the endpoint type of the custom domain this maps under.
                EndpointConfiguration = new EndpointConfiguration
                {
                    Types = new[] { endpointType },
                },
            });

            var authorizer = new CognitoUserPoolsAuthorizer(this, "PoolAuthorizer", new CognitoUserPoolsAuthorizerProps
            {
                CognitoUserPools = new[] { props.UserPool },
                AuthorizerName = "padi-sso-poc-pool-authorizer",
                IdentitySource = "method.request.header.Authorization",
            });

            var integration = new LambdaIntegration(ApiFunction, new LambdaIntegrationOptions
            {
                Proxy = true,
            });

            // Health check lives at /public/health, under the proxy resource below, rather
            // than as its own /health resource. A non-greedy resource forwards the request
            // with the custom domain's base path still attached, which ASP.NET routing does
            // not match — it 404s in AWS while working locally.

            // Registration: a user cannot hold a token before their account exists, so these
            // routes cannot sit behind the authorizer. Declared as its own resource rather
            // than by exempting paths inside the API, which keeps the unauthenticated
            // surface visible here and in RegistrationController — a more specific resource
            // takes precedence over the root {proxy+} below.
            RestApi.Root.AddResource("public").AddResource("{proxy+}").AddMethod("ANY", integration,
                new MethodOptions { AuthorizationType = AuthorizationType.NONE });

            // Everything else goes through the pool authorizer. The API re-validates the
            // token itself — see the comment in src/Api/Program.cs for why.
            var proxy = RestApi.Root.AddResource("{proxy+}");
            proxy.AddMethod("ANY", integration, new MethodOptions
            {
                AuthorizationType = AuthorizationType.COGNITO,
                Authorizer = authorizer,
            });

            // The custom domain already exists and is owned elsewhere — this stack only
            // claims a base path under it. Nothing here creates or modifies the domain, so
            // no certificate is needed and `cdk destroy` removes only the mapping.
            if (!string.IsNullOrWhiteSpace(domainName))
            {
                // An empty mapping key is the "(none)" catch-all: API Gateway routes every
                // request that matches no other mapping to it. On a shared domain that
                // captures other teams' traffic. Refused rather than guessed at.
                if (string.IsNullOrWhiteSpace(basePath))
                {
                    throw new System.InvalidOperationException(
                        "apiBasePath must be set when apiDomainName is set: an empty path becomes " +
                        "the (none) catch-all mapping for a domain this stack does not own.");
                }

                // Mapping keys accept only letters, numbers and $-_.+!*'()/ — a stray space
                // or colon is rejected at deploy, long after synth has passed.
                if (!System.Text.RegularExpressions.Regex.IsMatch(basePath, @"^[A-Za-z0-9$\-_.+!*'()/]+$"))
                {
                    throw new System.InvalidOperationException(
                        $"apiBasePath '{basePath}' contains characters API Gateway rejects. " +
                        "Allowed: letters, numbers and $-_.+!*'()/");
                }

                // ApiGatewayV2's ApiMapping, not ApiGateway's BasePathMapping, even though
                // this is a REST API: multi-level paths such as "p/padi-auth-poc" are only
                // supported through V2. AWS is explicit — "To create API mappings with
                // multiple levels, you must use AWS::ApiGatewayV2." A BasePathMapping here
                // synthesizes fine and fails at deploy.
                //
                // Requires the domain to be REGIONAL with the TLS 1.2 security policy, which
                // api.global-np.padi.com is.
                new ApiGwV2.CfnApiMapping(this, "ApiMapping", new ApiGwV2.CfnApiMappingProps
                {
                    DomainName = domainName,
                    ApiId = RestApi.RestApiId,
                    // Without an explicit stage the mapping targets the API's default stage,
                    // which this API does not define.
                    Stage = RestApi.DeploymentStage.StageName,
                    ApiMappingKey = basePath,
                });

                new CfnOutput(this, "ApiPublicUrl", new CfnOutputProps
                {
                    Value = $"https://{domainName}/{basePath}",
                    Description = "Public base URL — the base path is stripped before the API sees the request",
                });
            }

            new CfnOutput(this, "ApiInvokeUrl", new CfnOutputProps
            {
                Value = RestApi.Url,
                Description = "Execute-api endpoint (works whether or not a custom domain is set)",
            });
        }
    }
}
