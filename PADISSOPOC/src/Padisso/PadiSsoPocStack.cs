using System.Collections.Generic;
using System.Linq;
using Amazon.CDK;
using Amazon.CDK.AWS.CertificateManager;
using Amazon.CDK.AWS.Cognito;
using Amazon.CDK.AWS.DynamoDB;
using Amazon.CDK.AWS.IAM;
using Amazon.CDK.AWS.KMS;
using Amazon.CDK.AWS.Lambda;
using Amazon.CDK.AWS.SecretsManager;
using Constructs;

namespace Padi.Services.Authentication
{
    public class PadiSsoPocStack : Stack
    {
        public UserPool UserPool { get; }
        public UserPoolClient UserPoolClient { get; }
        public UserPoolDomain UserPoolDomain { get; }


        internal PadiSsoPocStack(Construct scope, string id, IStackProps props = null) : base(scope, id, props)
        {
            // Identity providers are opt-in per environment. A provider's secrets are only
            // read when it is enabled — an unreferenced secret never becomes a CloudFormation
            // dynamic reference, so the stack deploys without credentials for providers you
            // have not set up yet.
            var enabledIdps = new HashSet<string>(
                ((object[])Node.TryGetContext("enabledIdps") ?? System.Array.Empty<object>())
                    .Select(p => p.ToString()!.Trim().ToLowerInvariant()));

            var featurePlanName = ((string)Node.TryGetContext("featurePlan") ?? "essentials").Trim().ToLowerInvariant();
            var featurePlan = featurePlanName switch
            {
                "lite"       => FeaturePlan.LITE,
                "essentials" => FeaturePlan.ESSENTIALS,
                "plus"       => FeaturePlan.PLUS,
                _ => throw new System.ArgumentException(
                    $"Unknown featurePlan '{featurePlanName}' in cdk.json. Expected: lite, essentials, or plus."),
            };

            var userPoolName = (string)Node.TryGetContext("userPoolName");
            var passkeyRelyingPartyId = (string)Node.TryGetContext("passkeyRelyingPartyId");
            var cognitoDomainHost    = new System.Uri((string)Node.TryGetContext("cognitoDomain")).Host;
            var cognitoDomainCertArn = (string)Node.TryGetContext("cognitoDomainCertArn");
            var callbackUrls        = ((object[])Node.TryGetContext("callbackUrls")).Select(u => u.ToString()).ToArray();
            var logoutUrls          = ((object[])Node.TryGetContext("logoutUrls")).Select(u => u.ToString()).ToArray();
            var magicLinkBaseUrl    = (string)Node.TryGetContext("magicLinkBaseUrl");
            var magicLinkEmailFrom  = (string)Node.TryGetContext("magicLinkEmailFrom");
            var magicLinkSmsSenderId = (string)Node.TryGetContext("magicLinkSmsSenderId");
            var messagingEmailUrl   = (string)Node.TryGetContext("messagingEmailUrl");
            var messagingTokenUrl   = (string)Node.TryGetContext("messagingTokenUrl");
            var magicLinkAllowedOrigins = ((object[])Node.TryGetContext("magicLinkAllowedOrigins")
                    ?? System.Array.Empty<object>())
                .Select(o => o.ToString()!).ToArray();

            // Token store for magic links — keyed by SHA-256 hash of the raw token
            var magicLinkTable = new Table(this, "MagicLinkTokens", new TableProps
            {
                TableName = "padi-sso-poc-magic-links",
                PartitionKey = new Amazon.CDK.AWS.DynamoDB.Attribute
                {
                    Name = "tokenHash",
                    Type = AttributeType.STRING,
                },
                TimeToLiveAttribute = "expiresAt",
                BillingMode = BillingMode.PAY_PER_REQUEST,
                RemovalPolicy = RemovalPolicy.DESTROY,
            });

            // Shared secret between VerifyMagicLinkFn and the Cognito Verify trigger
            var adminProofSecret = new Secret(this, "MagicLinkAdminProof", new SecretProps
            {
                SecretName = "padisso-poc/magic-link/admin-proof",
                GenerateSecretString = new SecretStringGenerator
                {
                    ExcludePunctuation = true,
                    PasswordLength = 64,
                },
                RemovalPolicy = RemovalPolicy.DESTROY,
            });

            // Each Lambda is its own project. Run ./publish-lambdas.ps1 before cdk synth/deploy.
            static AssetCode LambdaCode(string project) =>
                Code.FromAsset($"src/Lambdas/{project}/bin/Release/net10.0/linux-x64/publish");

            var defineFn = new Function(this, "DefineAuthChallengeFn", new FunctionProps
            {
                FunctionName = "padi-sso-poc-define-auth",
                Runtime = Runtime.DOTNET_10,
                Handler = "DefineAuthChallenge::Padi.Services.Authentication.Cognito.DefineAuthChallenge.Function::Handler",
                Code = LambdaCode("DefineAuthChallenge"),
                Timeout = Duration.Seconds(30),
                MemorySize = 256,
            });

            var createFn = new Function(this, "CreateAuthChallengeFn", new FunctionProps
            {
                FunctionName = "padi-sso-poc-create-auth",
                Runtime = Runtime.DOTNET_10,
                Handler = "CreateAuthChallenge::Padi.Services.Authentication.Cognito.CreateAuthChallenge.Function::Handler",
                Code = LambdaCode("CreateAuthChallenge"),
                Timeout = Duration.Seconds(30),
                MemorySize = 256,
            });

            // Cognito encrypts one-time codes with this key before handing them to the
            // custom sender trigger; the trigger decrypts them via the AWS Encryption SDK.
            var codeKey = new Key(this, "CognitoCodeKey", new KeyProps
            {
                Alias = "alias/padi-sso-poc-cognito-codes",
                Description = "Encrypts Cognito one-time codes for the custom sender triggers",
                EnableKeyRotation = true,
                RemovalPolicy = RemovalPolicy.DESTROY,
            });
            codeKey.GrantEncrypt(new ServicePrincipal("cognito-idp.amazonaws.com"));

            // Credentials live under this SSM path and are loaded by the configuration
            // provider at runtime, so they never appear in GetFunctionConfiguration output.
            // Parameter names map onto configuration keys: the path prefix is stripped, so
            // /padi/services/authentication/Messaging/ClientId becomes "Messaging:ClientId",
            // the same key an env var would produce.
            const string configParameterPath = "/padi/services/authentication";

            var messagingEnv = new Dictionary<string, string>
            {
                ["CONFIG_PARAMETER_PATH"]   = configParameterPath,
                ["Messaging__EmailUrl"]     = messagingEmailUrl,
                ["Messaging__TokenUrl"]     = messagingTokenUrl,
                ["Messaging__FromAddress"]  = magicLinkEmailFrom,
                ["KEY_ARN"]                 = codeKey.KeyArn,
            };

            // Template ids are deliberately NOT set here. They live in SSM under
            // <configParameterPath>/Messaging/Definitions/<TriggerSource>, and because
            // LambdaHost applies environment variables after SSM, an env var of the same
            // name would silently shadow the parameter.

            var customEmailSenderFn = new Function(this, "CustomEmailSenderFn", new FunctionProps
            {
                FunctionName = "padi-sso-poc-custom-email-sender",
                Runtime = Runtime.DOTNET_10,
                Handler = "CustomEmailSender::Padi.Services.Authentication.Cognito.CustomEmailSender.Function::Handler",
                Code = LambdaCode("CustomEmailSender"),
                Timeout = Duration.Seconds(30),
                MemorySize = 512,
                Environment = messagingEnv,
            });
            codeKey.GrantDecrypt(customEmailSenderFn);

            // The configuration provider enumerates the path, so GetParametersByPath is
            // required in addition to the single-parameter reads.
            //
            // Two ARNs are needed, not one: GetParametersByPath authorizes against the
            // path *node* (no trailing wildcard), while GetParameter authorizes against
            // the individual parameters beneath it. Granting only ".../*" fails the
            // enumeration call.
            customEmailSenderFn.AddToRolePolicy(new PolicyStatement(new PolicyStatementProps
            {
                Actions = new[] { "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath" },
                Resources = new[]
                {
                    FormatArn(new ArnComponents
                    {
                        Service = "ssm",
                        Resource = "parameter",
                        ResourceName = configParameterPath.TrimStart('/'),
                    }),
                    FormatArn(new ArnComponents
                    {
                        Service = "ssm",
                        Resource = "parameter",
                        ResourceName = $"{configParameterPath.TrimStart('/')}/*",
                    }),
                },
            }));

            // SecureString parameters are decrypted with the AWS-managed SSM key. Scoped
            // by ViaService so this grant cannot be used against other KMS keys directly.
            customEmailSenderFn.AddToRolePolicy(new PolicyStatement(new PolicyStatementProps
            {
                Actions = new[] { "kms:Decrypt" },
                Resources = new[] { "*" },
                Conditions = new Dictionary<string, object>
                {
                    ["StringEquals"] = new Dictionary<string, string>
                    {
                        ["kms:ViaService"] = $"ssm.{Region}.amazonaws.com",
                    },
                },
            }));

            var postAuthFn = new Function(this, "PostAuthenticationFn", new FunctionProps
            {
                FunctionName = "padi-sso-poc-post-auth",
                Runtime = Runtime.DOTNET_10,
                Handler = "PostAuthentication::Padi.Services.Authentication.Cognito.PostAuthentication.Function::Handler",
                Code = LambdaCode("PostAuthentication"),
                Timeout = Duration.Seconds(30),
                MemorySize = 256,
            });

            var verifyFn = new Function(this, "VerifyAuthChallengeFn", new FunctionProps
            {
                FunctionName = "padi-sso-poc-verify-auth",
                Runtime = Runtime.DOTNET_10,
                Handler = "VerifyAuthChallenge::Padi.Services.Authentication.Cognito.VerifyAuthChallenge.Function::Handler",
                Code = LambdaCode("VerifyAuthChallenge"),
                Timeout = Duration.Seconds(30),
                MemorySize = 256,
                Environment = new Dictionary<string, string>
                {
                    ["ADMIN_PROOF"] = adminProofSecret.SecretValue.UnsafeUnwrap(),
                },
            });

            UserPool = new UserPool(this, "PadissoUserPool", new UserPoolProps
            {
                UserPoolName = userPoolName,
                FeaturePlan = featurePlan,
                SelfSignUpEnabled = true,
                SignInAliases = new SignInAliases
                {
                    Username = true,
                    Email = false,
                    Phone = false,
                },
                SignInCaseSensitive = false,
                SignInPolicy = new SignInPolicy
                {
                    AllowedFirstAuthFactors = new AllowedFirstAuthFactors
                    {
                        Password = true,
                        EmailOtp = true,
                        SmsOtp = true,
                        Passkey = true,
                    },
                },
                PasskeyRelyingPartyId = passkeyRelyingPartyId,
                PasskeyUserVerification = PasskeyUserVerification.PREFERRED,
                AutoVerify = new AutoVerifiedAttrs { Email = true, Phone = true },
                KeepOriginal = new KeepOriginalAttrs { Email = true, Phone = true },
                StandardAttributes = new StandardAttributes
                {
                    Email = new StandardAttribute { Required = false, Mutable = true },
                    PhoneNumber = new StandardAttribute { Required = false, Mutable = true },
                    GivenName = new StandardAttribute { Required = false, Mutable = true },
                    FamilyName = new StandardAttribute { Required = false, Mutable = true },
                    Birthdate = new StandardAttribute { Required = false, Mutable = true },
                },
                CustomAttributes = new System.Collections.Generic.Dictionary<string, ICustomAttribute>
                {
                    ["padi_id"]      = new StringAttribute(new StringAttributeProps { Mutable = true }),
                    ["affiliate_id"] = new StringAttribute(new StringAttributeProps { Mutable = true }),
                    // Written by the PostAuthentication trigger on every sign-in.
                    ["last_login"]   = new StringAttribute(new StringAttributeProps { Mutable = true }),
                },
                PasswordPolicy = new PasswordPolicy
                {
                    MinLength = 6,
                    RequireDigits = false,
                    RequireLowercase = true,
                    RequireUppercase = true,
                    RequireSymbols = false,
                },
                AccountRecovery = AccountRecovery.EMAIL_AND_PHONE_WITHOUT_MFA,
                // RETAIN so a CloudFormation replacement orphans the pool rather than
                // deleting every user with it. `cdk destroy` will no longer remove it.
                RemovalPolicy = RemovalPolicy.RETAIN,
                LambdaTriggers = new UserPoolTriggers
                {
                    DefineAuthChallenge = defineFn,
                    CreateAuthChallenge = createFn,
                    VerifyAuthChallengeResponse = verifyFn,
                    PostAuthentication = postAuthFn,
                    // Takes over ALL Cognito-originated email, including passwordless
                    // email OTP (CustomEmailSender_Authentication). Cognito sends nothing
                    // itself once this is set — there is no fallback if the trigger fails.
                    CustomEmailSender = customEmailSenderFn,
                },
                CustomSenderKmsKey = codeKey,
            });

            // Attached as a standalone Policy rather than via postAuthFn.AddToRolePolicy().
            // The pool references this function in LambdaConfig, and CDK makes a function
            // DependsOn its role's default policy — so putting a UserPoolArn reference in
            // that default policy closes a cycle:
            //   UserPool -> PostAuthenticationFn -> DefaultPolicy -> UserPool
            // A separate Policy resource has no incoming edge from the function, so the
            // graph stays acyclic while the permission remains scoped to this pool.
            new Policy(this, "PostAuthCognitoPolicy", new PolicyProps
            {
                Roles = new[] { postAuthFn.Role! },
                Statements = new[]
                {
                    new PolicyStatement(new PolicyStatementProps
                    {
                        Actions   = new[] { "cognito-idp:AdminUpdateUserAttributes" },
                        Resources = new[] { UserPool.UserPoolArn },
                    }),
                },
            });

            // Built up as providers are enabled; the client is configured from these below.
            var idpDependencies = new List<IDependable>();
            var clientIdps = new List<UserPoolClientIdentityProvider> { UserPoolClientIdentityProvider.COGNITO };

            if (enabledIdps.Contains("google"))
            {
                idpDependencies.Add(new UserPoolIdentityProviderGoogle(this, "GoogleProvider", new UserPoolIdentityProviderGoogleProps
                {
                    UserPool = UserPool,
                    ClientId = SecretValue.SecretsManager("padisso-poc/google/client-id").UnsafeUnwrap(),
                    ClientSecretValue = SecretValue.SecretsManager("padisso-poc/google/client-secret"),
                    Scopes = new[] { "email", "profile", "openid" },
                    AttributeMapping = new AttributeMapping
                    {
                        Email = ProviderAttribute.GOOGLE_EMAIL,
                        GivenName = ProviderAttribute.GOOGLE_GIVEN_NAME,
                        FamilyName = ProviderAttribute.GOOGLE_FAMILY_NAME,
                    },
                }));
                clientIdps.Add(UserPoolClientIdentityProvider.GOOGLE);
            }

            if (enabledIdps.Contains("apple"))
            {
                idpDependencies.Add(new UserPoolIdentityProviderApple(this, "AppleProvider", new UserPoolIdentityProviderAppleProps
                {
                    UserPool = UserPool,
                    ClientId = SecretValue.SecretsManager("padisso-poc/apple/client-id").UnsafeUnwrap(),
                    TeamId = SecretValue.SecretsManager("padisso-poc/apple/team-id").UnsafeUnwrap(),
                    KeyId = SecretValue.SecretsManager("padisso-poc/apple/key-id").UnsafeUnwrap(),
                    PrivateKeyValue = SecretValue.SecretsManager("padisso-poc/apple/private-key"),
                    Scopes = new[] { "email", "name" },
                    AttributeMapping = new AttributeMapping
                    {
                        Email = ProviderAttribute.APPLE_EMAIL,
                        GivenName = ProviderAttribute.APPLE_FIRST_NAME,
                        FamilyName = ProviderAttribute.APPLE_LAST_NAME,
                    },
                }));
                clientIdps.Add(UserPoolClientIdentityProvider.APPLE);
            }

            if (enabledIdps.Contains("facebook"))
            {
                idpDependencies.Add(new UserPoolIdentityProviderFacebook(this, "FacebookProvider", new UserPoolIdentityProviderFacebookProps
                {
                    UserPool = UserPool,
                    ClientId = SecretValue.SecretsManager("padisso-poc/facebook/client-id").UnsafeUnwrap(),
                    ClientSecret = SecretValue.SecretsManager("padisso-poc/facebook/client-secret").UnsafeUnwrap(),
                    Scopes = new[] { "email", "public_profile" },
                    ApiVersion = "v21.0",
                    AttributeMapping = new AttributeMapping
                    {
                        Email = ProviderAttribute.FACEBOOK_EMAIL,
                        GivenName = ProviderAttribute.FACEBOOK_FIRST_NAME,
                        FamilyName = ProviderAttribute.FACEBOOK_LAST_NAME,
                    },
                }));
                clientIdps.Add(UserPoolClientIdentityProvider.FACEBOOK);
            }

            if (enabledIdps.Contains("amazon"))
            {
                idpDependencies.Add(new UserPoolIdentityProviderAmazon(this, "AmazonProvider", new UserPoolIdentityProviderAmazonProps
                {
                    UserPool = UserPool,
                    ClientId = SecretValue.SecretsManager("padisso-poc/amazon/client-id").UnsafeUnwrap(),
                    ClientSecret = SecretValue.SecretsManager("padisso-poc/amazon/client-secret").UnsafeUnwrap(),
                    Scopes = new[] { "profile" },
                    AttributeMapping = new AttributeMapping
                    {
                        Email = ProviderAttribute.AMAZON_EMAIL,
                        GivenName = ProviderAttribute.AMAZON_NAME,
                    },
                }));
                clientIdps.Add(UserPoolClientIdentityProvider.AMAZON);
            }

            if (enabledIdps.Contains("microsoft"))
            {
                var microsoftTenantId = SecretValue.SecretsManager("padisso-poc/microsoft/tenant-id").UnsafeUnwrap();
                idpDependencies.Add(new UserPoolIdentityProviderOidc(this, "MicrosoftProvider", new UserPoolIdentityProviderOidcProps
                {
                    UserPool = UserPool,
                    Name = "Microsoft",
                    ClientId = SecretValue.SecretsManager("padisso-poc/microsoft/client-id").UnsafeUnwrap(),
                    ClientSecret = SecretValue.SecretsManager("padisso-poc/microsoft/client-secret").UnsafeUnwrap(),
                    IssuerUrl = $"https://login.microsoftonline.com/{microsoftTenantId}/v2.0",
                    Scopes = new[] { "openid", "profile", "email" },
                    AttributeRequestMethod = OidcAttributeRequestMethod.GET,
                    AttributeMapping = new AttributeMapping
                    {
                        Email      = ProviderAttribute.Other("email"),
                        GivenName  = ProviderAttribute.Other("given_name"),
                        FamilyName = ProviderAttribute.Other("family_name"),
                    },
                }));
                clientIdps.Add(UserPoolClientIdentityProvider.Custom("Microsoft"));
            }

            UserPoolDomain = UserPool.AddDomain("PadissoDomain", new UserPoolDomainOptions
            {
                CustomDomain = new CustomDomainOptions
                {
                    DomainName = cognitoDomainHost,
                    Certificate = Certificate.FromCertificateArn(this, "CognitoDomainCert", cognitoDomainCertArn),
                },
            });

            UserPoolClient = UserPool.AddClient("PadissoAppClient", new UserPoolClientOptions
            {
                UserPoolClientName = "padisso-app-client",
                AuthFlows = new AuthFlow
                {
                    UserSrp = true,
                    UserPassword = false,
                    User = true,
                    Custom = true,
                },
                GenerateSecret = false,
                PreventUserExistenceErrors = true,
                AccessTokenValidity = Duration.Hours(1),
                IdTokenValidity = Duration.Hours(1),
                RefreshTokenValidity = Duration.Days(30),
                SupportedIdentityProviders = clientIdps.ToArray(),
                OAuth = new OAuthSettings
                {
                    Flows = new OAuthFlows { AuthorizationCodeGrant = true },
                    Scopes = new[] { OAuthScope.EMAIL, OAuthScope.OPENID, OAuthScope.PROFILE },
                    CallbackUrls = callbackUrls,
                    LogoutUrls = logoutUrls,
                },
            });

            // Ensure every enabled provider exists before the client references it
            foreach (var idp in idpDependencies)
            {
                UserPoolClient.Node.AddDependency(idp);
            }

            // ─── Magic-link Function URL endpoints (server-side flow) ───
            var magicLinkEnv = new Dictionary<string, string>
            {
                ["MAGIC_LINK_TABLE"]      = magicLinkTable.TableName,
                ["MAGIC_LINK_BASE_URL"]   = magicLinkBaseUrl,
                ["MAGIC_LINK_EMAIL_FROM"] = magicLinkEmailFrom,
                ["MAGIC_LINK_SMS_SENDER_ID"] = magicLinkSmsSenderId ?? "",
                ["MAGIC_LINK_TTL_MIN"]    = "15",
                ["USER_POOL_ID"]          = UserPool.UserPoolId,
                ["CLIENT_ID"]             = UserPoolClient.UserPoolClientId,
                ["ADMIN_PROOF"]           = adminProofSecret.SecretValue.UnsafeUnwrap(),
            };

            var requestMagicLinkFn = new Function(this, "RequestMagicLinkFn", new FunctionProps
            {
                FunctionName = "padi-sso-poc-request-magic-link",
                Runtime = Runtime.DOTNET_10,
                Handler = "RequestMagicLink::Padi.Services.Authentication.MagicLink.RequestMagicLink.Function::Handler",
                Code = LambdaCode("RequestMagicLink"),
                Timeout = Duration.Seconds(30),
                MemorySize = 512,
                Environment = magicLinkEnv,
            });

            var verifyMagicLinkFn = new Function(this, "VerifyMagicLinkFn", new FunctionProps
            {
                FunctionName = "padi-sso-poc-verify-magic-link",
                Runtime = Runtime.DOTNET_10,
                Handler = "VerifyMagicLink::Padi.Services.Authentication.MagicLink.VerifyMagicLink.Function::Handler",
                Code = LambdaCode("VerifyMagicLink"),
                Timeout = Duration.Seconds(30),
                MemorySize = 512,
                Environment = magicLinkEnv,
            });

            magicLinkTable.GrantReadWriteData(requestMagicLinkFn);
            magicLinkTable.GrantReadWriteData(verifyMagicLinkFn);

            requestMagicLinkFn.AddToRolePolicy(new PolicyStatement(new PolicyStatementProps
            {
                Actions   = new[] { "ses:SendEmail", "ses:SendRawEmail" },
                Resources = new[] { "*" },
            }));
            // SMS publishes target a phone number, not a topic — no ARN to scope to.
            requestMagicLinkFn.AddToRolePolicy(new PolicyStatement(new PolicyStatementProps
            {
                Actions   = new[] { "sns:Publish" },
                Resources = new[] { "*" },
            }));
            requestMagicLinkFn.AddToRolePolicy(new PolicyStatement(new PolicyStatementProps
            {
                Actions   = new[] { "cognito-idp:AdminGetUser" },
                Resources = new[] { UserPool.UserPoolArn },
            }));

            verifyMagicLinkFn.AddToRolePolicy(new PolicyStatement(new PolicyStatementProps
            {
                Actions = new[]
                {
                    "cognito-idp:AdminInitiateAuth",
                    "cognito-idp:AdminRespondToAuthChallenge",
                },
                Resources = new[] { UserPool.UserPoolArn },
            }));

            // Browsers preflight these endpoints, so they need explicit CORS. Origins are
            // configurable per environment — keep localhost out of anything non-development.
            var magicLinkCors = new FunctionUrlCorsOptions
            {
                AllowedOrigins = magicLinkAllowedOrigins,
                AllowedMethods = new[] { HttpMethod.POST },
                AllowedHeaders = new[] { "content-type" },
                MaxAge = Duration.Hours(1),
            };

            var requestUrl = requestMagicLinkFn.AddFunctionUrl(new FunctionUrlOptions
            {
                AuthType = FunctionUrlAuthType.NONE,
                Cors = magicLinkCors,
            });
            var verifyUrl = verifyMagicLinkFn.AddFunctionUrl(new FunctionUrlOptions
            {
                AuthType = FunctionUrlAuthType.NONE,
                Cors = magicLinkCors,
            });

            new CfnOutput(this, "UserPoolId", new CfnOutputProps
            {
                Value = UserPool.UserPoolId,
                Description = "Cognito User Pool ID",
                ExportName = "PadissoUserPoolId",
            });

            new CfnOutput(this, "UserPoolClientId", new CfnOutputProps
            {
                Value = UserPoolClient.UserPoolClientId,
                Description = "Cognito App Client ID",
                ExportName = "PadissoUserPoolClientId",
            });

            new CfnOutput(this, "UserPoolDomain", new CfnOutputProps
            {
                Value = UserPoolDomain.DomainName,
                Description = "Cognito Hosted UI Domain",
                ExportName = "PadissoUserPoolDomain",
            });

            new CfnOutput(this, "RequestMagicLinkUrl", new CfnOutputProps
            {
                Value = requestUrl.Url,
                Description = "POST endpoint to request a magic link",
            });

            new CfnOutput(this, "VerifyMagicLinkUrl", new CfnOutputProps
            {
                Value = verifyUrl.Url,
                Description = "POST endpoint to consume a magic link and receive Cognito tokens",
            });
        }
    }
}
