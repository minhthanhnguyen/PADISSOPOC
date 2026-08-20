# PADISSO

AWS CDK application (C# / .NET 10) provisioning an Amazon Cognito user pool for PADI single sign-on.

Supports password, passwordless (email OTP, SMS OTP, passkey), social federation, and a custom magic-link flow backed by Lambda and DynamoDB.

---

## Project layout

All projects share the base namespace **`Padi.Services.Authentication`**.

The solution follows clean architecture: dependencies point inward only.

```
src/
  Domain/                       MagicLinkToken, DeliveryChannel, CognitoTriggerSource,
                                SharedSecret                        — no dependencies
  Application/
    Abstractions/               ports: IUserDirectory, IMagicLinkTokenStore, IAuthenticator,
                                IEmailSender, ICodeDecryptor, ITemplateCatalog,
                                IClock, IAuditLog
    Cognito/                    CustomAuthChallenge, SendCognitoMessage, RecordSignIn
    MagicLink/                  RequestMagicLink, RedeemMagicLink
  Infrastructure/
    Core/                       SystemClock, ConsoleAuditLog, LambdaConfiguration  (no AWS SDK)
    Configuration/              AddParameterStore()                    (Systems Manager SDK)
    Cognito/                    CognitoUserDirectory, CognitoCustomAuthenticator
    DynamoDb/                   DynamoMagicLinkTokenStore
    Notifications/              SES and SNS magic-link delivery
    Messaging/                  PADI messaging client, OAuth2 token provider
    Kms/                        EncryptionSdkCodeDecryptor
  Lambdas/                      thin adapters + per-function composition roots
    DefineAuthChallenge/  CreateAuthChallenge/  VerifyAuthChallenge/
    PostAuthentication/   CustomEmailSender/
    RequestMagicLink/     VerifyMagicLink/
  Padisso/                      CDK app — PadiSsoPocStack
web/                            React reference client (Vite + TypeScript)
publish-lambdas.ps1             Publishes all Lambda projects
cdk.json                        Environment configuration (context block)
```

`Domain` has no dependencies. `Application` knows only `Domain` and declares ports as interfaces. `Infrastructure` implements those ports. Each Lambda is an adapter that maps its event onto a use case, plus a `Composition` class that wires the container once per execution environment.

Namespaces follow the directory structure — `Padi.Services.Authentication.Application.MagicLink`, `….Infrastructure.Cognito`. Lambda assembly names stay short (`CustomEmailSender`, `RequestMagicLink`) because they form the first segment of each handler string.

### Bundle sizes

Infrastructure is split per concern rather than into one project, so each Lambda carries only the SDKs it uses. A single `Infrastructure` assembly would push every function past 30 MB.

| Function | References | Bundle |
|---|---|---|
| DefineAuthChallenge / CreateAuthChallenge | Application | 237–241 KB |
| VerifyAuthChallenge | Application | 237 KB |
| PostAuthentication | + Core, Cognito | 5.0 MB |
| VerifyMagicLink | + Core, Cognito, DynamoDb | 7.5 MB |
| RequestMagicLink | + Core, Cognito, DynamoDb, Notifications | 9.4 MB |
| CustomEmailSender | + Core, Configuration, Messaging, Kms | 30 MB |

The three custom-auth triggers reference **Application only** — no AWS SDKs — so they stay small by construction rather than by discipline. Two boundaries exist specifically to protect this:

- **`Core` versus `Configuration`.** `Core` holds the clock, audit log and environment-variable configuration with no AWS packages; `Configuration` adds SSM Parameter Store. Only `CustomEmailSender` reads parameters, so only it ships `AWSSDK.SimpleSystemsManagement` — worth roughly 4 MB to the others.
- **`PostAuthentication` references `Infrastructure.Cognito` alone**, never a broader bundle, keeping DynamoDB, SES and SNS out of a function that only writes a user attribute.

`CustomEmailSender` is well inside Lambda's 250 MB unzipped limit but is the largest cold start, and sits in the critical path of every sign-up and OTP. The bulk is the AWS Encryption SDK's native crypto binaries.

### Testability

Use cases take their ports through the constructor, so they can be exercised with fakes — no AWS, no Lambda runtime. `CustomAuthChallenge` is pure static logic and needs no fakes at all. There are currently **no tests**; the structure makes them possible, which was the main motivation for the layering.

---

## User pool

| Setting | Value |
|---|---|
| Name | `padi-sso-poc-user-pool` |
| Feature plan | `essentials` |
| Sign-in alias | Username only, **case-insensitive** |
| Optional attributes | email, phone_number, given_name, family_name, birthdate |
| Custom attributes | `custom:padi_id`, `custom:affiliate_id`, `custom:last_login` |
| Password policy | 6+ chars, upper + lower required; digits and symbols not required |
| Account recovery | Email and phone, no MFA |
| Passkey relying party | `padi.com` |

### Authentication methods

| Method | Mechanism |
|---|---|
| Username + password | SRP (`USER_SRP_AUTH`) |
| Email OTP | Cognito native |
| SMS OTP | Cognito native |
| Passkey / WebAuthn | Cognito native |
| Magic link | Custom — Lambda + DynamoDB (see below) |
| Social | Google, Apple, Facebook, Amazon, Microsoft — all gated behind `enabledIdps` |

---

## Magic-link flow

The Cognito session never reaches the client, so its ~3-minute lifetime does not constrain the link. The 15-minute DynamoDB TTL governs instead, and clicking the link on a different device works.

```
POST /request-link   { "username": "alice", "channel": "email" | "sms" }
  ├─ AdminGetUser → resolve email or phone_number for the chosen channel
  ├─ DynamoDB put { tokenHash: sha256(token), username, channel, expiresAt }
  ├─ channel.SendAsync()  →  SES email  |  SNS SMS
  └─ always 200  (no user enumeration)

        user clicks link → /verify?token=…

POST /verify-link    { "token": "…" }
  ├─ DynamoDB conditional delete by tokenHash   ← atomic single-use
  ├─ TTL check
  ├─ AdminInitiateAuth (CUSTOM_AUTH) + AdminRespondToAuthChallenge
  │     └─ Define → Create (no-op) → Verify (constant-time ADMIN_PROOF check)
  └─ 200 { idToken, accessToken, refreshToken, expiresIn, tokenType }
```

`ADMIN_PROOF` is a 64-character secret generated at deploy time and shared only between `VerifyMagicLink` and the `VerifyAuthChallenge` trigger. It proves the challenge originated from the one Lambda holding `AdminInitiateAuth` permission — the actual authentication decision already happened against DynamoDB before the Cognito challenge begins.

**Security properties:** 256-bit tokens, only SHA-256 hashes persisted, constant-time comparison, single-use enforced by conditional delete, 15-minute TTL.

Both endpoints are Lambda Function URLs with `AuthType.NONE`. They declare CORS explicitly — allowed origins come from `magicLinkAllowedOrigins`, methods are limited to `POST`, and headers to `content-type`. Origins are enumerated rather than wildcarded because the endpoints are unauthenticated. A browser calling them from an origin outside that list fails at preflight, before the request reaches Lambda.

### Delivery channels

`IMagicLinkDelivery` abstracts transport *and* presentation, since a URL that reads well in email is hostile inside a 160-character SMS segment. `SesMagicLinkDelivery` and `SnsMagicLinkDelivery` implement it; the use case selects one by channel. Channel is explicit in the request and defaults to email — inferring it would be ambiguous for a user with both an email address and a phone number.

---

## Post-authentication trigger

Fires on every successful sign-in, before tokens are issued. Two responsibilities:

**Audit logging** — one JSON object per sign-in, single-line so CloudWatch Logs Insights can query the fields directly:

| Field | |
|---|---|
| `eventType` | Always `SignIn` |
| `timestamp` | ISO 8601, UTC |
| `userPoolId`, `userName`, `sub`, `email` | Identity |
| `triggerSource`, `clientId` | Origin of the sign-in |
| `identities` | Populated for federated sign-ins — distinguishes Google from native |
| `padiId` | `custom:padi_id`, if set |
| `newDeviceUsed` | Cognito device tracking |
| `requestId` | Lambda request ID, for correlation |

**Last-login tracking** — writes an ISO 8601 timestamp to `custom:last_login` via `AdminUpdateUserAttributes`. IAM is scoped to the pool ARN.

### Failure behaviour

A PostAuthentication trigger that throws **fails the user's sign-in**. Both operations are therefore independently wrapped and the handler always returns the event — a Cognito API blip yields a stale `custom:last_login`, never a failed login. Audit logging runs before the attribute write so a write failure cannot cost the audit record.

### Caveats

- **Adds an extra Cognito API call to every sign-in** (~50–100 ms). This lands inside `/verify-link` too, since `VerifyMagicLink` calls `AdminRespondToAuthChallenge` synchronously.
- **Federated coverage is unverified.** PostAuthentication is not reliably invoked for hosted-UI / third-party IdP sign-ins. Not yet relevant with `enabledIdps: []`, but verify against a real Google sign-in before relying on this for audit completeness.
- **The trigger cannot deny a sign-in.** Authentication has already succeeded and the response is ignored. Use `PreAuthentication` to block.

---

## Outbound email

There are **two delivery paths**, and they do not share a provider.

**Cognito-originated email** goes through the `CustomEmailSender` trigger to the PADI messaging service. Once that trigger is attached, Cognito sends nothing itself — every message below depends on the Lambda succeeding, and there is **no fallback**. Cognito's 50-message/day default sender is out of the picture entirely.

| Trigger source | Message |
|---|---|
| `CustomEmailSender_SignUp` | Sign-up verification code |
| `CustomEmailSender_Authentication` | **Passwordless email OTP and MFA codes** |
| `CustomEmailSender_ForgotPassword` | Password reset code |
| `CustomEmailSender_ResendCode` | Replacement confirmation code |
| `CustomEmailSender_UpdateUserAttribute` | Attribute change verification |
| `CustomEmailSender_VerifyUserAttribute` | New attribute verification |
| `CustomEmailSender_AdminCreateUser` | Temporary password |
| `CustomEmailSender_AccountTakeOverNotification` | Threat-protection alert |

Cognito encrypts the one-time code with a customer-managed KMS key using the **AWS Encryption SDK envelope format** — `kms:Decrypt` alone will not open it, which is why `CustomEmailSender` depends on `AWS.Cryptography.EncryptionSDK`. Codes are never logged; only trigger source, definition key and request ID are.

The decryptor sets `CommitmentPolicy = REQUIRE_ENCRYPT_ALLOW_DECRYPT`. Cognito encrypts with a **non-committing** algorithm suite, and the SDK default (`REQUIRE_ENCRYPT_REQUIRE_DECRYPT`) rejects those with `InvalidAlgorithmSuiteInfoOnDecrypt` before reaching KMS. The relaxed policy applies to decryption only; anything this code encrypts still requires commitment. Note the .NET API differs from the JavaScript one here — `ESDKCommitmentPolicy` is a smithy-generated union of static fields, not an enum, and lives in `AWS.Cryptography.MaterialProviders`.

### Authenticating to the messaging service

OAuth2 client credentials. The token request posts a **JSON** body — not the more usual `application/x-www-form-urlencoded` — with credentials in an HTTP Basic header:

```
POST <messagingTokenUrl>
Authorization: Basic base64(clientId:clientSecret)
Content-Type: application/json

{ "grant_type": "client_credentials" }
```

`scope` is added to the body when `Messaging:Scope` is configured; it currently is not. The access token is cached in `BearerTokenProvider` for the life of the execution environment and refreshed 60 seconds before expiry, so a token call happens roughly once per cold start rather than per message.

**Magic-link email** still goes directly to SES via `SesMagicLinkDelivery`, not through the messaging service. Both now implement Application ports, so consolidating means registering `MessagingEmailSender` in place of the SES delivery — a composition-root change rather than a rewrite.

### Request contract

The messaging service owns the templates, so this sends a definition key and substitution values rather than rendered content. No subjects or bodies live in this repository.

```csharp
public sealed record EmailProxyRequest
{
    public required string ContactKey { get; init; }
    public required string DefinitionKey { get; init; }
    public required string RecipientEmail { get; init; }
    public IReadOnlyDictionary<string, object?> Attributes { get; init; }
}
```

Serialised **PascalCase** — `System.Text.Json` would otherwise camelCase the property names, which the service does not expect. `Attributes` is a dictionary rather than `dynamic`: identical on the wire, but compile-time checkable and free of the runtime binder.

Attributes sent on every message:

| Attribute | Source |
|---|---|
| `SubscriberKey` | Email address |
| `EmailAddress` | Email address |
| `VerificationCode` | Decrypted Cognito code |
| `LanguageCode` | `custom:language`, defaulting to `en-US` |
| `FirstName` | `given_name` |
| `META_COUNTRY_CODE` | Currently hardcoded `US` |

Anything in `ClientMetadata` is merged in afterwards and **overwrites** a colliding key, so a client can vary template behaviour — locale, brand, campaign — without a code change. Cognito forwards `ClientMetadata` for the `SignUp`, `ForgotPassword` and `Authentication` trigger sources only.

`ContactKey` is the email address. Note that this makes the contact identity change if a user updates their email; Cognito's `sub` would be stable across that, if the messaging service can key on it.

### Template definitions

Definition ids are **not** in `cdk.json` or environment variables. They live in SSM under `/padi/services/authentication/Messaging/Definitions/<TriggerSource>`, named for the trigger source with the `CustomEmailSender_` prefix removed:

```bash
aws ssm put-parameter --name /padi/services/authentication/Messaging/Definitions/SignUp --type String --value "<definition-key>" --region us-west-2
```

Valid names: `SignUp`, `Authentication`, `ForgotPassword`, `ResendCode`, `UpdateUserAttribute`, `VerifyUserAttribute`, `AdminCreateUser`, `AccountTakeOverNotification`.

A trigger source with no matching parameter logs a warning and sends nothing, rather than failing the underlying Cognito operation. `SignUp` and `Authentication` are the two the current sign-up and OTP flows depend on.

> **Do not also set these as environment variables.** Configuration applies environment variables *after* SSM, so an env var of the same key silently shadows the parameter — the symptom is a warning about an unconfigured definition while the parameter looks correct in the console.

### Configuration and dependency injection

Each Lambda has a `Composition` class that builds an `IConfiguration` and a service provider once per execution environment, behind a `Lazy`. Configuration sources are merged so callers cannot tell which supplied a given value:

| Source | Produces key |
|---|---|
| Env var `Messaging__EmailUrl` | `Messaging:EmailUrl` |
| SSM `/padi/services/authentication/Messaging/ClientId` | `Messaging:ClientId` |
| SSM `/padi/services/authentication/Messaging/Definitions/SignUp` | `Messaging:Definitions:SignUp` |

The SSM path prefix is stripped by the provider, so parameter paths and environment-variable names converge on the same configuration keys. **Environment variables are applied last and therefore win on a key collision** — intentional, so a value can be pinned per function, but it means anything sourced from Parameter Store must not also be set as an environment variable.

Which sources a function reads depends on what it needs:

```csharp
// CustomEmailSender — reads SSM parameters
LambdaConfiguration.Create().AddParameterStore().AddEnvironment().Build();

// RequestMagicLink, VerifyMagicLink — environment only, no Systems Manager SDK
LambdaConfiguration.FromEnvironment();
```

Values are read through `IConfiguration` or bound onto an options class:

```csharp
var url = configuration["Messaging:EmailUrl"];
var sender = Composition.Resolve<SendCognitoMessage>();
```

Credentials therefore **never appear in Lambda environment variables**, where `lambda:GetFunctionConfiguration` would expose them.

Rotating a parameter takes effect **without a redeploy**, but the timing is best-effort rather than guaranteed. `ReloadAfter` schedules a background refresh every 15 minutes; Lambda freezes the execution environment between invocations, so that timer fires only while the sandbox happens to be thawed. In practice a rotated value is reliably picked up on the **next cold start**, and opportunistically before then. `IOptionsMonitor` ensures the new value reaches `BearerTokenProvider` on its next token refresh.

`MessagingOptions` validates with `[Required]` data annotations on first resolve. There is no `IHost`, so validation is lazy rather than at startup, which surfaces a missing value as a clear error in the invocation log.

---

## Configuration

All environment-specific values live in the `context` block of `cdk.json`.

| Key | Purpose |
|---|---|
| `userPoolName` | Cognito user pool name |
| `featurePlan` | `lite` \| `essentials` \| `plus` |
| `passkeyRelyingPartyId` | WebAuthn RP ID — **bare domain**, no scheme |
| `enabledIdps` | Any of `google`, `apple`, `facebook`, `amazon`, `microsoft` |
| `cognitoDomain` | Hosted UI custom domain |
| `cognitoDomainCertArn` | ACM certificate ARN — must be in **us-east-1** |
| `callbackUrls` / `logoutUrls` | OAuth redirect targets |
| `magicLinkBaseUrl` | Landing page that receives `?token=` |
| `magicLinkEmailFrom` | Sender address — verified SES identity, also used as `Messaging:FromAddress` |
| `magicLinkSmsSenderId` | Optional SMS sender ID (unsupported in the US) |
| `magicLinkAllowedOrigins` | CORS origins permitted to call the Function URLs |
| `messagingEmailUrl` | PADI messaging service transactional email endpoint |
| `messagingTokenUrl` | OAuth2 token endpoint for the messaging service |

### SSM Parameter Store

Messaging credentials are read at runtime, not baked into the template. Create them once — CloudFormation cannot create `SecureString` parameters:

```bash
aws ssm put-parameter --name /padi/services/authentication/Messaging/ClientId --type SecureString --value "<client-id>" --region us-west-2
```

```bash
aws ssm put-parameter --name /padi/services/authentication/Messaging/ClientSecret --type SecureString --value "<client-secret>" --region us-west-2
```

Template definition ids live under the same path — see [Template definitions](#template-definitions).

Add `--overwrite` to rotate. No redeploy is needed; the change is picked up within 15 minutes.

IAM grants `ssm:GetParameter*` across `/padi/services/authentication/*`, so the path is a shared namespace — any parameter added under it becomes readable by these functions and appears in their configuration.

The policy lists **two** ARNs, and both are required:

```
arn:aws:ssm:<region>:<account>:parameter/padi/services/authentication
arn:aws:ssm:<region>:<account>:parameter/padi/services/authentication/*
```

`GetParametersByPath` authorizes against the path *node* — no trailing wildcard — while `GetParameter` authorizes against the parameters beneath it. Granting only `.../*` fails the enumeration the configuration provider performs at cold start, and because that happens while building configuration it fails every invocation of the function, not just the one that needed a parameter.

### Secrets Manager

Social provider credentials live in AWS Secrets Manager under `padisso-poc/<provider>/<field>` and are resolved at deploy time — nothing sensitive is committed.

| Provider | Secret paths |
|---|---|
| Google | `client-id`, `client-secret` |
| Apple | `client-id`, `team-id`, `key-id`, `private-key` |
| Facebook | `client-id`, `client-secret` |
| Amazon | `client-id`, `client-secret` |
| Microsoft | `client-id`, `client-secret`, `tenant-id` |

A provider's secrets are only referenced when it appears in `enabledIdps`. An unreferenced secret never becomes a CloudFormation dynamic reference, so the stack deploys without credentials for providers that are not yet set up.

---

## Prerequisites

- .NET 10 SDK
- AWS CDK CLI **2.1131.0 or later** — older versions cannot read the cloud assembly schema emitted by `Amazon.CDK.Lib` 2.264.0
- AWS credentials with permission to deploy Cognito, Lambda, DynamoDB, IAM, and Secrets Manager

```bash
npm install -g aws-cdk@latest
```

---

## Build and deploy

Publish the Lambdas first — CDK packages their build output as assets, so this must run before every `synth` or `deploy`:

```bash
pwsh -File ./publish-lambdas.ps1
```

Then:

```bash
npx cdk synth
```

```bash
npx cdk deploy
```

Inspect pending changes before deploying against an existing pool:

```bash
npx cdk diff
```

### Stack outputs

`PadissoUserPoolId`, `PadissoUserPoolClientId`, `PadissoUserPoolDomain`, `RequestMagicLinkUrl`, `VerifyMagicLinkUrl`

---

## Web client

A minimal React reference client lives in `web/` — Vite, TypeScript, and AWS Amplify v6.

| Route | Purpose |
|---|---|
| `/signup` | Username, password, email, first name, last name |
| `/confirm` | 6-digit email verification code; account is unconfirmed until entered |
| `/login` | Username + password over SRP |
| `/passwordless` | Choice-based `USER_AUTH` — email OTP, SMS OTP, or passkey |
| `/magic-link` | Requests a link; manual token redemption as a fallback |
| `/verify` | Where the emailed link lands — redeems the token automatically and shows a placeholder signed-in page |
| `/` | ID and access tokens, decoded claims, passkey management; redirects to `/login` when signed out |

### Running it

Fill in the pool details:

```bash
cp web/.env.example web/.env.local
```

Read the values from the deployed stack:

```bash
aws cloudformation describe-stacks --stack-name PadiSsoPocStack --query "Stacks[0].Outputs" --output table
```

Then:

```bash
npm install --prefix web
```

```bash
npm run dev --prefix web
```

### Notes

- **Sign-in uses `USER_SRP_AUTH` explicitly.** The app client has `USER_PASSWORD_AUTH` disabled, so a client defaulting to plaintext password auth will fail. The password is never sent to Cognito directly.
- **Email verification is enforced by the pool.** `AutoVerify` is on for email, so `signUp` returns a `CONFIRM_SIGN_UP` next step and Cognito emails a code. Sign-in fails until `confirmSignUp` succeeds. The login page detects an unconfirmed account and routes back to `/confirm`.
- **Cognito's default email sender caps at 50 messages/day**, which covers these verification codes — the first thing to hit if you test signup repeatedly.
- **No hosted UI involvement.** The client calls the Cognito API directly, so `callbackUrls` is not used. Add `http://localhost:5173` to `callbackUrls` in `cdk.json` before wiring up social sign-in through the hosted UI.

### Passwordless testability

Each factor has its own prerequisites, and only email OTP works against a local dev server as configured:

| Factor | Status locally | Blocker |
|---|---|---|
| Email OTP | Works | None — subject to the 50/day default-sender cap |
| SMS OTP | Blocked | Signup collects no `phone_number`, and SNS is in the SMS sandbox |
| Passkey | Blocked | `passkeyRelyingPartyId` is `padi.com`; WebAuthn requires the RP ID to be a registrable suffix of the page origin, which `localhost` is not |
| Magic link | Partial | Needs `RequestMagicLinkUrl` in `.env.local` and a verified SES sender |

To exercise passkeys locally, either set `passkeyRelyingPartyId` to `localhost` in `cdk.json` and redeploy, or serve the app from a `*.padi.com` host. Changing the RP ID invalidates any passkeys already registered under the previous value.

### Magic-link round trip

`magicLinkBaseUrl` is currently set to `http://localhost:5173/verify` so emailed links open the dev app directly. **Point it back at a real URL before any non-local deployment** — the value is per-stack, so while it reads localhost *every* link the pool sends goes there.

Clicking a link lands on `/verify`, which redeems the token on mount and renders a placeholder signed-in page. The `/magic-link` page keeps a manual paste field for when the base URL points elsewhere.

Two details worth knowing if this code is modified:

- **The redemption is guarded against double invocation.** React StrictMode runs effects twice in development, and the token is single-use — without the guard the second call would consume nothing and report 401 on every valid link.
- **The tokens do not come from Amplify.** The verify endpoint returns them directly, so the app is not signed in from Amplify's perspective and `/` still redirects to `/login`. A real client would persist them and hydrate its own session.

---

## Operational notes

**Schema changes are dangerous on a live pool.** Custom attributes cannot be deleted, renamed, or retyped once created, and `Schema` changes have historically triggered CloudFormation *replacement*. Always run `cdk diff` before deploying a schema change and stop if it reports the pool will be replaced.

**Never rename a CDK construct ID.** IDs such as `"PadissoUserPool"`, `"PadissoAppClient"` and `"PadissoDomain"` determine CloudFormation logical IDs. Renaming one makes CloudFormation treat it as a new resource and destroy the original — so they deliberately still read `Padisso` even though the namespaces are now `Padi.Services.Authentication`. The same applies to the three `ExportName` values, which other stacks may reference.

**Lambda timeouts are 30 seconds, but Cognito triggers are bounded by Cognito, not Lambda.** `DefineAuthChallenge`, `CreateAuthChallenge`, `VerifyAuthChallenge`, `PostAuthentication` and `CustomEmailSender` all run synchronously inside a Cognito request, and Cognito abandons a trigger after roughly 5 seconds regardless of the configured Lambda timeout. The higher ceiling helps with cold starts and produces a real stack trace instead of a bare `Task timed out`, but a trigger that genuinely needs longer must be made faster or asynchronous. The two Function URLs are not triggers, so 30 seconds applies to them directly.

**A Lambda that is both a Cognito trigger and needs the pool ARN creates a dependency cycle.** CDK makes a function `DependsOn` its role's default policy, so `AddToRolePolicy` with a `UserPool.UserPoolArn` reference closes the loop: `UserPool → Function → DefaultPolicy → UserPool`. Attach a standalone `Policy` resource to the function's role instead — see `PostAuthCognitoPolicy`. `cdk synth` does not catch this; only the deploy fails.

**The pool is `RemovalPolicy.RETAIN`.** Both `DeletionPolicy` and `UpdateReplacePolicy` are `Retain`, so a replacement orphans the original pool instead of deleting its users. Two consequences:

- `cdk destroy` leaves the pool behind. Remove it deliberately with `aws cognito-idp delete-user-pool`.
- A replacement leaves *two* pools in the account — the stack points at the new one while the old keeps the users. Recoverable, but messy, so `cdk diff` remains the first line of defence rather than this.

`DeletionProtection` is **not** enabled. It is the stronger guard — Cognito itself refuses to delete the pool regardless of what CloudFormation asks — and is worth turning on before this holds real users.

**Prefer DynamoDB over custom attributes for evolving data.** Custom attributes are permanent, capped at 50, and fixed in type. Keep a profile table keyed by `sub` and promote to a Cognito attribute only what must travel inside the token for authorization decisions. Pre-allocating spare attributes as a hedge is a poor trade: it locks in names and types you cannot change and does nothing to prevent replacement.

**Several settings are fixed at pool creation** and cannot be changed later: username case sensitivity, sign-in aliases, and whether an attribute is required. The password policy is *not* among them — it can be tightened on a live pool at any time, and existing passwords are unaffected until their next change.

**Rotating provider secrets does not propagate automatically.** The template embeds `{{resolve:secretsmanager:…}}`, which resolves at deploy time. Changing a secret's value leaves the template byte-identical, so CloudFormation performs no update and the old credential stays live. Rotate via `aws cognito-idp update-identity-provider` out-of-band, then reconcile Secrets Manager.

**Passkeys are bound to the relying party ID.** Changing `passkeyRelyingPartyId` invalidates every passkey registered under the previous value.

---

## Known gaps

This is a proof of concept. Before production:

- **Password policy is below current guidance** — 6 characters is Cognito's floor and short of the 8-character minimum in NIST SP 800-63B. The composition rules are also an unusual pairing: uppercase and lowercase are mandatory while digits are not, which pushes users toward predictable shapes like `Passwd` without adding real entropy. Prefer a longer minimum over composition requirements, and enable threat protection (requires the `plus` feature plan) so credentials are checked against known-breached passwords.
- **The messaging integration has not been exercised end to end.** The `EmailProxyRequest` shape matches the service contract, but the attribute names, the PascalCase serialisation, and HTTP Basic client authentication on the token request are all unconfirmed against a live call — if the endpoint expects `client_id` and `client_secret` inside the JSON body instead of the header, that is a small change in `BearerTokenProvider`. Because `CustomEmailSender` has no fallback, a mismatch breaks sign-up, password reset, and email OTP simultaneously — **test a sign-up immediately after the first deploy**, and roll back by removing `CustomEmailSender` from `LambdaTriggers`.
- **`META_COUNTRY_CODE` is hardcoded to `US`.** It should derive from a user attribute or `ClientMetadata` once the requirement is clear.
- **`CustomEmailSender` is a hard dependency of authentication.** Cognito sends no email itself once the trigger is attached. There is no retry or SES failover; if the messaging service is unavailable, nobody can register or recover an account.
- **Magic-link email bypasses the messaging service**, still going directly to SES via `SesMagicLinkDelivery`. Both sides now implement Application ports, so consolidating is a composition-root change.
- **SES sender identity** — `magicLinkEmailFrom` (`no-reply@padi.com`) must be a verified identity in SES in the sending region for the magic-link path, and the account must be out of the SES sandbox to reach unverified recipients
- **`magicLinkBaseUrl` and `magicLinkAllowedOrigins` both reference `localhost:5173`** for local testing. Both must be changed before any shared or production deployment.
- **There are no automated tests.** The clean-architecture split makes the use cases testable with fakes; nothing has been written yet.
- **`CustomSMSSender` is not wired.** SMS OTP still uses Cognito's own delivery. `MessagingEmailSender` already implements `ISmsSender`; attaching the trigger later is a `LambdaConfig` update-in-place, no pool replacement.
- **Function URLs use `AuthType.NONE`** — publicly reachable with no rate limiting on `/request-link`; put them behind API Gateway with WAF
- **`ADMIN_PROOF` is stored in plain Lambda environment variables**, readable via `GetFunctionConfiguration`. The messaging credentials already avoid this by loading from Parameter Store at runtime — `ADMIN_PROOF` should move to the same mechanism.
- **`ses:SendEmail` and `sns:Publish` are granted on `*`** and should be scoped
- **No account linking** — a user who registers with a password and later signs in with the same email via a social provider receives a second, separate account. Consider `AdminLinkProviderForUser` from a PreSignUp trigger.
- **SMS is untested** — requires exiting the SNS SMS sandbox and, for US traffic, 10DLC or toll-free registration
- **Threat protection is dormant** — available on the `plus` feature plan but not enabled
- **`DeletionProtection` is not enabled** on the user pool — `RemovalPolicy.RETAIN` guards against CloudFormation deleting it, but not against a direct API or console deletion
- **Sign-in audit records live only in CloudWatch Logs** and inherit the log group's retention. For durable audit history, fan the PostAuthentication event out to EventBridge or a data store rather than relying on log retention.
