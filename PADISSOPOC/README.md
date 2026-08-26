# PADISSO

AWS CDK application (C# / .NET 10) provisioning an Amazon Cognito user pool for PADI single sign-on.

Supports password, passwordless (email OTP, SMS OTP, passkey), social federation, and a custom magic-link flow backed by Lambda and DynamoDB. Usernames are mutable — see [Mutable usernames](#mutable-usernames).

**[docs/architecture.md](docs/architecture.md)** has the diagrams: deployed topology, identity model, code layering, and the magic-link and email-delivery sequences.

---

## Project layout

All projects share the base namespace **`Padi.Services.Authentication`**.

The solution follows clean architecture: dependencies point inward only.

```
src/
  Domain/                       MagicLinkToken, DeliveryChannel, CognitoTriggerSource,
                                SharedSecret, UsernameRules         — no dependencies
  Application/
    Abstractions/               ports: IUserDirectory, IMagicLinkTokenStore, IAuthenticator,
                                IEmailSender, ICodeDecryptor, ITemplateCatalog,
                                IClock, IAuditLog
    Cognito/                    CustomAuthChallenge, SendCognitoMessage, RecordSignIn,
                                AssignPreferredUsername
    MagicLink/                  RequestMagicLink, RedeemMagicLink
    Users/                      RegisterUser, ChangeUsername, SetUserUsername
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
    PostAuthentication/   PostConfirmation/     CustomEmailSender/
    RequestMagicLink/     VerifyMagicLink/
  Api/                          ASP.NET Core management API, hosted in Lambda
  Padisso/                      CDK app — PadiSsoPocStack, PadiSsoApiStack
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
| DefineAuthChallenge | Application | 249 KB |
| CreateAuthChallenge | Application | 245 KB |
| VerifyAuthChallenge | Application | 245 KB |
| PostAuthentication | + Core, Cognito | 5.0 MB |
| PostConfirmation | + Core, Cognito | 5.0 MB |
| VerifyMagicLink | + Core, Cognito, DynamoDb | 7.5 MB |
| RequestMagicLink | + Core, Cognito, DynamoDb, Notifications | 9.4 MB |
| CustomEmailSender | + Core, Configuration, Messaging, Kms | 30 MB |

The three custom-auth triggers reference **Application only** — no AWS SDKs — so they stay small by construction rather than by discipline. Two boundaries exist specifically to protect this:

- **`Core` versus `Configuration`.** `Core` holds the clock, audit log and environment-variable configuration with no AWS packages; `Configuration` adds SSM Parameter Store. Only `CustomEmailSender` reads parameters, so only it ships `AWSSDK.SimpleSystemsManagement` — one bundle out of eight, worth roughly 4 MB to each of the others.
- **`PostAuthentication` and `PostConfirmation` reference `Infrastructure.Cognito` alone**, never a broader bundle, keeping DynamoDB, SES and SNS out of two functions that only write a user attribute.

`CustomEmailSender` is well inside Lambda's 250 MB unzipped limit but is the largest cold start, and sits in the critical path of every sign-up and OTP. The bulk is the AWS Encryption SDK's native crypto binaries.

### Testability

Use cases take their ports through the constructor, so they can be exercised with fakes — no AWS, no Lambda runtime. `CustomAuthChallenge` is pure static logic and needs no fakes at all. There are currently **no tests**; the structure makes them possible, which was the main motivation for the layering.

---

## User pool

| Setting | Value |
|---|---|
| Name | `padi-sso-poc-user-pool` |
| Feature plan | `essentials` |
| Sign-in alias | Username + **`preferred_username`**, case-insensitive |
| Optional attributes | email, phone_number, given_name, family_name, birthdate |
| Custom attributes | `custom:padi_id`, `custom:affiliate_id`, `custom:last_login`, `custom:signup_username` |
| Password policy | 6+ chars, upper + lower required; digits and symbols not required |
| Account recovery | Email and phone, no MFA |
| Passkey relying party | `padi.com` |

### Mutable usernames

Cognito's `username` can never change: *"After you create a user, you can't change the value of the `username` attribute."* No pool setting alters that. The mechanism AWS documents is `preferred_username` configured as an **alias attribute** — a secondary sign-in identifier the user can update.

So the account's real username is an **opaque UUID the user never sees**, and `preferred_username` is the name they type. The sequence:

```
signUp(username: "a7f3e2c1-…", custom:signup_username: "minh9")
  → confirmSignUp
  → PostConfirmation promotes custom:signup_username into preferred_username
  → signIn("minh9")

updateUserAttributes({ preferred_username: "minh-new" })
  → signIn("minh-new");  "minh9" is released for anyone to claim
```

The staging attribute exists because **Cognito rejects `preferred_username` in a SignUp request while it is an alias** — the value can only be assigned after confirmation, which is what the `PostConfirmation` trigger is for.

#### Username characters

Cognito constrains the `Username` request parameter of `SignUp`, `ForgotPassword`, `ConfirmSignUp` and the admin operations to **1–128 characters** matching `[\p{L}\p{M}\p{S}\p{N}\p{P}]+` — letters, marks, symbols, numbers and punctuation in any script. `\p{Z}` is absent, so **whitespace is rejected anywhere**: leading, trailing or internal. That omission is deliberate — the `AttributeType.Name` pattern is the same set *plus* `\t\n\r` and a space.

The trap is that Cognito does not apply this where `preferred_username` is actually written. An attribute value is capped at 2048 characters with **no pattern at all**, so `updateUserAttributes({ preferred_username: "john smith" })` succeeds and produces an alias the user cannot sign in with or reset a password against. Nothing in the pool prevents it either: `StringAttributeConstraints` supports only min and max length, not a regex.

Validation is therefore ours to enforce, in two places that must agree:

| | |
|---|---|
| `src/Domain/Identity/UsernameRules.cs` | Enforced by the `PostConfirmation` trigger, which throws rather than write an unusable alias |
| `web/src/username-rules.ts` | Enforced by `/signup` and `/change-username` before any Cognito call |

Sign-up cannot rely on Cognito to catch a bad name: the account's username is a UUID, so `signUp` succeeds regardless and the problem only appears once `PostConfirmation` promotes the staged value.

One divergence is handled explicitly. **.NET applies these Unicode categories per UTF-16 code unit**, so an emoji is seen as a surrogate pair and rejected, while JavaScript's `/u` flag matches by code point and would accept it. The browser rule rejects astral-plane characters outright so both sides agree — erring strict, because the cost is choosing another name rather than a confirmation that throws after the account exists.

Three further consequences worth knowing:

- **Uniqueness is enforced by Cognito.** Alias values must be unique pool-wide, so a taken name is rejected on update. No application-level check needed — unlike `email`, which is a plain attribute and *is* duplicable.
- **An unconfirmed account has no alias yet.** Between sign-up and confirmation the UUID is the only identifier `confirmSignUp` and `resendSignUpCode` accept, and the user has never seen it. The client keeps it in `localStorage` (`web/src/pending-signup.ts`) so a reload or a login-page redirect can recover. Abandoning confirmation and returning on another device means signing up again — the chosen name is still free, because it never became an alias.
- **Magic links are issued against the immutable username**, not the alias the caller supplied, so a username change between requesting a link and following it does not break redemption.

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

## Management API

An ASP.NET Core app in `src/Api`, hosted in Lambda and fronted by API Gateway. It runs unchanged under Kestrel locally — `AddAWSLambdaHosting` is a no-op outside Lambda — so the whole surface is testable without deploying.

Conventional MVC controllers, not minimal APIs:

```
src/Api/
  Program.cs                  auth, DI, JSON options
  Authorization.cs            policies + the client-id requirement
  HttpContextExtensions.cs    access-token extraction
  DirectoryExceptionHandler.cs
  Contracts/                  Requests.cs, Responses.cs
  Controllers/                HealthController, RegistrationController,
                              MeController, AdminUsersController
```

Request models carry data annotations, so `[ApiController]` returns a 400 with `ValidationProblemDetails` before an action runs — a controller only ever sees a structurally valid body. Rules needing domain knowledge, such as the Cognito username pattern, still live in the Application layer. Responses are declared types rather than anonymous objects, and `[ProducesResponseType]` records the status codes each action can return.

The gateway is **regional**, matching the endpoint type of the custom domain it maps under — the two have to agree. Clients resolve straight to the endpoint in `us-west-2` rather than through a CloudFront point of presence, and header names are passed through as-is.

WAF attaches to the API *stage* with a **REGIONAL**-scoped WAFv2 ACL in the API's region. That is true of either endpoint type, so the reason REST was chosen over HTTP API does not depend on this setting.

Two route groups, separated by **authority rather than by feature**:

| Route | Policy | |
|---|---|---|
| `GET /health` | anonymous | Liveness. Reveals nothing |
| `POST /public/signup` | anonymous | Creates an unconfirmed account; returns `accountId` |
| `POST /public/signup/confirm` | anonymous | Confirms with the emailed code |
| `POST /public/signup/resend` | anonymous | Sends a replacement code |
| `GET /me` | `caller` | Profile from the caller's own token |
| `PATCH /me` | `caller` | `given_name`, `family_name` |
| `PUT /me/username` | `caller` | `preferred_username`, validated |
| `PUT /me/email` | `caller` | Starts verification; 202 with masked destination |
| `POST /me/email/confirm` | `caller` | Completes it |
| `GET /admin/users` | `administrator` | List / filter, paginated |
| `GET /admin/users/{u}` | `administrator` | One user. `accountId` is the immutable id, `username` the mutable alias |
| `PATCH /admin/users/{u}/attributes` | `administrator` | Set attributes |
| `PUT /admin/users/{u}/username` | `administrator` | Set `preferred_username`, validated |
| `POST /admin/users/{u}/enable`, `/disable` | `administrator` | |
| `POST /admin/users/{u}/reset-password` | `administrator` | Forces reset, sends a code |
| `GET`/`PUT`/`DELETE /admin/users/{u}/groups[/{g}]` | `administrator` | Group membership |

### The public surface

Registration cannot sit behind the authorizer — a user has no token before their account exists. Those routes live under a single `/public` prefix, mapped in API Gateway as **its own resource with `AuthorizationType.NONE`** while everything else stays behind the Cognito authorizer. The unauthenticated surface is therefore exactly the routes under that prefix, reviewable by looking at `RegistrationController` and one block in the stack. *Nothing under `/public` may act on an existing account.*

Every action calls Cognito's own unauthenticated operations (`SignUp`, `ConfirmSignUp`, `ResendConfirmationCode`) with the app client id and no IAM credentials, so an anonymous caller can do nothing here they could not already do against Cognito directly. The one exception is the username availability check inside sign-up, which uses `ListUsers` under the service role.

Sign-up returns an **`accountId`** the client must keep until confirmation. An unconfirmed account has no `preferred_username` yet, so that opaque id is the only value Cognito will accept for confirming or resending — the name the user chose will not work. This is the same constraint `web/src/pending-signup.ts` works around in the browser; the API now makes it explicit in the contract.

The availability check exists because the alias is only assigned at confirmation. Without it two people can register the same name and the second is rejected *at confirmation*, with the account already created and no way to change the staged name. Checking up front is a deliberate disclosure — a sign-up form has to say whether a name is taken — but it is confined to sign-up attempts rather than exposed as a standalone lookup, so each guess costs a rate-limited request with side effects. A race between two simultaneous sign-ups is still possible and still fails at confirmation.

### The two authorities

The split is the point of the design, not a convenience.

**`/me` uses the caller's own access token.** Requests are forwarded to Cognito as the user, so Cognito applies the **app client's attribute write permissions** to every call. A bug in this API's authorization cannot let a user write an attribute the app client is not allowed to write.

**`/admin` uses the service's IAM role.** `Admin*` calls bypass app client permissions entirely. That is why admin routes are gated on membership of the `padi-sso-admins` Cognito group, why every one is audited *before* it acts, and why the IAM policy grants only the nine actions the code actually calls — `AdminDeleteUser` and `AdminSetUserPassword` are deliberately absent.

No `/me` route takes a user identifier. There is no route shape that lets a caller name someone else's account, so even a misconfigured policy cannot turn self-service into administration.

### Guardrails

- **`email_verified` cannot be set through the API**, along with `sub`, `phone_number_verified`, `cognito:username` and `identities`. Writing `email_verified: true` would let an administrator mark any address as verified and capture account recovery without ever proving control of the mailbox.
- **`preferred_username` is rejected by the generic attribute route** and must go through the dedicated username route, so it cannot bypass [`UsernameRules`](#username-characters).
- **The token is validated twice** — once by the gateway's Cognito authorizer, once by the API. The second check keeps the API safe if it is ever reached directly, and is what populates the claims the policies read.
- **Cognito access tokens carry `client_id`, not `aud`**, so audience validation is off and the client id is checked by an explicit requirement instead. Without it, a token minted by any other app client on the same pool would be accepted.

## Post-confirmation trigger

Fires once, after a user confirms their account. Its only job is to promote `custom:signup_username` into `preferred_username` — see [Mutable usernames](#mutable-usernames) for why the value cannot be set at sign-up.

It is idempotent in both directions: it returns early if `preferred_username` is already set (confirmation can be replayed), and logs a warning without failing if there is no staged name (an admin-created or federated account, which arrives by another route). A staged name that fails `UsernameRules` throws rather than being written — see [Username characters](#username-characters).

### Failure behaviour

**Exceptions propagate deliberately** — the opposite of the PostAuthentication trigger. That one runs inside a sign-in, where throwing would deny an already-successful authentication. This one runs after confirmation, where a swallowed failure produces an account with no sign-in alias, reachable only by a UUID the user has never seen. A visible failure at confirmation beats a silently unreachable account.

IAM is a standalone `Policy` on the function's role rather than `AddToRolePolicy`, for the same reason as PostAuthentication: the pool references the function in `LambdaConfig`, and CDK makes a function depend on its role's default policy, so a pool ARN in that policy would close a `UserPool → Function → DefaultPolicy → UserPool` cycle.

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
| `CustomEmailSender_UpdateUserAttribute` | Attribute change verification — the change-email flow |
| `CustomEmailSender_VerifyUserAttribute` | New attribute verification — "resend code" on that flow |
| `CustomEmailSender_AdminCreateUser` | Temporary password |
| `CustomEmailSender_AccountTakeOverNotification` | Threat-protection alert |

Cognito encrypts the one-time code with a customer-managed KMS key using the **AWS Encryption SDK envelope format** — `kms:Decrypt` alone will not open it, which is why `CustomEmailSender` depends on `AWS.Cryptography.EncryptionSDK`. Codes are never logged; only trigger source, definition key, request ID and a masked recipient are.

The recipient is masked as `m***7@gmail.com` — first and last character of the local part, deliberately weaker than a full mask so two similar addresses stay distinguishable in a log line.

**On `UpdateUserAttribute`, `userAttributes.email` carries the user's new address, not the existing one** — confirmed against the live pool. This is worth stating explicitly because the AWS documentation reads the other way at first glance: it says the original value stays active "for sign-in and to receive messages" until the new one is verified. That sentence covers *other* messages. The verification code itself goes to the new address, which is the only behaviour consistent with the worked example on the same page, where a user who mistypes the new address never receives the email.

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

A `Default` parameter, if set, serves any trigger source without its own entry:

```bash
aws ssm put-parameter --name /padi/services/authentication/Messaging/Definitions/Default --type String --value "<definition-key>" --region us-west-2
```

Every message this sender delivers is fundamentally "here is a code", so one generic template is a workable catch-all. It exists so that a newly-exercised flow degrades to a generic email rather than silently sending nothing — the failure mode that is hardest to diagnose, because Cognito still reports success to the caller.

A trigger source with no matching parameter *and* no `Default` logs a warning naming the missing key, and sends nothing rather than failing the underlying Cognito operation. `SignUp` and `Authentication` are what the sign-up and OTP flows depend on; `UpdateUserAttribute` and `VerifyUserAttribute` are what the change-email flow depends on.

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
| `apiName` | REST API name |
| `apiStageName` | Deployment stage — appears in the `execute-api` URL, hidden behind a custom domain |
| `apiDomainName` | An **existing** custom domain to attach to. Empty leaves the API on its `execute-api` URL |
| `apiBasePath` | The path to claim under that domain, e.g. `p/padi-auth-poc`. Multi-level is supported. Required whenever `apiDomainName` is set |
| `apiEndpointType` | `edge` or `regional`. Must match the custom domain's own endpoint type |
| `apiAllowedOrigins` | CORS origins permitted to call the API |
| `apiThrottleRatePerSecond` | Stage throttle, steady-state |
| `apiThrottleBurst` | Stage throttle, burst |
| `adminGroupName` | Cognito group whose members may call `/admin` routes |

### Attaching to the custom domain

The API does **not** own a domain. It claims a base path under one that already exists:

```
https://api.global-np.padi.com/p/padi-auth-poc/public/signup
                                              └── the API sees /public/signup
```

API Gateway strips the mapped path before matching resources, so routes are written as if the API were at a domain root and nothing in the code changes when the path does.

Only an `AWS::ApiGatewayV2::ApiMapping` is created — no domain, no certificate. Those belong to whoever owns the domain, and `cdk destroy` removes the mapping without touching it. That is why `apiDomainCertArn` no longer exists.

**The V2 resource is required, not a preference.** `apiBasePath` has two segments, and `AWS::ApiGateway::BasePathMapping` only supports one. AWS is explicit: *"To create API mappings with multiple levels, you must use `AWS::ApiGatewayV2`."* The V1 resource synthesizes a multi-level path without complaint and fails at deploy, so this is not something CDK will catch for you. Multi-level mappings also require the domain to be **Regional with the TLS 1.2 security policy** — `api.global-np.padi.com` is both.

Consequences of a multi-level mapping worth knowing:

- **Header names are lowercased.** *"If you create an API mappings with multiple levels, API Gateway converts all header names to lowercase."* ASP.NET Core matches headers case-insensitively so this API is unaffected, but anything comparing raw header names would be.
- **Longest matching path wins.** With `p/padi-auth-poc` and a hypothetical `p` mapping on the same domain, requests to `/p/padi-auth-poc/...` reach this API and `/p/anything-else` reaches the other.
- **Characters are restricted** to letters, numbers and `$-_.+!*'()/`, max 300. The stack validates this at synth rather than letting the deploy fail.
- **The domain's routing mode** must be `ROUTING_RULE_THEN_API_MAPPING` or `API_MAPPING_ONLY` for API mappings to apply at all.

Two things to get right:

- **`apiBasePath` cannot be empty while `apiDomainName` is set.** An empty base path maps to the *root* of the domain, capturing every request that matches no other mapping — on a shared domain that hijacks it. The stack throws at synth rather than let this happen by omission.
- **Endpoint types must match.** A custom domain has its own endpoint type and `apiEndpointType` has to agree with it. `api.global-np.padi.com` is `REGIONAL`, so the API is too. Check before changing either:

  ```bash
  aws apigateway get-domain-name --domain-name api.global-np.padi.com --region us-west-2
  ```

- **The path must be free.** The domain is shared — its tags name `padi-api` / team `learning` as owner — so other services already hold mappings on it. A collision fails the deploy. List what is taken (v2, so multi-level mappings are shown):

  ```bash
  aws apigatewayv2 get-api-mappings --domain-name api.global-np.padi.com --region us-west-2
  ```

Leave `apiDomainName` empty and the mapping is skipped entirely — the API is reachable at its `execute-api` URL, which is the current default.

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

That script also publishes `src/Api`, which `PadiSsoApiStack` packages as an asset.

### Naming the stack

The app defines **two** stacks — `PadiSsoPocStack` and `PadiSsoApiStack` — so the CLI will not guess:

> Since this app includes more than a single stack, specify which stacks to use (wildcards are supported) or specify `--all`

`deploy` and `destroy` refuse to run without a selection. Name a stack, pass `--all`, or use a wildcard such as `'PadiSso*'` — quoted, so the shell does not expand it.

`synth` is the exception: with no stack it still succeeds and writes **both** templates to `cdk.out`, and only declines to print one —

```
Supply a stack id (PadiSsoPocStack, PadiSsoApiStack) to display its template.
```

So this is enough to produce templates, and `--quiet` just suppresses that note:

```bash
npx cdk synth --quiet
```

To print one template, name it:

```bash
npx cdk synth PadiSsoApiStack
```

Inspect pending changes before deploying:

```bash
npx cdk diff --all
```

Deploy. `PadiSsoApiStack` takes the pool by reference, so CDK orders them — pool first — and `--all` is enough:

```bash
npx cdk deploy --all
```

To deploy just one:

```bash
npx cdk deploy PadiSsoApiStack
```

### Replacing the user pool

Adding `preferred_username` changed the pool's construct ID to `PadissoUserPoolV2`, because sign-in alias configuration is fixed at creation and `UpdateUserPool` cannot change it. CloudFormation therefore **creates a new pool** and, under `RemovalPolicy.RETAIN`, leaves the previous one orphaned rather than deleting it. New pool id, new app client id, no users.

There is an ordering trap: **a custom domain can only be attached to one pool at a time.** The retained pool keeps whatever domain it already holds, so a new pool asking for the same name fails — and because the pool is `RETAIN`, the failed rollback would orphan a half-built pool.

This deployment sidestepped it by moving to a **new subdomain**: `cognitoDomain` changed from `auth-stage-v2.padi.com` to `auth-poc-stage-v2.padi.com`, so the two pools never contend. The ACM certificate covers both. That is the cheapest route when the old pool is being kept around.

The alternatives, if the domain name has to be reused: delete the old pool first, or deploy in two steps —

```bash
npx cdk deploy -c customDomainEnabled=false
```

— then delete the old pool (it has no deletion protection) and deploy again normally to attach the domain.

Either way, copy the new `UserPoolId` and `UserPoolClientId` outputs into `web/.env.local`; the old values will not work, and a client id from one pool paired with another pool's id fails on the first call. `RequestMagicLinkUrl` and `VerifyMagicLinkUrl` do **not** change — the Function URLs survive because only the pool is replaced, not the Lambdas.

### Stack outputs

`PadissoUserPoolId`, `PadissoUserPoolClientId`, `PadissoUserPoolDomain`, `RequestMagicLinkUrl`, `VerifyMagicLinkUrl`

---

## Web client

A minimal React reference client lives in `web/` — Vite, TypeScript, and AWS Amplify v6.

| Route | Purpose |
|---|---|
| `/signup` | Username, password, email, first name, last name |
| `/confirm` | 6-digit email verification code; account is unconfirmed until entered. Resolves the chosen name to the opaque account id via `localStorage` |
| `/login` | Username + password over SRP |
| `/forgot-password` | Two-step reset: username, then code + new password |
| `/passwordless` | Choice-based `USER_AUTH` — email OTP, SMS OTP, or passkey |
| `/magic-link` | Requests a link; manual token redemption as a fallback |
| `/verify` | Where the emailed link lands — redeems the token automatically and shows a placeholder signed-in page |
| `/change-email` | Two-step email change: new address, then the verification code. Signed-in only |
| `/change-username` | Updates `preferred_username`. Immediate, no verification step. Signed-in only |
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
- **Password reset does not reveal whether an account exists.** The app client sets `PreventUserExistenceErrors`, so `resetPassword` for an unknown username returns a normal `CONFIRM_RESET_PASSWORD_WITH_CODE` step with a **fabricated** masked destination rather than throwing. Verified: `not-a-real-user-9df3` returns `n***@h***`. Don't "improve" `/forgot-password` by surfacing a not-found error — that would reintroduce enumeration.
- **Changing email needs a session refresh.** The ID token caches the `email` claim, so `/change-email` calls `fetchAuthSession({ forceRefresh: true })` after confirming. Without it the dashboard keeps showing the old address even though the pool has the new one.
- **Email is not unique.** It is an attribute, not a sign-in alias, so Cognito will not stop two accounts holding the same address. `/change-email` only rejects re-entering the account's *current* address. Enforce uniqueness in the app if it matters.

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

**Lambda timeouts are 30 seconds, but Cognito triggers are bounded by Cognito, not Lambda.** `DefineAuthChallenge`, `CreateAuthChallenge`, `VerifyAuthChallenge`, `PostAuthentication`, `PostConfirmation` and `CustomEmailSender` all run synchronously inside a Cognito request, and Cognito abandons a trigger after roughly 5 seconds regardless of the configured Lambda timeout. The higher ceiling helps with cold starts and produces a real stack trace instead of a bare `Task timed out`, but a trigger that genuinely needs longer must be made faster or asynchronous. The two Function URLs are not triggers, so 30 seconds applies to them directly.

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

- **The V2 pool is deployed but the mutable-username flows are untested.** Sign-up, password reset and change email were proven against the *previous* pool, before `preferred_username` existed. The triggers and messaging path are unchanged so they should carry over, but nothing in the new design has been exercised. Test sign-up first: it now spans `signUp` → `PostConfirmation` → alias assignment, the longest untried path in the system, and the only one that can leave an account unreachable if it fails.
- **The previous pool is orphaned, not deleted.** `RemovalPolicy.RETAIN` means CloudFormation left it behind when the logical ID changed. It still holds the old test accounts and the `auth-stage-v2.padi.com` custom domain, and it still bills for anything the feature plan charges. Delete it once nothing depends on it.
- **Confirmation is browser-bound.** Between sign-up and confirmation an account has no `preferred_username`, so the opaque UUID is the only identifier Cognito accepts, and it lives in `localStorage`. A user who abandons confirmation and returns on another device cannot finish; they sign up again, and the chosen name is still free. Acceptable for a POC — a production flow should confirm by emailed link carrying the id, or auto-confirm via `PreSignUp` and verify email separately.
- **The management API has never served an authenticated request.** Startup, routing, and rejection of missing and malformed tokens are verified locally; nothing has been exercised with a real Cognito token, because the new pool has no users yet and no one is in `padi-sso-admins`. Both authorization policies and every Cognito call are unproven.
- **No AWS WAF is attached yet, and `/public/signup` is now an unauthenticated write.** REST API was chosen specifically because it *can* carry WAF, but no web ACL is associated. Stage throttling (50 rps / 100 burst) is the only limit and it is per-stage, not per-caller — so one client can consume the whole budget. Sign-up is the endpoint that makes this urgent: each call creates a Cognito user *and* sends an email through the messaging service, so abuse costs money and sender reputation, not just capacity. Attach a web ACL with a rate-based rule, and consider a CAPTCHA before opening it to the internet.
- **A username can still be lost between sign-up and confirmation.** The availability check narrows the window but does not close it; two simultaneous sign-ups for the same name both succeed, and the second fails at confirmation with the account already created. Recovery today is to register again.
- **The base path `auth` is unverified.** `api.global-np.padi.com` is shared with other services, and a mapping that collides with an existing one fails the deploy. Run `get-base-path-mappings` against the domain before deploying, and change `apiBasePath` if `auth` is taken.
- **Magic-link Function URLs are still `AuthType.NONE` and outside the gateway.** The API now provides the WAF-capable front door the README has wanted for them, but `/request-link` and `/verify` have not been moved behind it.
- **Password policy is below current guidance** — 6 characters is Cognito's floor and short of the 8-character minimum in NIST SP 800-63B. The composition rules are also an unusual pairing: uppercase and lowercase are mandatory while digits are not, which pushes users toward predictable shapes like `Passwd` without adding real entropy. Prefer a longer minimum over composition requirements, and enable threat protection (requires the `plus` feature plan) so credentials are checked against known-breached passwords.
- **The messaging integration is proven for the account lifecycle, not for every trigger source.** Live `SignUp`, `ForgotPassword` and `UpdateUserAttribute` deliveries have each exercised the whole chain — Parameter Store credentials, the `client_credentials` token request with HTTP Basic client authentication, `EmailProxyRequest` attribute names and PascalCase serialisation, and Encryption SDK code decryption. Register, recover and change-email all worked end to end — though against the pool that `PadissoUserPoolV2` replaces, so they need one confirmation run after the new pool is deployed. Still unexercised: `Authentication`, `ResendCode`, `VerifyUserAttribute`, `AdminCreateUser`, `AccountTakeOverNotification`. These differ only in template key, so the remaining risk is a missing or wrong `Messaging:Definitions:*` entry, not a broken integration — and the `Default` fallback covers any of them that lack a specific key. `Authentication` is the next one worth a live test: the passwordless email-OTP flow depends on it. Because `CustomEmailSender` has no fallback, roll back by removing it from `LambdaTriggers`.
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
