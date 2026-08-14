# PADISSO

AWS CDK application (C# / .NET 10) provisioning an Amazon Cognito user pool for PADI single sign-on.

Supports password, passwordless (email OTP, SMS OTP, passkey), social federation, and a custom magic-link flow backed by Lambda and DynamoDB.

---

## Project layout

```
src/
  Padisso/                    CDK app — PadiSsoPocStack
  Lambdas/
    MagicLink.Shared/         Config, Crypto, Http, IMagicLinkChannel  (no AWS SDK deps)
    MagicLink.Aws/            AWS clients, SES/SNS delivery channels
    DefineAuthChallenge/      Cognito trigger
    CreateAuthChallenge/      Cognito trigger
    VerifyAuthChallenge/      Cognito trigger
    RequestMagicLink/         Lambda Function URL
    VerifyMagicLink/          Lambda Function URL
publish-lambdas.ps1           Publishes all five Lambdas
cdk.json                      Environment configuration (context block)
```

`MagicLink.Shared` deliberately carries no AWS dependencies, keeping the three Cognito triggers around 110 KB instead of bundling SDKs they never call. `MagicLink.Aws` holds the clients and is referenced only by the functions that talk to AWS services.

---

## User pool

| Setting | Value |
|---|---|
| Name | `padi-sso-poc-user-pool` |
| Feature plan | `essentials` |
| Sign-in alias | Username only, **case-insensitive** |
| Optional attributes | email, phone_number, given_name, family_name, birthdate |
| Custom attributes | `custom:padi_id`, `custom:affiliate_id` |
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

### Delivery channels

`IMagicLinkChannel` abstracts transport *and* presentation, since a URL that reads well in email is hostile inside a 160-character SMS segment. Channel is explicit in the request and defaults to email — inferring it would be ambiguous for a user with both an email address and a phone number.

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
| `magicLinkEmailFrom` | Verified SES identity |
| `magicLinkSmsSenderId` | Optional SMS sender ID (unsupported in the US) |

### Secrets

Provider credentials live in AWS Secrets Manager under `padisso-poc/<provider>/<field>` and are resolved at deploy time — nothing sensitive is committed.

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

## Operational notes

**Schema changes are dangerous on a live pool.** Custom attributes cannot be deleted, renamed, or retyped once created, and `Schema` changes have historically triggered CloudFormation *replacement* — which deletes every user. The pool currently sets `RemovalPolicy.DESTROY`, so a replacement would be unrecoverable. Always run `cdk diff` before deploying a schema change, and switch to `RETAIN` before this holds real users.

**Several settings are fixed at pool creation** and cannot be changed later: username case sensitivity, sign-in aliases, and whether an attribute is required. The password policy is *not* among them — it can be tightened on a live pool at any time, and existing passwords are unaffected until their next change.

**Rotating provider secrets does not propagate automatically.** The template embeds `{{resolve:secretsmanager:…}}`, which resolves at deploy time. Changing a secret's value leaves the template byte-identical, so CloudFormation performs no update and the old credential stays live. Rotate via `aws cognito-idp update-identity-provider` out-of-band, then reconcile Secrets Manager.

**Passkeys are bound to the relying party ID.** Changing `passkeyRelyingPartyId` invalidates every passkey registered under the previous value.

---

## Known gaps

This is a proof of concept. Before production:

- **Password policy is below current guidance** — 6 characters is Cognito's floor and short of the 8-character minimum in NIST SP 800-63B. The composition rules are also an unusual pairing: uppercase and lowercase are mandatory while digits are not, which pushes users toward predictable shapes like `Passwd` without adding real entropy. Prefer a longer minimum over composition requirements, and enable threat protection (requires the `plus` feature plan) so credentials are checked against known-breached passwords.
- **SES sender identity** — `magicLinkEmailFrom` must be verified in SES
- **Cognito default email sender caps at 50 messages/day**, which affects email OTP sign-ins; wire `UserPoolEmail.WithSES(...)`
- **Function URLs use `AuthType.NONE`** — publicly reachable with no rate limiting on `/request-link`; put them behind API Gateway with WAF
- **`ADMIN_PROOF` is stored in plain Lambda environment variables**, readable via `GetFunctionConfiguration`; fetch from Secrets Manager at cold start instead
- **`ses:SendEmail` and `sns:Publish` are granted on `*`** and should be scoped
- **No account linking** — a user who registers with a password and later signs in with the same email via a social provider receives a second, separate account. Consider `AdminLinkProviderForUser` from a PreSignUp trigger.
- **SMS is untested** — requires exiting the SNS SMS sandbox and, for US traffic, 10DLC or toll-free registration
- **Threat protection is dormant** — available on the `plus` feature plan but not enabled
