# PADISSO architecture

Five views of the same system: what runs in AWS, how identity is modelled, how the code is
layered, and how the two non-obvious flows sequence.

Two CDK stacks: `PadiSsoPocStack` (the pool and its triggers) and `PadiSsoApiStack` (the
management API behind API Gateway). The API stack takes the pool by reference, so CDK orders
the deployments.

---

## 1. Deployed architecture

```mermaid
flowchart LR
    subgraph client["Browser — web/ (React 19 + Vite + Amplify v6)"]
        UI["Sign-up · Confirm · Login · Forgot password<br/>Passwordless · Magic link · Passkeys<br/>Dashboard · Change email · Change username"]
    end

    subgraph aws["AWS — us-west-2"]
        subgraph idp["Amazon Cognito"]
            POOL["User Pool<br/>padi-sso-poc-user-pool<br/>opaque UUID username +<br/>mutable preferred_username alias<br/>case-insensitive · essentials"]
            DOMAIN["Custom domain<br/>auth-poc-stage-v2.padi.com"]
        end

        subgraph triggers["Cognito trigger Lambdas (.NET 10, ARM-free x64, 30s)"]
            DEFINE["DefineAuthChallenge"]
            CREATE["CreateAuthChallenge"]
            VERIFYC["VerifyAuthChallenge"]
            POSTAUTH["PostAuthentication"]
            POSTCONF["PostConfirmation"]
            EMAILSENDER["CustomEmailSender"]
        end

        subgraph fnurls["Magic-link Lambdas (Function URLs, AuthType.NONE + CORS)"]
            REQ["RequestMagicLink"]
            VER["VerifyMagicLink"]
        end

        subgraph apigw["PadiSsoApiStack — separate stack"]
            GW["API Gateway REST · regional<br/>/public/* → no authorizer<br/>everything else → Cognito authorizer<br/>api.global-np.padi.com/p/padi-auth-poc<br/>stage throttle"]
            API["Api — ASP.NET Core MVC in Lambda<br/>Registration · Session · Me · AdminUsers"]
        end

        DDB[("DynamoDB<br/>padi-sso-poc-magic-links<br/>single-use, TTL")]
        KMS["KMS key<br/>alias/padi-sso-poc-cognito-codes"]
        SSM["SSM Parameter Store<br/>/padi/services/authentication"]
        SM["Secrets Manager<br/>ADMIN_PROOF · IdP secrets"]
        SES["SES"]
        SNS["SNS"]
        LOGS["CloudWatch Logs<br/>audit trail"]
    end

    MSG["PADI Messaging Service<br/>messaging-stage.global-np.padi.com<br/>OAuth2 client_credentials"]

    UI -->|"USER_SRP_AUTH · SignUp · OTP · WebAuthn"| POOL
    UI -.->|"hosted UI / social"| DOMAIN
    DOMAIN --- POOL

    POOL --> DEFINE
    POOL --> CREATE
    POOL --> VERIFYC
    POOL --> POSTAUTH
    POOL --> POSTCONF
    POOL -->|"KMS-encrypted code"| EMAILSENDER

    POSTCONF -->|"custom:signup_username<br/>→ preferred_username"| POOL

    UI -->|"POST /request-link"| REQ
    UI -->|"GET /verify?token"| VER

    UI -->|"Bearer access token"| GW
    UI -->|"/public/login · signup · confirm · resend<br/>no token — none exists yet"| GW
    GW -->|"authorizer validates,<br/>then proxy integration"| API
    GW -.->|"validates token against"| POOL
    API -->|"/me — caller's access token"| POOL
    API -->|"/admin — service IAM role"| POOL

    EMAILSENDER -->|decrypt| KMS
    EMAILSENDER -->|"send templated email"| MSG
    POSTAUTH -->|"AdminUpdateUserAttributes<br/>custom:last_login"| POOL
    POSTAUTH --> LOGS

    REQ -->|"put token hash"| DDB
    REQ -->|"AdminGetUser"| POOL
    REQ -->|email| SES
    REQ -.->|"sms (wired, unused)"| SNS
    VER -->|"conditional delete (single use)"| DDB
    VER -->|"AdminInitiateAuth CUSTOM_AUTH"| POOL

    EMAILSENDER -.->|"client id / secret / templates"| SSM
    REQ -.-> SM
    VER -.-> SM
```

Dashed edges are configuration or not-yet-active paths. `CustomSMSSender` exists in code
but is not wired to the pool.

---

## 2. Identity model

Three identifiers, only one of which the user ever types. This is the part most likely to
be misread by someone new to the codebase.

| Identifier | Mutable | Who sees it | Role |
|---|---|---|---|
| `sub` | Never | Nobody | Cognito's internal id. Stable across everything |
| `username` | Never | Nobody | An opaque UUID minted at sign-up. Cognito fixes it at creation |
| `preferred_username` | **Yes** | The user | The name they type to sign in. Unique pool-wide |
| `email` | Yes | The user | A plain attribute — **not** an alias, so not unique |

Cognito's `username` cannot be changed after a user is created, so it cannot be the name
anyone types. `preferred_username` is configured as an **alias attribute**, which makes it a
sign-in identifier the user can update.

```mermaid
sequenceDiagram
    autonumber
    participant U as Browser
    participant C as Cognito
    participant P as PostConfirmation

    Note over U: user picks "minh9"
    U->>C: signUp(username: "a7f3e2c1-…",<br/>custom:signup_username: "minh9")
    Note over U,C: preferred_username is rejected here —<br/>Cognito forbids it in SignUp while it is an alias,<br/>so the chosen name is parked in a custom attribute
    C-->>U: CONFIRM_SIGN_UP
    Note over U: UUID kept in localStorage —<br/>no alias exists yet, so it is the<br/>only way to reach the account
    U->>C: confirmSignUp(username: "a7f3e2c1-…", code)
    C->>P: PostConfirmation trigger
    P->>C: AdminUpdateUserAttributes<br/>preferred_username = "minh9"
    U->>C: signIn("minh9") ✓

    Note over U,C: later
    U->>C: updateUserAttributes(preferred_username: "minh-new")
    U->>C: signIn("minh-new") ✓ — "minh9" is released
```

The gap between sign-up and confirmation is the sharp edge: the account has no alias yet, so
the UUID is the only identifier `confirmSignUp` and `resendSignUpCode` accept — and the user
has never seen it. `web/src/pending-signup.ts` holds it in `localStorage` so a reload or a
login-page redirect recovers. Confirming on a different device is not possible; the user
signs up again, and the chosen name is still free because it never became an alias.

---

## 3. Code layers

Dependencies point inward only. Nothing in `Domain` or `Application` references an AWS SDK.

```mermaid
flowchart TD
    WEBAPI["src/Api — ASP.NET Core MVC<br/>controllers + contracts<br/>auth policies"]

    subgraph lam["src/Lambdas — thin adapters + composition roots"]
        L1["DefineAuthChallenge"]
        L2["CreateAuthChallenge"]
        L3["VerifyAuthChallenge"]
        L4["PostAuthentication"]
        L8["PostConfirmation"]
        L5["CustomEmailSender"]
        L6["RequestMagicLink"]
        L7["VerifyMagicLink"]
    end

    subgraph infra["src/Infrastructure — adapters, split per concern"]
        ICore["Core<br/>config + clock + audit<br/>no AWS SDK"]
        ICfg["Configuration<br/>SSM provider"]
        ICog["Cognito"]
        IDdb["DynamoDb"]
        IKms["Kms<br/>Encryption SDK"]
        IMsg["Messaging<br/>token + email/SMS client"]
        INot["Notifications<br/>SES / SNS delivery"]
    end

    APP["src/Application<br/>use cases + ports<br/>CustomAuthChallenge · SendCognitoMessage<br/>RecordSignIn · AssignPreferredUsername<br/>RequestMagicLink · RedeemMagicLink<br/>RegisterUser · ChangeUsername · SetUserUsername"]
    DOM["src/Domain<br/>MagicLinkToken · DeliveryChannel<br/>CognitoTriggerSource · SharedSecret"]

    CDK["src/Padisso<br/>CDK app — PadiSsoPocStack, PadiSsoApiStack"]

    L1 --> APP
    L2 --> APP
    L3 --> APP
    L4 --> ICog
    L5 --> ICfg
    L5 --> IKms
    L5 --> IMsg
    L6 --> ICog
    L6 --> IDdb
    L6 --> INot
    L7 --> ICog
    L7 --> IDdb

    L8 --> ICog
    L8 --> ICore
    L4 --> ICore
    L5 --> ICore
    L6 --> ICore
    L7 --> ICore

    WEBAPI --> APP
    WEBAPI --> ICog
    WEBAPI --> ICore

    ICore --> APP
    ICfg --> ICore
    ICog --> APP
    IDdb --> APP
    IKms --> APP
    IMsg --> APP
    INot --> APP
    APP --> DOM

    CDK -.->|deploys| lam
```

**Why infrastructure is split per concern rather than one project:** each Lambda pulls in
only the AWS SDKs it uses. The published bundle sizes show what that buys:

| Lambda | References | Size |
|---|---|---|
| `DefineAuthChallenge` | `Application` only | 249 KB |
| `CreateAuthChallenge` | `Application` only | 245 KB |
| `VerifyAuthChallenge` | `Application` only | 245 KB |
| `PostAuthentication` | `+ Cognito`, `Core` | 5.0 MB |
| `PostConfirmation` | `+ Cognito`, `Core` | 5.0 MB |
| `VerifyMagicLink` | `+ DynamoDb` | 7.5 MB |
| `RequestMagicLink` | `+ Notifications` | 9.4 MB |
| `CustomEmailSender` | `+ Configuration`, `Kms`, `Messaging` | 30 MB |

The three challenge triggers carry no AWS SDK at all. `Configuration` is separate from
`Core` precisely so the Systems Manager SDK reaches only `CustomEmailSender` — one bundle
out of eight. Collapsing infrastructure into a single project would push every function
toward that 30 MB.

---

## 4. Magic-link flow

The bespoke part — a custom auth flow driven server-side, so the browser never holds a
Cognito secret.

```mermaid
sequenceDiagram
    autonumber
    participant U as Browser
    participant R as RequestMagicLink
    participant C as Cognito
    participant D as DynamoDB
    participant E as SES
    participant V as VerifyMagicLink

    U->>R: POST /request-link { username }
    R->>C: AdminGetUser (accepts the alias)
    Note over R: unknown user or no destination<br/>→ silent 200 (no enumeration)
    R->>R: issue token against the *immutable*<br/>username, not the alias supplied
    R->>D: put { hash, username, expiresAt = now + 15m }
    R->>E: send link containing raw token
    R-->>U: 200 (always)

    U->>V: GET /verify?token
    V->>D: conditional delete on hash, ReturnValue = ALL_OLD
    Note over V: delete-then-validate makes<br/>the token single-use atomically
    V->>V: reject if absent or expired
    V->>C: AdminInitiateAuth CUSTOM_AUTH + ADMIN_PROOF
    C->>C: Define → Create → Verify challenge Lambdas
    C-->>V: id / access / refresh tokens
    V-->>U: tokens
```

The three challenge Lambdas exist only to satisfy Cognito's custom-auth contract; the real
check already happened in `VerifyMagicLink`. `ADMIN_PROOF` is the shared secret that lets
them distinguish a server-initiated flow from a client-initiated one.

Storing the immutable username rather than the caller's input matters now that usernames are
mutable: a user who changes their name between requesting a link and clicking it would
otherwise hold a token pointing at an alias that no longer resolves.

---

## 5. Email delivery

Every Cognito-originated email — sign-up confirmation, password reset, passwordless OTP,
MFA — leaves through `CustomEmailSender`, not Cognito's built-in mailer.

```mermaid
sequenceDiagram
    autonumber
    participant C as Cognito
    participant S as CustomEmailSender
    participant K as KMS / Encryption SDK
    participant P as SSM Parameter Store
    participant T as PADI token endpoint
    participant M as PADI messaging API

    C->>S: trigger + KMS-encrypted code
    S->>P: Messaging:ClientId / ClientSecret / Definitions:*
    S->>K: decrypt code
    Note over S,K: commitment policy<br/>REQUIRE_ENCRYPT_ALLOW_DECRYPT<br/>Cognito uses a non-committing suite
    S->>T: POST { "grant_type": "client_credentials" } + Basic auth
    T-->>S: bearer token (cached, 60s skew)
    S->>M: EmailProxyRequest { DefinitionKey, RecipientEmail, Attributes }
```

There is **no fallback**: if the messaging call fails, sign-up, password reset and email OTP
all fail together. The trigger source name selects the template — `CustomEmailSender_SignUp`
becomes definition key `SignUp`, falling back to `Default` when that key is unset.

On `CustomEmailSender_UpdateUserAttribute` — the change-email flow — `userAttributes.email`
carries the user's **new** address, so the code reaches the address being verified rather
than the one still active for sign-in. Confirmed against the live pool.
