# PADISSO architecture

Three views of the same system: what runs in AWS, how the code is layered, and how the
two non-obvious flows actually sequence.

---

## 1. Deployed architecture

```mermaid
flowchart LR
    subgraph client["Browser — web/ (React 19 + Vite + Amplify v6)"]
        UI["Sign-up · Confirm · Login<br/>Passwordless · Magic link<br/>Passkeys · Dashboard"]
    end

    subgraph aws["AWS — us-west-2"]
        subgraph idp["Amazon Cognito"]
            POOL["User Pool<br/>padi-sso-poc-user-pool<br/>username sign-in, case-insensitive<br/>feature plan: essentials"]
            DOMAIN["Custom domain<br/>auth-stage-v2.padi.com"]
        end

        subgraph triggers["Cognito trigger Lambdas (.NET 10, ARM-free x64, 30s)"]
            DEFINE["DefineAuthChallenge"]
            CREATE["CreateAuthChallenge"]
            VERIFYC["VerifyAuthChallenge"]
            POSTAUTH["PostAuthentication"]
            EMAILSENDER["CustomEmailSender"]
        end

        subgraph fnurls["Magic-link Lambdas (Function URLs, AuthType.NONE + CORS)"]
            REQ["RequestMagicLink"]
            VER["VerifyMagicLink"]
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
    POOL -->|"KMS-encrypted code"| EMAILSENDER

    UI -->|"POST /request-link"| REQ
    UI -->|"GET /verify?token"| VER

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

## 2. Code layers

Dependencies point inward only. Nothing in `Domain` or `Application` references an AWS SDK.

```mermaid
flowchart TD
    subgraph lam["src/Lambdas — thin adapters + composition roots"]
        L1["DefineAuthChallenge"]
        L2["CreateAuthChallenge"]
        L3["VerifyAuthChallenge"]
        L4["PostAuthentication"]
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

    APP["src/Application<br/>use cases + ports<br/>CustomAuthChallenge · SendCognitoMessage<br/>RecordSignIn · RequestMagicLink · RedeemMagicLink"]
    DOM["src/Domain<br/>MagicLinkToken · DeliveryChannel<br/>CognitoTriggerSource · SharedSecret"]

    CDK["src/Padisso<br/>CDK stack — provisions everything above"]

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

    L4 --> ICore
    L5 --> ICore
    L6 --> ICore
    L7 --> ICore

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
only the AWS SDKs it uses. `DefineAuthChallenge`, `CreateAuthChallenge` and
`VerifyAuthChallenge` reference `Application` alone and carry no SDK at all;
`PostAuthentication` takes `Infrastructure.Cognito` but not `Configuration`, so the Systems
Manager SDK stays out of five of the seven bundles. Merging these projects would add tens of
megabytes to every function.

---

## 3. Magic-link flow

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
    R->>C: AdminGetUser
    Note over R: unknown user or no destination<br/>→ silent 200 (no enumeration)
    R->>R: issue token, hash it
    R->>D: put { hash, sub, expiresAt = now + 15m }
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

---

## 4. Email delivery

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
becomes definition key `SignUp`.
