/**
 * The browser half of passkey sign-in. The API relays Cognito's challenge; only the WebAuthn
 * ceremony itself has to happen here, because the authenticator lives on this device.
 *
 * Cognito exchanges WebAuthn data as JSON with binary fields in base64url, while
 * `navigator.credentials.get` takes and returns ArrayBuffers. This converts in both
 * directions, mirroring what Amplify does internally.
 */

type RequestOptionsJson = Omit<PublicKeyCredentialRequestOptions, 'challenge' | 'allowCredentials'> & {
  challenge: string;
  allowCredentials?: (Omit<PublicKeyCredentialDescriptor, 'id'> & { id: string })[];
};

export function isPasskeySupported(): boolean {
  return typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials?.get;
}

/**
 * Runs the passkey ceremony for Cognito's `CREDENTIAL_REQUEST_OPTIONS` and returns the
 * assertion as the `AuthenticationResponseJSON` string Cognito expects in `CREDENTIAL`.
 */
export async function signWithPasskey(credentialRequestOptionsJson: string): Promise<string> {
  if (!isPasskeySupported()) {
    throw new Error('This browser does not support passkeys.');
  }

  const options = JSON.parse(credentialRequestOptionsJson) as RequestOptionsJson;
  const credential = (await navigator.credentials.get({
    publicKey: {
      ...options,
      challenge: fromBase64Url(options.challenge),
      allowCredentials: (options.allowCredentials ?? []).map((c) => ({ ...c, id: fromBase64Url(c.id) })),
    },
  })) as PublicKeyCredential | null;

  if (!credential) {
    throw new Error('No passkey was selected.');
  }

  const response = credential.response as AuthenticatorAssertionResponse;
  return JSON.stringify({
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
    response: {
      clientDataJSON: toBase64Url(response.clientDataJSON),
      authenticatorData: toBase64Url(response.authenticatorData),
      signature: toBase64Url(response.signature),
      userHandle: response.userHandle ? toBase64Url(response.userHandle) : undefined,
    },
  });
}

function fromBase64Url(value: string): ArrayBuffer {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  const bytes = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
  return bytes.buffer;
}

function toBase64Url(buffer: ArrayBuffer): string {
  let binary = '';
  for (const byte of new Uint8Array(buffer)) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
