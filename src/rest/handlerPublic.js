import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand
} from "@aws-sdk/client-cognito-identity-provider";

const cognito = new CognitoIdentityProviderClient({});
const CLIENT_ID = process.env.CLIENT_ID;


function json(statusCode, data) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data)
  };
}

function convertJson(s) {
  try {
    return JSON.parse(s || "{}");
  } catch {
    return {};
  }
}

export const handler = async (event) => {
  
  if (event.requestContext?.http?.method === "OPTIONS") {
    return json(204, {});
  }

  const body = convertJson(event.body);
  const { email, password } = body || {};

  if (!email || !password) {
    return json(
      400,
      {
        error: "email_and_password_required"
      }
    );
  }

  try {
    const cognitoResponse = await cognito.send(
      new InitiateAuthCommand({
        ClientId: CLIENT_ID,
        AuthFlow: "USER_PASSWORD_AUTH",
        AuthParameters: { USERNAME: email, PASSWORD: password }
      })
    );

    const { IdToken, AccessToken, RefreshToken, ExpiresIn, TokenType } = cognitoResponse.AuthenticationResult || {};

    return json(200, {
      idToken: IdToken,
      accessToken: AccessToken,
      refreshToken: RefreshToken,
      expiresIn: ExpiresIn,
      tokenType: TokenType
    });
  } catch (e) {
    const name = e.name || "AuthError";
    if (name === "UserNotConfirmedException")  return json(403, { error: "user_not_confirmed" });
    if (name === "NotAuthorizedException")     return json(401, { error: "invalid_credentials" });
    if (name === "PasswordResetRequiredException") return json(403, { error: "password_reset_required" });
    if (name === "UserNotFoundException")      return json(404, { error: "user_not_found" });
    console.error("Auth error:", e);
    return json(500, { error: "auth_failed" });
  }
};