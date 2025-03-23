/**
 * Import function triggers from their respective submodules:
 *
 * const {onCall} = require("firebase-functions/v2/https");
 * const {onDocumentWritten} = require("firebase-functions/v2/firestore");
 *
 * See a full list of supported triggers at https://firebase.google.com/docs/functions
 */


const {onRequest} = require("firebase-functions/v2/https");
const {onCall} = require("firebase-functions/v2/https");
const {HttpsError} = require("firebase-functions/v2/https");
const admin = require("firebase-admin");
const axios = require("axios");

// Initialize Firebase
admin.initializeApp();

// Get config values from environment
const config = process.env;
const clientId = config.FITBIT_CLIENT_ID;
const clientSecret = config.FITBIT_CLIENT_SECRET;
const redirectUri = config.FITBIT_REDIRECT_URI;

// Define runtime options for all functions
const runtimeOpts = {
  region: "us-central1",
  memory: "256MiB",
  timeoutSeconds: 60,
  minInstances: 0,
};

// Fitbit OAuth redirect URL
exports.fitbitOAuthRedirect = onRequest(runtimeOpts, (req, res) => {
  console.log("fitbitOAuthRedirect function called");
  // Validate required configuration
  if (!clientId || !redirectUri) {
    console.error("Missing required Fitbit OAuth configuration");
    return res.status(500).send("Server configuration error");
  }
  // Get userId from request and validate
  const userId = req.query.userId;
  if (!userId) {
    return res.status(400).send("Missing user ID parameter");
  }
  // Add state parameter for security
  const state = Buffer.from(JSON.stringify({userId})).toString("base64");
  const authorizationUrl = `https://www.fitbit.com/oauth2/authorize?` +
    `response_type=code&client_id=${clientId}&` +
    `redirect_uri=${encodeURIComponent(redirectUri)}&` +
    `scope=activity%20profile%20sleep&state=${state}`;
  console.log("Redirecting to Fitbit authorization URL");
  res.redirect(authorizationUrl);
});

// Callback URL that Fitbit redirects to after user logs in
exports.fitbitOAuthCallback = onRequest(runtimeOpts, async (req, res) => {
  console.log("fitbitOAuthCallback function called");
  try {// Check for error response from Fitbit
    if (req.query.error) {
      console.error("Fitbit OAuth error:", req.query.error);
      return res.status(400).send(`FitbitAuthorizationErr: ${req.query.error}`);
    }
    // Get and validate authorization code
    const code = req.query.code;
    if (!code) {
      return res.status(400).send("Missing authorization code");
    }
    // Validate state parameter to prevent CSRF attacks
    const state = req.query.state;
    if (!state) {
      return res.status(400).send("Missing state parameter");
    }
    // Decode state to get userId
    let userId;
    try {
      const decodedState = JSON.parse(Buffer.from(state, "base64").toString());
      userId = decodedState.userId;
    } catch (error) {
      return res.status(400).send("Invalid state parameter");
    }
    if (!userId) {
      return res.status(400).send("User ID not found in state parameter");
    }
    // Validate configuration
    if (!clientId || !clientSecret || !redirectUri) {
      console.error("Missing required Fitbit OAuth configuration");
      return res.status(500).send("Server configuration error");
    }
    console.log("Requesting access token from Fitbit");
    const tokenUrl = "https://api.fitbit.com/oauth2/token";
    const body = new URLSearchParams({
      code: code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
    });
    const response = await axios.post(tokenUrl, body, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    });
    console.log("Token received, storing in Firestore");
    const tokenData = {
      accessToken: response.data.access_token,
      refreshToken: response.data.refresh_token,
      expiresAt: Date.now() + (response.data.expires_in * 1000),
      scope: response.data.scope,
      userId: response.data.user_id,
      tokenType: response.data.token_type,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };
    // Check if user exists first
    const userDoc = await admin.firestore()
        .collection("users")
        .doc(userId)
        .get();
    if (!userDoc.exists) {
      return res.status(404).send("User not found");
    }
    // Save token data in Firestore
    await admin.firestore().collection("users").doc(userId).update({
      fitbitTokenData: tokenData,
    });
    console.log("Token saved, redirecting to success page");
    // Redirect to a success page
    res.redirect(`/fitbit-connected?success=true`);
  } catch (error) {
    console.error("Error in Fitbit OAuth callback:", error);
    // Send appropriate error response with fixed syntax
    if (error.response) {
      console.error("Fitbit API error:", error.response.data);
      const errorMessage = (error.response.data.errors &&
                         error.response.data.errors.length > 0 &&
                         error.response.data.errors[0].message) || "UnknownErr";
      return res.status(error.response.status)
          .send(`Error connecting to Fitbit: ${errorMessage}`);
    }
    res.status(500).send("Error linking Fitbit account Please try again later");
  }
});

// Function to refresh an expired token
exports.refreshFitbitToken = onCall(runtimeOpts, async (data, context) => {
  console.log("refreshFitbitToken function called");
  // Ensure user is authenticated
  if (!context.auth) {
    throw new HttpsError(
        "unauthenticated",
        "You must be logged in to refresh tokens",
    );
  }
  const userId = context.auth.uid;
  try {
    // Get the user's current token data
    const userDoc = await admin.firestore()
        .collection("users")
        .doc(userId)
        .get();
    if (!userDoc.exists) {
      throw new HttpsError("not-found", "User not found");
    }
    const tokenData = userDoc.data().fitbitTokenData;
    if (!tokenData || !tokenData.refreshToken) {
      throw new HttpsError(
          "failed-precondition",
          "No Fitbit refresh token found",
      );
    }
    console.log("Refreshing token for user:", userId);
    // Request a new access token using the refresh token
    const tokenUrl = "https://api.fitbit.com/oauth2/token";
    const body = new URLSearchParams({
      refresh_token: tokenData.refreshToken,
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: "refresh_token",
    });
    const response = await axios.post(tokenUrl, body, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    });
    console.log("New token received, updating in Firestore");
    // Update token information
    const newTokenData = {
      accessToken: response.data.access_token,
      refreshToken: response.data.refresh_token,
      expiresAt: Date.now() + (response.data.expires_in * 1000),
      scope: response.data.scope,
      userId: response.data.user_id,
      tokenType: response.data.token_type,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };
    // Save updated token data
    await admin.firestore().collection("users").doc(userId).update({
      fitbitTokenData: newTokenData,
    });
    return {success: true};
  } catch (error) {
    console.error("Error refreshing Fitbit token:", error);
    throw new HttpsError(
        "internal",
        "Failed to refresh Fitbit token",
    );
  }
});
