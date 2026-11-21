/**
 * Environment variable validation.
 *
 * Loads .env once, then checks that every core variable exists.
 * The server refuses to start with a clear message instead of
 * failing later with a confusing error.
 *
 * Feature-specific keys (ImgBB, Stripe) only produce a warning,
 * because those features are wired up in later phases.
 */
import "dotenv/config";
/** Core variables the server cannot start without. */
const REQUIRED_KEYS = [
    "PORT",
    "CLIENT_URL",
    "MONGODB_URI",
    "MONGODB_DB_NAME",
    "BETTER_AUTH_SECRET",
    "BETTER_AUTH_URL",
    "JWT_SECRET",
];
/** Feature keys needed only when the related feature is used. */
const FEATURE_KEYS = ["IMGBB_API_KEY", "STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET"];
function assertRequiredVariables() {
    const missing = REQUIRED_KEYS.filter((key) => !process.env[key]);
    if (missing.length > 0) {
        throw new Error(`Missing required environment variables: ${missing.join(", ")}. ` +
            `Copy .env.example to .env and fill in the values.`);
    }
}
function warnAboutMissingFeatureVariables() {
    const missing = FEATURE_KEYS.filter((key) => !process.env[key]);
    if (missing.length > 0) {
        console.warn(`[env] Warning: feature keys not set yet: ${missing.join(", ")}. ` +
            `Those features will be disabled until you add them.`);
    }
}
assertRequiredVariables();
warnAboutMissingFeatureVariables();
export const env = {
    port: Number(process.env.PORT),
    nodeEnv: process.env.NODE_ENV ?? "development",
    clientUrl: process.env.CLIENT_URL,
    mongodbUri: process.env.MONGODB_URI,
    mongodbDbName: process.env.MONGODB_DB_NAME,
    betterAuthSecret: process.env.BETTER_AUTH_SECRET,
    betterAuthUrl: process.env.BETTER_AUTH_URL,
    jwtSecret: process.env.JWT_SECRET,
    imgbbApiKey: process.env.IMGBB_API_KEY ?? "",
    stripeSecretKey: process.env.STRIPE_SECRET_KEY ?? "",
    stripeWebhookSecret: process.env.STRIPE_WEBHOOK_SECRET ?? "",
};
