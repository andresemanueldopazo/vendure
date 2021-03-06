import 'dotenv/config'
import {
    dummyPaymentHandler,
    DefaultJobQueuePlugin,
    DefaultSearchPlugin,
    VendureConfig,
    NativeAuthenticationStrategy,
} from '@vendure/core'; 
import { defaultEmailHandlers, EmailPlugin } from '@vendure/email-plugin';
import { AssetServerPlugin } from '@vendure/asset-server-plugin';
import { AdminUiPlugin } from '@vendure/admin-ui-plugin';
import path from 'path';
import { GoogleAuthenticationStrategy } from './GoogleAuthenticationStrategy';
import { FacebookAuthenticationStrategy } from './FacebookAuthenticationStrategy';
import { StripePlugin } from '@vendure/payments-plugin/package/stripe';

export const config: VendureConfig = {
    apiOptions: {
        port: parseInt(process.env.API_PORT!),
        adminApiPath: 'admin-api',
        adminApiPlayground: {
            settings: {
                'request.credentials': 'include',
            } as any,
        },// turn this off for production
        adminApiDebug: true, // turn this off for production
        shopApiPath: 'shop-api',
        shopApiPlayground: {
            settings: {
                'request.credentials': 'include',
            } as any,
        },// turn this off for production
        shopApiDebug: true,// turn this off for production
    },
    authOptions: {
        shopAuthenticationStrategy: [
            new NativeAuthenticationStrategy(),
            new GoogleAuthenticationStrategy(process.env.GOOGLE_CLIENT_ID!),
            new FacebookAuthenticationStrategy({
                appId: process.env.FACEBOOK_APP_ID!,
                appSecret: process.env.FACEBOOK_APP_SECRET!,
                clientToken: process.env.FACEBOOK_CLIENT_TOKEN!
            }),
        ],
        requireVerification: false,
        superadminCredentials: {
            identifier: process.env.SUPERADMIN_IDENTIFIER!,
            password: process.env.SUPERADMIN_PASSWORD!,
        },
        cookieOptions: {
          secret: process.env.COOKIE_SECRET || 'cookie-secret',
        },
    },
    dbConnectionOptions: {
        type: 'better-sqlite3',
        synchronize: true, // turn this off for production
        logging: false,
        database: path.join(__dirname, '../vendure.sqlite'),
        migrations: [path.join(__dirname, '../migrations/*.ts')],
    },
    paymentOptions: {
        paymentMethodHandlers: [dummyPaymentHandler],
    },
    customFields: {},
    plugins: [
        StripePlugin.init({
            apiKey: process.env.YOUR_STRIPE_SECRET_KEY!,
            webhookSigningSecret: process.env.YOUR_STRIPE_WEBHOOK_SIGNING_SECRET!,
            // This prevents different customers from using the same PaymentIntent
            storeCustomersInStripe: true,
          }),
        AssetServerPlugin.init({
            route: 'assets',
            assetUploadDir: path.join(__dirname, '../static/assets'),
        }),
        DefaultJobQueuePlugin.init({ useDatabaseForBuffer: true }),
        DefaultSearchPlugin.init({ bufferUpdates: false, indexStockStatus: true }),
        EmailPlugin.init({
            devMode: true,
            outputPath: path.join(__dirname, '../static/email/test-emails'),
            route: 'mailbox',
            handlers: defaultEmailHandlers,
            templatePath: path.join(__dirname, '../static/email/templates'),
            globalTemplateVars: {
                // The following variables will change depending on your storefront implementation
                fromAddress: '"example" <noreply@example.com>',
                verifyEmailAddressUrl: process.env.VERIFY_EMAIL_ADDRESS_URL,
                passwordResetUrl: process.env.PASSWORD_RESET_URL,
                changeEmailAddressUrl: process.env.CHANGE_EMAIL_ADDRESS_URL
            },
        }),
        AdminUiPlugin.init({
            route: 'admin',
            port: parseInt(process.env.ADMIN_PORT!)
        }),
    ],
};
