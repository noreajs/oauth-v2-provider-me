import { mongooseModel } from "@noreajs/mongoose";
import { Document, Schema } from "mongoose";
import oauthScopeProvider from "../providers/oauth-scope.provider";
import { IOauthClient, OauthClientGrantType } from "./OauthClient";

export interface IOauthAccessToken extends Document {
  userId: string;
  grant: OauthClientGrantType;
  client: IOauthClient;
  name: string;
  scope: string;
  userAgent: string;
  revokedAt?: Date;
  expiresAt: Date;
}

export default mongooseModel<IOauthAccessToken>({
  name: "OauthAccessToken",
  collection: "oauth_access_tokens",
  autopopulate: true,
  schema: new Schema(
    {
      userId: {
        type: Schema.Types.String,
      },
      grant: {
        type: Schema.Types.String,
        enum: [
          "implicit",
          "client_credentials",
          "password",
          "authorization_code",
        ],
        required: [true, "The grant is required."],
      },
      client: {
        type: Schema.Types.ObjectId,
        ref: "OauthClient",
        autopopulate: true,
      },
      name: {
        type: Schema.Types.String,
      },
      scope: {
        type: Schema.Types.String,
      },
      userAgent: {
        type: Schema.Types.String,
      },
      revokedAt: {
        type: Schema.Types.Date,
      },
      expiresAt: {
        type: Schema.Types.Date,
      },
    },
    {
      timestamps: true,
    }
  ),
  externalConfig: function (schema) {
    /**
     * Before save
     */
    schema.pre<IOauthAccessToken>("save", async function (next) {
      /**
       * Verify missing scopes
       */
      await oauthScopeProvider.validateScopesHook(this.scope, next);
    });
  },
});
