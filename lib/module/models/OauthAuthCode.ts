import { mongooseModel } from "@noreajs/mongoose";
import { Document, HookNextFunction, Schema } from "mongoose";
import validator from "validator";
import { IAuthorizationResponseType } from "../interfaces/IAuthCodeRequest";
import oauthScopeProvider from "../providers/oauth-scope.provider";
import { IOauthClient } from "./OauthClient";

export interface IOauthAuthCode extends Document {
  userId: string;
  authorizationCode: string;
  client: IOauthClient;
  state?: string;
  strategyState?: string;
  scope: string;
  responseType: IAuthorizationResponseType;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  redirectUri: string;
  userAgent: string;
  revokedAt?: Date;
  expiresAt: Date;
}

export default mongooseModel<IOauthAuthCode>({
  name: "OauthAuthCode",
  collection: "oauth_auth_codes",
  schema: new Schema(
    {
      userId: {
        type: Schema.Types.String,
      },
      authorizationCode: {
        type: Schema.Types.String,
        validate: [
          {
            validator: function (value: string) {
              const self = this as IOauthAuthCode;
              return !(
                self.userId !== null &&
                self.userId != undefined &&
                self.userId.length !== 0 &&
                (value === null || value === undefined || value.length === 0)
              );
            },
            message: "Authorization code is required.",
          },
        ],
      },
      client: {
        type: Schema.Types.ObjectId,
        ref: "OauthClient",
        required: [true, "The oauth client is required."],
        autopopulate: true,
      },
      state: {
        type: Schema.Types.String,
      },
      strategyState: {
        type: Schema.Types.String,
      },
      scope: {
        type: Schema.Types.String,
      },
      responseType: {
        type: Schema.Types.String,
        enum: ["code", "token"],
        required: [true, "The reponse type is required."],
      },
      codeChallenge: {
        type: Schema.Types.String,
      },
      codeChallengeMethod: {
        type: Schema.Types.String,
        enum: ["plain", "S256"],
      },
      redirectUri: {
        type: Schema.Types.String,
        required: [true, "The redirect uri is required."],
        validate: [
          {
            validator: (value: string) => {
              return validator.isURL(value);
            },
            message: "The redirect uri value must be a valid URL.",
          },
        ],
      },
      userAgent: {
        type: Schema.Types.String,
      },
      revokedAt: {
        type: Schema.Types.Date,
      },
      expiresAt: {
        type: Schema.Types.Date,
        required: [true, "Expires at is required."],
      },
    },
    {
      timestamps: true,
    }
  ),
  externalConfig: function (schema: Schema) {
    /**
     * Before save
     */
    schema.pre<IOauthAuthCode>("save", async function (next: HookNextFunction) {
      /**
       * Verify missing scopes
       */
      await oauthScopeProvider.validateScopesHook(this.scope, next);
    });
  },
});
