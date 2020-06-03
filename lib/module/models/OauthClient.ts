import {
  mongooseModel,
  Document,
  Schema,
  HookNextFunction,
} from "@noreajs/mongoose";
import validator from "validator";
import OauthAccessToken, { IOauthAccessToken } from "./OauthAccessToken";
import { Request } from "express";
import moment from "moment";
import OauthHelper from "../helpers/OauthHelper";
import OauthRefreshToken, { IOauthRefreshToken } from "./OauthRefreshToken";
import UtilsHelper from "../helpers/UtilsHelper";
import OauthContext from "../OauthContext";

export type OauthClientType = "confidential" | "public";
export type OauthClientProfileType = "web" | "user-agent-based" | "native";
export type OauthClientGrantType =
  | "implicit"
  | "client_credentials"
  | "password"
  | "authorization_code"
  | "refresh_token";
export type OauthTokenType = {
  token: string;
  accessTokenExpireIn: number;
  refreshToken?: string;
};

export type NewAccessTokenParamsType = {
  req: Request;
  oauthContext: OauthContext;
  grant: OauthClientGrantType;
  scope: string;
  subject: string;
};

export interface IOauthClient extends Document {
  clientId: string;
  name: string;
  domaine?: string;
  logo?: string;
  description?: string;
  legalTermsAcceptedAt?: Date;
  secretKey?: string;
  internal: boolean;
  grants: OauthClientGrantType[];
  redirectURIs: string[];
  clientType: OauthClientType;
  clientProfile: OauthClientProfileType;
  programmingLanguage: string;
  scope: string;
  revokedAt?: Date;
  validateScope: (scope: String) => boolean;
  accessTokenExpiresIn: (oauthContext: OauthContext) => number;
  refreshTokenExpiresIn: (oauthContext: OauthContext) => number;
  newAccessToken: (params: NewAccessTokenParamsType) => Promise<OauthTokenType>;
  mergedScope: (
    subjectScope: string,
    requestScope?: string
  ) => string;
}

export default mongooseModel<IOauthClient>({
  name: "OauthClient",
  collection: "oauth_clients",
  schema: new Schema<IOauthClient>(
    {
      clientId: {
        type: Schema.Types.String,
        unique: true,
      },
      name: {
        type: Schema.Types.String,
        unique: true,
        required: [true, "The name is required"],
      },
      domaine: {
        type: Schema.Types.String,
        unique: true,
        validate: [
          {
            validator: (value: string) => {
              return !value || validator.isURL(value);
            },
            message: "The domaine value must be a valid URL.",
          },
          {
            validator: function (value: string) {
              const self = this as IOauthClient;
              const cond =
                (value === null || value === undefined || value.length === 0) &&
                ["web", "user-agent-based"].includes(self.clientProfile);
              return !cond;
            },
            message:
              "The domaine is required web and user agent based application.",
          },
        ],
      },
      logo: {
        type: Schema.Types.String,
        validate: [
          {
            validator: (value: string) => {
              return !value || validator.isURL(value);
            },
            message: "The log value must be a valid URL.",
          },
        ],
      },
      programmingLanguage: {
        type: Schema.Types.String,
      },
      description: {
        type: Schema.Types.String,
      },
      legalTermsAcceptedAt: {
        type: Schema.Types.Date,
      },
      secretKey: {
        type: Schema.Types.String,
      },
      internal: {
        type: Schema.Types.Boolean,
        required: [true, "The internal"],
      },
      grants: [Schema.Types.String],
      redirectURIs: [Schema.Types.String],
      clientType: {
        type: Schema.Types.String,
        enum: ["confidential", "public"],
        default: "public",
      },
      clientProfile: {
        type: Schema.Types.String,
        enum: ["web", "user-agent-based", "native"],
        required: [true, "The client profile is required."],
      },
      scope: {
        type: Schema.Types.String,
        required: [true, "The scope is required."],
        validate: [
          {
            validator: function (value: string) {
              const self = this as IOauthClient;
              return !(!self.internal && value === "*");
            },
            message: "* is not allowed as scope value for external client.",
          },
        ],
      },
      revokedAt: {
        type: Schema.Types.Date,
      },
    },
    {
      timestamps: true,
    }
  ),
  methods: {
    validateScope: function (scope: String): boolean {
      if (this.scope !== "*") {
        if (scope === "*") {
          return false;
        } else if (!scope) {
          return true;
        } else {
          const clientScopes = this.scope.split(" ");
          const scopes = scope.split(" ");
          for (const item of scopes) {
            if (!clientScopes.includes(item)) {
              return false;
            }
          }
          return true;
        }
      } else {
        return true;
      }
    },
    accessTokenExpiresIn: function (oauthContext: OauthContext): number {
      switch (this.clientType) {
        case "public":
          if (this.internal) {
            return oauthContext.accessTokenExpiresIn.public.internal;
          } else {
            return oauthContext.accessTokenExpiresIn.public.external;
          }
        case "confidential":
          if (this.internal) {
            return oauthContext.accessTokenExpiresIn.confidential.internal;
          } else {
            return oauthContext.accessTokenExpiresIn.confidential.external;
          }
      }
      return oauthContext.accessTokenExpiresIn.public.external;
    },
    refreshTokenExpiresIn: function (oauthContext: OauthContext): number {
      switch (this.clientType) {
        case "public":
          if (this.internal) {
            return oauthContext.refreshTokenExpiresIn.public.internal;
          } else {
            return oauthContext.refreshTokenExpiresIn.public.external;
          }
        case "confidential":
          if (this.internal) {
            return oauthContext.refreshTokenExpiresIn.confidential.internal;
          } else {
            return oauthContext.refreshTokenExpiresIn.confidential.external;
          }
      }
      return oauthContext.refreshTokenExpiresIn.public.external;
    },
    newAccessToken: async function (
      params: NewAccessTokenParamsType
    ): Promise<OauthTokenType> {
      /**
       * Check client grants
       * *********************************
       */
      if (this.grants.includes(params.grant)) {
        /**
         * Access token expires in
         */
        const accessTokenExpiresIn = this.accessTokenExpiresIn(
          params.oauthContext
        );

        /**
         * Save access token data
         */
        const oauthAccessToken = await new OauthAccessToken({
          userId: params.subject,
          grant: params.grant,
          client: this._id,
          name: this.name,
          scope: params.scope,
          expiresAt: moment().add(accessTokenExpiresIn, "seconds").toDate(),
          userAgent: params.req.headers["user-agent"],
        } as Partial<IOauthAccessToken>).save();

        // return object
        const r: OauthTokenType = {
          token: OauthHelper.jwtSign(params.req, params.oauthContext, {
            client_id: this.clientId,
            scope: params.scope,
            azp: this.domaine ?? this.clientId,
            aud: this.domaine ?? this.clientId,
            sub: params.subject,
            jti: oauthAccessToken._id.toString(),
            exp: oauthAccessToken.expiresAt.getTime(),
          }),
          accessTokenExpireIn: accessTokenExpiresIn,
          refreshToken: undefined,
        };

        /**
         * REFRESH TOKEN
         *
         * Not allowed for client_credentials grant and implicit grant
         * Only allowed for client with "refresh_token" in grants list
         * ********************************************************************
         */
        if (
          !([
            "client_credentials",
            "implicit",
          ] as OauthClientGrantType[]).includes(params.grant) &&
          this.clientType === "confidential"
        ) {
          /**
           * Create and save refresh token data
           * *********************************************
           */
          const oauthRefreshToken = await new OauthRefreshToken({
            accessToken: oauthAccessToken._id,
            expiresAt: moment()
              .add(this.refreshTokenExpiresIn(params.oauthContext), "seconds")
              .toDate(),
          } as Partial<IOauthRefreshToken>).save();

          /**
           * Refresh token
           * **********************
           */
          r.refreshToken = OauthHelper.jwtSign(
            params.req,
            params.oauthContext,
            {
              client_id: this.clientId,
              azp: this.domaine ?? this.clientId,
              aud: this.domaine ?? this.clientId,
              sub: params.subject,
              jti: oauthRefreshToken._id.toString(),
              exp: oauthRefreshToken.expiresAt.getTime(),
            }
          );
        }

        /**
         * Return the token
         */
        return r;
      } else {
        throw {
          message: `${params.grant} authorization grant type is not allowed for this client.`,
        };
      }
    },
    mergedScope: function (
      subjectScope: string,
      requestScope?: string
    ): string {
      /**
       * Scope exist in token request
       */
      if (requestScope) {
        if (requestScope === "*") {
          return subjectScope;
        } else if (subjectScope === "*") {
          return requestScope;
        } else {
          return UtilsHelper.getMatchedScope(subjectScope, requestScope);
        }
      } else {
        /**
         * Scope does not exist in token request
         */
        if (this.scope === "*") {
          return subjectScope;
        } else if (subjectScope === "*") {
          return this.scope;
        } else {
          return UtilsHelper.getMatchedScope(subjectScope, this.scope);
        }
      }
    },
  },
  externalConfig: function (sc) {
    /**
     * Before save
     * ******************************
     */
    sc.pre<IOauthClient>("save", function (next: HookNextFunction) {
      /**
       * Secret code availability
       * **********************
       */
      if (this.clientProfile === "web") {
        this.clientType = "confidential";
      } else {
        this.clientType = "public";
        this.secretKey = undefined;
      }

      /**
       * Client grants
       * *******************
       */
      switch (this.clientType) {
        case "public":
          if (this.internal) {
            this.grants = ["implicit", "authorization_code", "password"];
          } else {
            this.grants = ["implicit", "authorization_code"];
          }
          break;
        case "confidential":
          if (this.internal) {
            this.grants = [
              "implicit",
              "authorization_code",
              "password",
              "client_credentials",
            ];
          } else {
            this.grants = ["implicit", "authorization_code"];
          }
          break;
      }

      /**
       * Validate redirect URIs
       * ************************
       */
      let invalidUriFound = false;
      for (const uri of this.redirectURIs) {
        if (!validator.isURL(uri)) {
          invalidUriFound = true;
          break;
        }
      }
      if (invalidUriFound) {
        next({
          name: "Redirect URIs validation fail",
          message: "The redirect URIs value must be valid URLs.",
        });
      }

      /**
       * Default scope for internal clients
       * **************************************
       */
      if (this.internal && !this.scope) {
        this.scope = "*";
      }

      /**
       * Save the client
       */
      next();
    });
  },
});
