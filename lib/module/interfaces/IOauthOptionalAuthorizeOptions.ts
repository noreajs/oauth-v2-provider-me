import { OauthClientGrantType } from "../models/OauthClient";

type IOauthOptionalAuthorizeOptions =
  | string
  | undefined
  | {
      /**
       * Expected scopes
       */
      scope?: string;

      /**
       * Expected token's grant
       */
      grant?:
        | Array<Exclude<OauthClientGrantType, "refresh_token">>
        | Exclude<OauthClientGrantType, "refresh_token">;

      /**
       * Verify if the token type is supported
       * @default false
       */
      tokenTypeCheck?: boolean;
      /**
       * Verify if the token is expired
       * @default false
       */
      tokenExpirationCheck?: boolean;
      /**
       * Bypass token verification error
       * @default true
       */
      bypassTokenVerificationError?: boolean;
    };

export default IOauthOptionalAuthorizeOptions;
