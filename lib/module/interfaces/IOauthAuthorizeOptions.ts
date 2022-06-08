import { OauthClientGrantType } from "../models/OauthClient";

type IOauthAuthorizeOptions =
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
    };

export default IOauthAuthorizeOptions;
