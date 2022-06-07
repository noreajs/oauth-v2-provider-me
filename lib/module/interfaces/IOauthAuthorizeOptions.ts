import { OauthClientGrantType } from "../models/OauthClient";

type IOauthAuthorizeOptions =
  | string
  | undefined
  | {
      scope?: string;
      grant?:
        | Array<Exclude<OauthClientGrantType, "refresh_token">>
        | Exclude<OauthClientGrantType, "refresh_token">;
    };

export default IOauthAuthorizeOptions;
