import OauthClient, { TokenResponse } from "oauth-v2-client";
import { IEndUserAuthData } from "../..";
import OauthStrategyGrantType from "./OauthStrategyGrantType";

export type UserLookupFunc<T = TokenResponse> = (
  client: OauthClient,
  token: T
) => Promise<IEndUserAuthData | undefined> | IEndUserAuthData | undefined;

type OauthStrategyOptionsType<TokenType = TokenResponse> = {
  identifier: string;
  providerName?: string;
  grant: OauthStrategyGrantType;
  client: OauthClient;
  userLookup: UserLookupFunc<TokenType>;
};

export default OauthStrategyOptionsType;
