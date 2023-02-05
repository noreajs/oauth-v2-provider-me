import IEndUserAuthData from "./IEndUserAuthData";
import { JwtTokenReservedClaimsType } from "./IJwt";
import { RequestHandler } from "express";
import OauthStrategy from "../strategy/OauthStrategy";
import { Algorithm } from "jsonwebtoken";

export type SubLookupFuncType = {
  (sub: string): any | Promise<any>;
};

type ClientPartyType = {
  /**
   * First-party applications: Applications controlled by the same organization
   */
  internal: number;
  /**
   * Third-party applications: external parties or partners
   */
  external: number;
};

export type OauthExpiresInType = {
  /**
   * Clients capable of maintaining the confidentiality of their credentials (e.g., client implemented on a secure server with restricted access to the client credentials), or capable of secure client authentication using other means.
   */
  confidential: ClientPartyType;
  /**
   * Clients incapable of maintaining the confidentiality of their credentials (e.g., clients executing on the device used by the resource owner, such as an installed native application or a web browser-based application), and incapable of secure client authentication via any other means.
   */
  public: ClientPartyType;
};

export interface IOauthContext {
  /**
   * Oauth v2 provider name
   * This name is going to be used as cookie name.
   */
  providerName: string;

  /**
   * Oauth v2 provider secret key
   */
  secretKey: string;

  /**
   * Jwt encrypt algorithm
   */
  jwtAlgorithm?: Algorithm;

  /**
   * Authentification logic
   */
  authenticationLogic: (
    username: string,
    password: string
  ) => Promise<IEndUserAuthData | undefined> | IEndUserAuthData | undefined;

  /**
   * Claims to be included in id_token
   */
  supportedOpenIdStandardClaims: (
    userId: string
  ) =>
    | Promise<JwtTokenReservedClaimsType | undefined>
    | JwtTokenReservedClaimsType
    | undefined;

  /**
   * Lookup the token owner and make his data available in Express response within the locals property.
   *
   * ```typescript
   * response.locals.user
   * ```
   */
  subLookup?: SubLookupFuncType;

  /**
   * Middlewares to be applied to Clients management routes and Scopes management routes
   */
  securityMiddlewares?: RequestHandler[];

  /**
   * Token type will be always Bearer
   * @default Bearer
   */
  tokenType?: "Bearer";

  /**
   * Authorization code lifetime in seconds
   */
  authorizationCodeLifeTime?: number;

  /**
   * Access Token Expiration Times
   */
  accessTokenExpiresIn?: OauthExpiresInType;

  /**
   * Refresh Token Expiration Times
   */
  refreshTokenExpiresIn?: OauthExpiresInType;

  /**
   * Social strategies to integrate other oauth 2 provider, such as facebook, github, twitter etc
   */
  strategies?: Array<OauthStrategy>;

  /**
   * Login page page path (ejs file)
   */
  loginPagePath?: string[];

  /**
   * Cookie variable name to the state or code verifier
   */
  stateCookieVariableName?: string
}
