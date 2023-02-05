import {
  OauthExpiresInType,
  IOauthContext,
  SubLookupFuncType,
} from "./interfaces/IOauthContext";
import IEndUserAuthData from "./interfaces/IEndUserAuthData";
import { JwtTokenReservedClaimsType } from "./interfaces/IJwt";
import { RequestHandler } from "express";
import { OauthStrategy } from "..";
import { Algorithm } from "jsonwebtoken";

export default class OauthContext {
  providerName: string;
  secretKey: string;
  jwtAlgorithm: Algorithm;
  authenticationLogic: (
    username: string,
    password: string
  ) => Promise<IEndUserAuthData | undefined> | IEndUserAuthData | undefined;
  supportedOpenIdStandardClaims: (
    userId: string
  ) =>
    | Promise<JwtTokenReservedClaimsType | undefined>
    | JwtTokenReservedClaimsType
    | undefined;
  subLookup?: SubLookupFuncType;
  securityMiddlewares?: RequestHandler[];
  tokenType: "Bearer";
  authorizationCodeLifeTime: number;
  accessTokenExpiresIn: OauthExpiresInType;
  refreshTokenExpiresIn: OauthExpiresInType;
  strategies: Array<OauthStrategy>;
  loginPagePath: string[];
  stateCookieVariableName: string;
  codeChallengeCookieVariableName: string;
  codeVerifierCookieVariableName: string;

  constructor(init: IOauthContext) {
    /**
     * Initialize context
     */
    this.accessTokenExpiresIn = init.accessTokenExpiresIn ?? {
      confidential: {
        internal: 60 * 60 * 24, // 24h
        external: 60 * 60 * 12, // 12h
      },
      public: {
        internal: 60 * 60 * 2, // 2h
        external: 60 * 60, // 1h
      },
    };
    this.authenticationLogic = init.authenticationLogic;
    this.supportedOpenIdStandardClaims = init.supportedOpenIdStandardClaims;
    this.subLookup = init.subLookup;
    this.securityMiddlewares = init.securityMiddlewares;
    this.authorizationCodeLifeTime = init.authorizationCodeLifeTime ?? 60 * 5;
    this.jwtAlgorithm = init.jwtAlgorithm ?? "HS512";
    this.providerName = init.providerName;
    this.refreshTokenExpiresIn = init.refreshTokenExpiresIn ?? {
      confidential: {
        internal: 60 * 60 * 24 * 30 * 12, // 1 year
        external: 60 * 60 * 24 * 30, // 30 days
      },
      public: {
        internal: 60 * 60 * 24 * 30, // 30 days
        external: 60 * 60 * 24 * 7, // 1 week
      },
    };
    this.secretKey = init.secretKey;
    this.tokenType = init.tokenType ?? "Bearer";
    this.strategies = init.strategies ?? [];
    this.loginPagePath = init.loginPagePath ?? [];
    this.stateCookieVariableName = `oauth.v2.provider.state`;
    this.codeChallengeCookieVariableName = `${this.stateCookieVariableName}.code-challenge`
    this.codeVerifierCookieVariableName = `${this.stateCookieVariableName}.code-verifier`
  }
}
