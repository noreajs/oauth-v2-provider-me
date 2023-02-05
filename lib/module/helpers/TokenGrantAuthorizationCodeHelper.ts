import crypto from "crypto";
import { Request, Response } from "express";
import moment from "moment";
import { toASCII } from "punycode";
import IToken from "../interfaces/IToken";
import ITokenRequest from "../interfaces/ITokenRequest";
import OauthAuthCode, { IOauthAuthCode } from "../models/OauthAuthCode";
import { IOauthClient } from "../models/OauthClient";
import OauthContext from "../OauthContext";
import HttpStatus from "./HttpStatus";
import OauthHelper from "./OauthHelper";

class TokenGrantAuthorizationCodeHelper {
  /**
   * Get Authorization Code Grant
   *
   * @param req request
   * @param res response
   * @param data token request data
   * @param client oauth client
   * @param oauthContext oauth params
   */
  static async run(
    req: Request,
    res: Response,
    data: ITokenRequest,
    client: IOauthClient,
    oauthContext: OauthContext
  ) {
    try {
      /**
       * AUTHORIZATION CODE VALIDATION
       * *********************************
       */

      // load authoriation token
      const oauthCode = await OauthAuthCode.findOne<IOauthAuthCode>({
        client: client._id,
        authorizationCode: data.code,
      });

      if (oauthCode) {
        if (moment().isAfter(oauthCode.expiresAt)) {
          return OauthHelper.throwError(req, res, {
            error: "invalid_grant",
            error_description:
              "The authorization code has been expired. Try to get another one.",
          });
        } else if (oauthCode.revokedAt) {
          return OauthHelper.throwError(req, res, {
            error: "invalid_grant",
            error_description:
              "The authorization code has been revoked. Try to get another one.",
          });
        } else {
          /**
           * Redirect URI must match
           */
          if (oauthCode.redirectUri !== data.redirect_uri) {
            return OauthHelper.throwError(req, res, {
              error: "invalid_grant",
              error_description: `The redirect_uri parameter must be identical to the one included in the authorization request.`,
            });
          }

          const codeChallenge = req.cookies?.[oauthContext.codeChallengeCookieVariableName]

          /**
           * Code verifier check
           */
          if (codeChallenge) {
            if (!data.code_verifier) {
              return OauthHelper.throwError(req, res, {
                error: "invalid_request",
                error_description: `The "code_verifier" is required.`,
              });
            } else {
              switch (oauthCode.codeChallengeMethod) {
                case "plain":
                  if (data.code_verifier !== codeChallenge) {
                    return OauthHelper.throwError(req, res, {
                      error: "invalid_grant",
                      error_description: `Code verifier and code challenge are not identical.`,
                    });
                  }
                  break;
                case "S256":
                  // code here
                  const hashed = crypto
                    .createHash("sha256")
                    .update(toASCII(data.code_verifier))
                    .digest("base64")
                    .replace(/=/g, "")
                    .replace(/\+/g, "-")
                    .replace(/\//g, "_");

                  if (hashed !== codeChallenge) {
                    return OauthHelper.throwError(req, res, {
                      error: "invalid_grant",
                      error_description: `Hashed code verifier and code challenge are not identical.`,
                    });
                  }

                  break;
              }
            }
          }

          /**
           * Generate tokens
           * ******************************
           */
          const tokens = await client.newAccessToken({
            req: {
              host: req.hostname,
              userAgent: req.headers['user-agent']
            },
            oauthContext: oauthContext,
            grant: "authorization_code",
            scope: oauthCode.scope,
            subject: oauthCode.userId,
          });

          return res.status(HttpStatus.Ok).json({
            access_token: tokens.token,
            token_type: oauthContext.tokenType,
            expires_in: tokens.accessTokenExpireIn,
            refresh_token: tokens.refreshToken,
          } as IToken);
        }
      } else {
        return OauthHelper.throwError(req, res, {
          error: "invalid_grant",
          error_description: `The authorization code is not valid.`,
        });
      }
    } catch (error) {
      return OauthHelper.throwError(req, res, {
        error: "server_error",
        error_description:
          "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
        extra: error,
      });
    }
  }
}

export default TokenGrantAuthorizationCodeHelper;
