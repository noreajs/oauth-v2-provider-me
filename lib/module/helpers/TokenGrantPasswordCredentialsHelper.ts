import { Obj } from "@noreajs/common";
import { Request, Response } from "express";
import IToken from "../interfaces/IToken";
import ITokenRequest from "../interfaces/ITokenRequest";
import { IOauthClient } from "../models/OauthClient";
import OauthContext from "../OauthContext";
import HttpStatus from "./HttpStatus";
import OauthHelper from "./OauthHelper";
import UrlHelper from "./UrlHelper";

class TokenGrantPasswordCredentialsHelper {
  /**
   * Resource Owner Password Credentials
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
       * Password grant is allowed
       */
      if (client.grants.includes("password")) {
        /**
         * Required parameters
         * *********************************
         */
        const requiredParameters = Obj.missingKeys<ITokenRequest>(
          ["username", "password"],
          data
        );

        if (requiredParameters.length != 0) {
          return OauthHelper.throwError(req, res, {
            error: "invalid_request",
            error_description: `${requiredParameters.join(", ")} ${
              requiredParameters.length > 1 ? "are required" : "is required"
            }`,
          });
        }

        /**
         * Password Grant authentification data
         */
        const endUserAuthData = await oauthContext.authenticationLogic(
          data.username,
          data.password
        );

        if (!endUserAuthData) {
          return OauthHelper.throwError(req, res, {
            error: "invalid_grant",
            error_description: `Given credentials are not valid or do not match any record.`,
          });
        }

        /**
         * Check scopes
         * ****************
         */
        const mergedScope = client.mergedScope(
          endUserAuthData.scope,
          data.scope
        );
        if (!mergedScope) {
          return OauthHelper.throwError(req, res, {
            error: "invalid_scope",
            error_description: "The request scope must be in client scope.",
          });
        }

        /**
         * Generate tokens
         * ******************************
         */
        const tokens = await client.newAccessToken({
          req: {
            host: UrlHelper.getFullUrl(req),
            userAgent: req.headers["user-agent"],
          },
          oauthContext: oauthContext,
          grant: "password",
          scope: mergedScope,
          subject: endUserAuthData.userId,
        });

        return res.status(HttpStatus.Ok).json({
          access_token: tokens.token,
          token_type: oauthContext.tokenType,
          expires_in: tokens.accessTokenExpireIn,
          refresh_token: tokens.refreshToken,
          data: endUserAuthData.extraData,
        } as IToken);
      } else {
        return OauthHelper.throwError(req, res, {
          error: "unauthorized_client",
          error_description:
            "Password Credentials grant type is not allowed for this client.",
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

export default TokenGrantPasswordCredentialsHelper;
