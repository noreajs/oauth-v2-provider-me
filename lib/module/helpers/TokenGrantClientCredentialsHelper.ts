import ITokenRequest from "../interfaces/ITokenRequest";
import { IOauthClient } from "../models/OauthClient";
import IToken from "../interfaces/IToken";
import { Request, Response } from "express";
import OauthHelper from "./OauthHelper";
import OauthContext from "../OauthContext";
import HttpStatus from "./HttpStatus";

class TokenGrantClientCredentialsHelper {
  /**
   * Client Credentials Grant
   *
   * @param req express request
   * @param res response
   * @param data token request
   * @param client oauth client
   * @param oauthContext oauth parameters
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
       * Client Credentials Grant Type required
       */
      if (client.grants.includes("client_credentials")) {
        /**
         * Check scopes
         * ****************
         */
        const mergedScope = client.mergedScope(client.scope, data.scope);
        if (!mergedScope) {
          return OauthHelper.throwError(req, res, {
            error: "invalid_scope",
            error_description:
              "The requested scope is invalid, unknown, malformed, or exceeds the scope granted.",
          });
        }

        /**
         * Check client type
         */
        if (client.clientType !== "confidential") {
          return OauthHelper.throwError(req, res, {
            error: "unauthorized_client",
            error_description:
              "The authenticated client is not authorized to use this authorization grant type.",
          });
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
          grant: "client_credentials",
          scope: mergedScope,
          subject: client.clientId,
        });

        return res.status(HttpStatus.Ok).json({
          access_token: tokens.token,
          token_type: oauthContext.tokenType,
          expires_in: tokens.accessTokenExpireIn,
        } as IToken);
      } else {
        return OauthHelper.throwError(req, res, {
          error: "unauthorized_client",
          error_description:
            "Client Credentials grant type is not allowed for this client.",
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

export default TokenGrantClientCredentialsHelper;
