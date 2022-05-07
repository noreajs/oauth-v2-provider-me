import { Request, Response, NextFunction } from "express";
import IAuthCodeRequest from "../interfaces/IAuthCodeRequest";
import OauthClient from "../models/OauthClient";
import OauthHelper from "../helpers/OauthHelper";
import { Obj } from "@noreajs/common";

class AuthorizationMiddleware {
  /**
   * Authorization request validation required
   * @param req request
   * @param res response
   * @param next next function
   */
  async validRequestRequired(req: Request, res: Response, next: NextFunction) {
    // get request query data
    let data: IAuthCodeRequest = req.query as any;

    try {
      /**
       * Required parameters
       */
      const requiredParameters = Obj.missingKeys<IAuthCodeRequest>(
        ["response_type", "redirect_uri", "client_id"],
        data
      );

      if (requiredParameters.length != 0) {
        return OauthHelper.throwError(
          req,
          res,
          {
            error: "invalid_request",
            error_description: `${requiredParameters.join(", ")} ${
              requiredParameters.length > 1 ? "are required" : "is required"
            }`,
            state: data.state,
          },
          data.redirect_uri
        );
      }

      /**
       * Code challenge method validation
       */
      if (
        data.code_challenge_method &&
        !["plain", "S256"].includes(data.code_challenge_method)
      ) {
        return OauthHelper.throwError(
          req,
          res,
          {
            error: "invalid_request",
            error_description: `The code challenge method must be "plain" or "S256"`,
            state: data.state,
          },
          data.redirect_uri
        );
      }

      /**
       * Authentificate client
       * ***************************************
       */
      const client = await OauthClient.findOne({ clientId: data.client_id });

      /**
       * Client exists
       */
      if (!client) {
        return OauthHelper.throwError(
          req,
          res,
          {
            error: "invalid_request",
            error_description: "Unknown client",
            state: data.state,
          },
          data.redirect_uri
        );
      }

      /**
       * Personal client not allowed
       */
      if (client.personal) {
        return OauthHelper.throwError(req, res, {
          error: "unauthorized_client",
          error_description: "Personal client are not allowed",
        });
      }

      // Client revoked
      if (client.revokedAt) {
        return OauthHelper.throwError(
          req,
          res,
          {
            error: "access_denied",
            error_description:
              "The client related to this request has been revoked.",
            state: data.state,
          },
          data.redirect_uri
        );
      }

      if (!client.redirectURIs.includes(data.redirect_uri)) {
        return OauthHelper.throwError(
          req,
          res,
          {
            error: "invalid_request",
            error_description:
              "Given redirect uri is not in the client redirect URIs",
            state: data.state,
          },
          data.redirect_uri
        );
      }

      /**
       * Check scopes
       * ****************
       */
      if (data.scope && !client.validateScope(data.scope)) {
        return OauthHelper.throwError(
          req,
          res,
          {
            error: "invalid_scope",
            error_description: "The request scope must be in client scopes.",
          },
          data.redirect_uri
        );
      }

      /**
       * Response type
       * ***************************
       */
      if (!["code", "token"].includes(data.response_type)) {
        return OauthHelper.throwError(
          req,
          res,
          {
            error: "unsupported_response_type",
            error_description:
              "Expected value for response_type are 'token' and 'code'",
            state: data.state,
          },
          data.redirect_uri
        );
      }

      /**
       * Inject data in request
       */
      res.locals.data = data;
      res.locals.client = client;

      // continue the request
      next();
    } catch (e) {
      return OauthHelper.throwError(
        req,
        res,
        {
          error: "server_error",
          error_description:
            "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
          state: data.state,
          extra: e,
        },
        data.redirect_uri
      );
    }
  }
}

export default new AuthorizationMiddleware();
