import { Request, Response } from "express";
import OauthHelper from "../helpers/OauthHelper";
import RevokeTokenHelper from "../helpers/RevokeTokenHelper";
import TokenGrantAuthorizationCodeHelper from "../helpers/TokenGrantAuthorizationCodeHelper";
import TokenGrantClientCredentialsHelper from "../helpers/TokenGrantClientCredentialsHelper";
import TokenGrantPasswordCredentialsHelper from "../helpers/TokenGrantPasswordCredentialsHelper";
import TokenGrantRefreshTokenHelper from "../helpers/TokenGrantRefreshTokenHelper";
import ITokenRequest from "../interfaces/ITokenRequest";
import ITokenRevokeRequest from "../interfaces/ITokenRevokeRequest";
import OauthClient, { IOauthClient } from "../models/OauthClient";
import OauthController from "./oauth.controller";

class AccessTokenController extends OauthController {
  /**
   * Generate token
   * @param req request
   * @param res response
   */
  token = async (req: Request, res: Response) => {
    // request data
    let data = req.body as ITokenRequest;

    // get basic auth header credentials
    let basicAuthCredentials = OauthHelper.getBasicAuthHeaderCredentials(req);

    // update credential if exist
    if (basicAuthCredentials) {
      data.client_id = basicAuthCredentials.client_id;
      data.client_secret = basicAuthCredentials.client_secret;
    }

    try {
      if (!data.client_id) {
        return OauthHelper.throwError(req, res, {
          error: "invalid_request",
          error_description:
            "The client_id is required. You can send it with client_secret in body or via Basic Auth header.",
        });
      }

      // load client
      const client = await OauthClient.findOne<IOauthClient>({ clientId: data.client_id });

      /**
       * Client has to exist
       */
      if (!client) {
        return OauthHelper.throwError(req, res, {
          error: "invalid_client",
          error_description: "Unknown client",
        });
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
        return OauthHelper.throwError(req, res, {
          error: "invalid_client",
          error_description:
            "The client related to this request has been revoked.",
        });
      }

      /**
       * Check scopes
       * ****************
       */
      if (data.scope && !client.validateScope(data.scope)) {
        return OauthHelper.throwError(req, res, {
          error: "invalid_scope",
          error_description:
            "The requested scope is invalid, unknown, malformed, or exceeds the scope granted.",
        });
      }

      if (client.clientType === "confidential" && !data.client_secret) {
        return OauthHelper.throwError(req, res, {
          error: "invalid_request",
          error_description:
            "The secret_secret is required for confidential client. You can send it with client_id in body or via Basic Auth header.",
        });
      }

      /**
       * Verify secret code if it exist
       */
      if (
        data.client_secret &&
        data.client_secret.length !== 0 &&
        data.client_secret !== client.secretKey
      ) {
        return OauthHelper.throwError(req, res, {
          error: "invalid_client",
          error_description: "Invalid client secret.",
        });
      }

      switch (data.grant_type) {
        case "authorization_code":
          // Authorization Code Grant
          return TokenGrantAuthorizationCodeHelper.run(
            req,
            res,
            data,
            client,
            this.oauthContext
          );
        case "client_credentials":
          // Client Credentials Grant
          return TokenGrantClientCredentialsHelper.run(
            req,
            res,
            data,
            client,
            this.oauthContext
          );
        case "password":
          // Resource Owner Password Credentials
          return TokenGrantPasswordCredentialsHelper.run(
            req,
            res,
            data,
            client,
            this.oauthContext
          );
        case "refresh_token":
          // Refreshing an Access Token
          return TokenGrantRefreshTokenHelper.run(
            req,
            res,
            data,
            client,
            this.oauthContext
          );
        default:
          return OauthHelper.throwError(req, res, {
            error: "unsupported_grant_type",
            error_description:
              "The authorization grant type is not supported by the authorization server.",
          });
      }
    } catch (e) {
      return OauthHelper.throwError(req, res, {
        error: "server_error",
        error_description:
          "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
        extra: e,
      });
    }
  };

  /**
   * Revoke a token
   * @param req request
   * @param res response
   */
  revoke = async (req: Request, res: Response) => {
    // request data
    let data = req.body as ITokenRevokeRequest;

    // get basic auth header credentials
    let basicAuthCredentials = OauthHelper.getBasicAuthHeaderCredentials(req);

    // update credential if exist
    if (basicAuthCredentials) {
      data.client_id = basicAuthCredentials.client_id;
      data.client_secret = basicAuthCredentials.client_secret;
    }

    try {
      if (!data.client_id) {
        return OauthHelper.throwError(req, res, {
          error: "invalid_request",
          error_description:
            "The client_id is required. You can send it with client_secret in body or via Basic Auth header.",
        });
      }

      // load client
      const client = await OauthClient.findOne({ clientId: data.client_id });

      /**
       * Client has to exist
       */
      if (!client) {
        return OauthHelper.throwError(req, res, {
          error: "invalid_client",
          error_description: "Unknown client",
        });
      }

      // Client revoked
      if (client.revokedAt) {
        return OauthHelper.throwError(req, res, {
          error: "invalid_client",
          error_description:
            "The client related to this request has been revoked.",
        });
      }

      if (client.clientType === "confidential" && !data.client_secret) {
        return OauthHelper.throwError(req, res, {
          error: "invalid_request",
          error_description:
            "The secret_secret is required for confidential client. You can send it with client_id in body or via Basic Auth header.",
        });
      }

      /**
       * Verify secret code if it exist
       */
      if (
        data.client_secret &&
        data.client_secret.length !== 0 &&
        data.client_secret !== client.secretKey
      ) {
        return OauthHelper.throwError(req, res, {
          error: "invalid_client",
          error_description: "Invalid client secret.",
        });
      }

      // Run revoke token helper
      return RevokeTokenHelper.run(req, res, data, this.oauthContext);
    } catch (e) {
      return OauthHelper.throwError(req, res, {
        error: "server_error",
        error_description:
          "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
        extra: e,
      });
    }
  };
}

export default AccessTokenController;
