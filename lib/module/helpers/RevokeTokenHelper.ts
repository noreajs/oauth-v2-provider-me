import ITokenRequest from "../interfaces/ITokenRequest";
import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import { IOauthClient } from "../models/OauthClient";
import { Obj } from "@noreajs/common";
import OauthRefreshToken, {
  IOauthRefreshToken,
} from "../models/OauthRefreshToken";
import moment from "moment";
import OauthHelper from "./OauthHelper";
import { IJwtTokenPayload } from "../interfaces/IJwt";
import OauthContext from "../OauthContext";
import ITokenRevokeRequest from "../interfaces/ITokenRevokeRequest";
import OauthAccessToken, {
  IOauthAccessToken,
} from "../models/OauthAccessToken";
import HttpStatus from "./HttpStatus";

class RevokeTokenHelper {
  /**
   * Get the token type
   * @param params parameters
   */
  static async getTokenType(params: {
    token: string;
    secretKey: string;
    jwtAlgorithm: any;
  }): Promise<"refresh_token" | "access_token" | undefined> {
    // Verify token signature
    const tokenData = jwt.verify(params.token, params.secretKey, {
      algorithms: [params.jwtAlgorithm],
    }) as any;

    if (await OauthAccessToken.findById(tokenData.jti)) {
      return "access_token";
    } else if (await OauthRefreshToken.findById(tokenData.jti)) {
      return "refresh_token";
    } else {
      return undefined;
    }
  }

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
    data: ITokenRevokeRequest,
    oauthContext: OauthContext
  ) {
    try {
      /**
       * REVOKE TOKEN VERIFICATION
       * *******************************
       */

      // Check if token is within the request
      if (Obj.missingKeys<ITokenRevokeRequest>(["token"], data).length !== 0) {
        return OauthHelper.throwError(req, res, {
          error: "invalid_request",
          error_description: `token is required.`,
        });
      }

      /**
       * Revoke access token
       * *******************************
       */
      const revokeAccessToken = async () => {
        try {
          // Verify token signature
          const tokenData = jwt.verify(data.token, oauthContext.secretKey, {
            algorithms: [oauthContext.jwtAlgorithm],
          }) as IJwtTokenPayload;

          // load access token
          const accessToken = await OauthAccessToken.findById(tokenData.jti);

          /**
           * Verify client_id
           * *******************************
           */
          if (data.client_id !== tokenData.client_id) {
            return OauthHelper.throwError(req, res, {
              error: "invalid_grant",
              error_description: `Invalid access token. client_id does not match.`,
            });
          }

          // refresh token doesn't exist
          if (
            accessToken &&
            moment().isBefore(accessToken.expiresAt) &&
            !accessToken.revokedAt
          ) {
            /**
             * Revocation of the refresh token
             */
            await OauthAccessToken.updateOne(
              {
                _id: accessToken._id,
              },
              {
                revokedAt: new Date(),
              } as Partial<IOauthAccessToken>
            );
          }
        } catch (error) {
          // no error response needed
        }
      };

      /**
       * Revoke refresh token
       * *******************************
       */
      const revokeRefreshToken = async () => {
        try {
          // Verify token signature
          const tokenData = jwt.verify(data.token, oauthContext.secretKey, {
            algorithms: [oauthContext.jwtAlgorithm],
          }) as IJwtTokenPayload;

          // load refresh token
          const oauthRefreshToken = await OauthRefreshToken.findOne({
            _id: tokenData.jti,
          });

          /**
           * Verify client_id
           * *******************************
           */
          if (data.client_id !== tokenData.client_id) {
            return OauthHelper.throwError(req, res, {
              error: "invalid_grant",
              error_description: `Invalid refresh token. client_id does not match.`,
            });
          }

          // refresh token doesn't exist
          if (
            oauthRefreshToken &&
            moment().isBefore(oauthRefreshToken.expiresAt) &&
            !oauthRefreshToken.revokedAt
          ) {
            /**
             * Revocation of the refresh token
             */
            await OauthRefreshToken.updateOne(
              {
                _id: oauthRefreshToken._id,
              },
              {
                revokedAt: new Date(),
              } as Partial<IOauthRefreshToken>
            );
          }
        } catch (error) {
          // no error response needed
        }
      };

      // token type
      const tokenTypeHint =
        data.token_type_hint ??
        (await RevokeTokenHelper.getTokenType({
          token: data.token,
          jwtAlgorithm: oauthContext.jwtAlgorithm,
          secretKey: oauthContext.secretKey,
        }));

      /**
       * Token type provided
       */
      if (tokenTypeHint) {
        if (["access_token", "refresh_token"].includes(tokenTypeHint)) {
          switch (tokenTypeHint) {
            case "access_token":
              await revokeAccessToken();
              break;
            case "refresh_token":
              await revokeRefreshToken();
            default:
              break;
          }
        } else {
          return OauthHelper.throwError(req, res, {
            error: "unsupported_token_type",
            error_description:
              "The authorization server does not support the revocation of the presented token type.",
          });
        }
      }

      return res.status(HttpStatus.Ok).send();
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

export default RevokeTokenHelper;
