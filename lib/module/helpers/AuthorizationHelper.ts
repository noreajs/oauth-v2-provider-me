import { Obj } from "@noreajs/common";
import { Request, Response } from "express";
import { suid } from "rand-token";
import IAuthorizationResponse from "../interfaces/IAuthorizationResponse";
import ISessionCurrentData from "../interfaces/ISessionCurrentData";
import IToken from "../interfaces/IToken";
import OauthAuthCode, { IOauthAuthCode } from "../models/OauthAuthCode";
import OauthContext from "../OauthContext";
import HttpStatus from "./HttpStatus";
import OauthHelper from "./OauthHelper";
import UrlHelper from "./UrlHelper";

class AuthorizationHelper {
  static run = async function (
    params: {
      req: Request,
      res: Response,
      oauthContext: OauthContext,
      oauthCodeId: any,
      state?: string,
      sessionCurrentData: ISessionCurrentData
    }
  ) {
    /**
     * Load oauth code
     */
    const oauthCode = await OauthAuthCode.findById<IOauthAuthCode>(params.oauthCodeId)

    if (oauthCode) {
      /**
     * Check scopes
     * ****************
     */
      const mergedScope = oauthCode.client.mergedScope(
        params.sessionCurrentData.authData.scope,
        oauthCode.scope
      );

      /**
       * Authorization code
       * *************************
       */
      if (oauthCode.responseType === "code") {
        /**
         * Generate authorization code
         * ***********************************
         */
        const authorizationCode = suid(100);

        /**
         * Update oauth code
         */
        await OauthAuthCode.updateOne(
          {
            _id: oauthCode._id,
          },
          {
            userId: params.sessionCurrentData.authData.userId,
            authorizationCode: authorizationCode,
          } as Partial<IOauthAuthCode>
        );

        const codeResponse = {
          code: authorizationCode,
          state: params.state,
        } as IAuthorizationResponse;

        return params.res.redirect(
          HttpStatus.MovedPermanently,
          UrlHelper.injectQueryParams(oauthCode.redirectUri, Obj.cleanWithEmpty(codeResponse))
        );
      } else if (oauthCode.responseType === "token") {
        /**
         * Implicit Grant
         */
        const tokens = await oauthCode.client.newAccessToken({
          grant: "implicit",
          oauthContext: params.oauthContext,
          req: {
            host: params.req.hostname,
            userAgent: params.req.headers['user-agent']
          },
          scope: mergedScope,
          subject: params.sessionCurrentData.authData.userId,
        });

        const authResponse = {
          access_token: tokens.token,
          token_type: params.oauthContext.tokenType,
          expires_in: tokens.accessTokenExpireIn,
          state: params.state,
        } as IToken;

        return params.res.redirect(
          HttpStatus.TemporaryRedirect,
          UrlHelper.injectQueryParams(oauthCode.redirectUri, Obj.cleanWithEmpty(authResponse))
        );
      } else {
        /**
         * Unsupported response type
         */
        return OauthHelper.throwError(
          params.req,
          params.res,
          {
            error: "unsupported_response_type",
          },
          oauthCode.redirectUri
        );
      }
    } else {
      /**
       * Unsupported response type
       */
      return OauthHelper.throwError(params.req, params.res, {
        error: "server_error",
        error_description:
          "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
        extra: {
          oauthCodeId: params.oauthCodeId,
          message: 'oauth code missing'
        }
      });
    }
  };
}

export default AuthorizationHelper;
