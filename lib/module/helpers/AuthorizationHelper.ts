import { suid } from "rand-token";
import OauthAuthCode, { IOauthAuthCode } from "../models/OauthAuthCode";
import { Response, Request } from "express";
import ISessionCurrentData from "../interfaces/ISessionCurrentData";
import IAuthorizationResponse from "../interfaces/IAuthorizationResponse";
import UrlHelper from "./UrlHelper";
import OauthHelper from "./OauthHelper";
import IToken from "../interfaces/IToken";
import OauthContext from "../OauthContext";
import HttpStatus from "./HttpStatus";

class AuthorizationHelper {
  static run = async function (
    req: Request,
    res: Response,
    oauthContext: OauthContext,
    oauthCode: IOauthAuthCode,
    sessionCurrentData: ISessionCurrentData
  ) {
    /**
     * Check scopes
     * ****************
     */
    const mergedScope = oauthCode.client.mergedScope(
      sessionCurrentData.authData.scope,
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
          userId: sessionCurrentData.authData.userId,
          authorizationCode: authorizationCode,
        } as Partial<IOauthAuthCode>
      );

      const codeResponse = {
        code: authorizationCode,
        state: oauthCode.state ?? "",
      } as IAuthorizationResponse;

      return res.redirect(
        HttpStatus.MovedPermanently,
        UrlHelper.injectQueryParams(oauthCode.redirectUri, codeResponse)
      );
    } else if (oauthCode.responseType === "token") {
      /**
       * Implicit Grant
       */
      const tokens = await oauthCode.client.newAccessToken({
        grant: "implicit",
        oauthContext: oauthContext,
        req: req,
        scope: mergedScope,
        subject: sessionCurrentData.authData.userId,
      });

      const authResponse = {
        access_token: tokens.token,
        token_type: oauthContext.tokenType,
        expires_in: tokens.accessTokenExpireIn,
        state: oauthCode.state ?? "",
      } as IToken;

      return res.redirect(
        HttpStatus.TemporaryRedirect,
        UrlHelper.injectQueryParams(oauthCode.redirectUri, authResponse)
      );
    } else {
      /**
       * Unsupported response type
       */
      return OauthHelper.throwError(
        req,
        res,
        {
          error: "unsupported_response_type",
        },
        oauthCode.redirectUri
      );
    }
  };
}

export default AuthorizationHelper;
