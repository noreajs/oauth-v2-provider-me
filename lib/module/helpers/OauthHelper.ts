import { Request, Response } from "express";
import { sign } from "jsonwebtoken";
import UrlHelper from "./UrlHelper";
import { Obj } from "@noreajs/common";
import IOauthError from "../interfaces/IOauthError";
import { IJwtTokenPayload } from "../interfaces/IJwt";
import OauthContext from "../OauthContext";
import HttpStatus from "./HttpStatus";

class OauthHelper {
  /**
   * Get authentification scheme
   * @param req request
   */
  getAuthenticationScheme(req: Request) {
    const authorization =
      req.headers["authorization"] ?? req.headers["proxy-authorization"];
    if (authorization) {
      return authorization.split(" ")[0];
    } else {
      return undefined;
    }
  }

  /**
   * Get authentification header
   * @param req request
   */
  getAuthenticationHeader(req: Request) {
    if (req.headers["authorization"]) {
      return "WWW-authenticate";
    } else if (req.headers["proxy-authorization"]) {
      return "proxy-authenticate";
    } else {
      return undefined;
    }
  }

  /**
   * Get basic authentification header
   * @param request request
   */
  getBasicAuthHeaderCredentials(
    request: Request
  ):
    | {
        client_id: string;
        client_secret: string;
      }
    | undefined {
    const authorization =
      request.headers["authorization"] ??
      request.headers["proxy-authorization"];
    if (!authorization || !authorization.startsWith("Basic")) {
      return undefined;
    } else {
      const base64Key = authorization.replace("Basic ", "");
      const credentials = Buffer.from(base64Key, "base64")
        .toString()
        .split(":");
      return {
        client_id: credentials[0],
        client_secret: credentials[1],
      };
    }
  }

  jwtSign(req: Request, oauthContext: OauthContext, claims: IJwtTokenPayload) {
    return sign(claims, oauthContext.secretKey, {
      algorithm: oauthContext.jwtAlgorithm,
      issuer: UrlHelper.getFullUrl(req),
    });
  }

  throwError(
    req: Request,
    res: Response,
    error: IOauthError,
    redirectUri?: string
  ) {
    // 400 Bad Request status by default
    let status: number = HttpStatus.BadRequest;
    // authentification scheme
    const authentificationScheme = this.getAuthenticationScheme(req);
    const authentificationHeader = this.getAuthenticationHeader(req);

    // special status
    switch (error.error) {
      case "invalid_client":
        status = HttpStatus.Unauthorized;

        if (authentificationScheme && authentificationHeader) {
          const parts: string[] = [];
          // realm
          parts.push(`realm="${UrlHelper.getFullUrl(req)}"`);
          // scope
          if (error.scope) {
            parts.push(`scope="${error.scope}"`);
          }
          // error
          parts.push(`error="${error.error}"`);
          // error_description
          if (error.error_description) {
            parts.push(`error_description="${error.error_description}"`);
          }
          // error_uri
          if (error.error_uri) {
            parts.push(`error_uri="${error.error_uri}"`);
          }
          // state
          if (error.state) {
            parts.push(`state="${error.state}"`);
          }

          // set authentification header
          res.setHeader(
            authentificationHeader,
            `${authentificationScheme} ${parts.join(", ")}`
          );
        }
        break;
    }

    /**
     * Redirect if needed
     */
    if (redirectUri) {
      return res.redirect(
        UrlHelper.injectQueryParams(redirectUri, Obj.cleanWithEmpty(error))
      );
    } else {
      return res.status(status).json(Obj.cleanWithEmpty(error));
    }
  }
}

export default new OauthHelper();
