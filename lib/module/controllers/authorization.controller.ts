import { Obj } from "@noreajs/common";
import { serialize } from "cookie";
import { Request, Response } from "express";
import moment from "moment";
import path from "path";
import { serializeError } from "serialize-error";
import AuthorizationHelper from "../helpers/AuthorizationHelper";
import HttpStatus from "../helpers/HttpStatus";
import OauthHelper from "../helpers/OauthHelper";
import UrlHelper from "../helpers/UrlHelper";
import IAuthCodeRequest from "../interfaces/IAuthCodeRequest";
import ISessionCurrentData from "../interfaces/ISessionCurrentData";
import OauthAuthCode, { IOauthAuthCode } from "../models/OauthAuthCode";
import { IOauthClient } from "../models/OauthClient";
import OauthStrategy from "../strategy/OauthStrategy";
import OauthController from "./oauth.controller";

class AuthorizationController extends OauthController {
  static OAUTH_DIALOG_PATH = "oauth/v2/dialog";
  static OAUTH_AUTHORIZE_PATH = "oauth/v2/authorize";
  static OAUTH_AUTHORIZE_SUBMIT_PATH = "oauth/v2/authorize-submit";
  static OAUTH_STRATEGY_PATH = "oauth/v2/strategy/:identifier";

  /**
   * Get authorization token
   * @param req request
   * @param res response
   */
  authorize = async (req: Request, res: Response) => {
    // get request query data
    const data = res.locals.data as IAuthCodeRequest;
    // get client
    const client = res.locals.client as IOauthClient;

    try {
      /**
       * Response type
       * *****************************
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

      // create oauth code
      const oauthCode = new OauthAuthCode({
        client: client._id,
        state: data.state,
        scope: data.scope,
        responseType: data.response_type,
        codeChallengeMethod: data.code_challenge_method,
        redirectUri: data.redirect_uri,
        expiresAt: moment()
          .add(this.oauthContext.authorizationCodeLifeTime, "seconds")
          .toDate(),
      } as Partial<IOauthAuthCode>);

      // save codes
      await oauthCode.save();

      // session exists
      if (req.session) {
        // clear session
        (req.session as any).oauthAuthCodeId = oauthCode._id;

        /**
         * Strategy shortcut
         * ------------------------
         */
        if (req.query.strategy && `${req.query.strategy}`.length !== 0) {
          const stateCookieStr = data.state ? serialize(this.oauthContext.stateCookieVariableName, data.state, {
            path: '/',
            sameSite: 'lax',
            priority: 'high',
            maxAge: 60
          }) : undefined

          const codeChallengeCookieStr = data.code_challenge ? serialize(this.oauthContext.codeChallengeCookieVariableName, data.code_challenge, {
            path: '/',
            sameSite: 'lax',
            priority: 'high',
            maxAge: 60
          }) : undefined

          if (stateCookieStr)
            res.setHeader('Set-Cookie', stateCookieStr)

          if (codeChallengeCookieStr)
            res.setHeader('Set-Cookie', codeChallengeCookieStr)

          return res.redirect(
            HttpStatus.TemporaryRedirect,
            `${UrlHelper.getFullUrl(req)}/${AuthorizationController.OAUTH_STRATEGY_PATH
              }`.replace(":identifier", req.query.strategy as string)
          );
        } else {
          // current user
          const currentData: ISessionCurrentData = (req.session as any)
            .currentData;

          if (currentData) {
            // redirect authorization code
            return await AuthorizationHelper.run({
              req,
              res,
              oauthContext: this.oauthContext,
              oauthCodeId: oauthCode._id,
              sessionCurrentData: currentData,
              state: data.state
            });
          } else {

            const stateCookieStr = data.state ? serialize(this.oauthContext.stateCookieVariableName, data.state, {
              path: '/',
              sameSite: 'lax',
              priority: 'high',
              maxAge: 60
            }) : undefined

            const codeChallengeCookieStr = data.code_challenge ? serialize(this.oauthContext.codeChallengeCookieVariableName, data.code_challenge, {
              path: '/',
              sameSite: 'lax',
              priority: 'high',
              maxAge: 60
            }) : undefined

            if (stateCookieStr)
              res.setHeader('Set-Cookie', stateCookieStr)

            if (codeChallengeCookieStr)
              res.setHeader('Set-Cookie', codeChallengeCookieStr)

            return res.redirect(
              HttpStatus.TemporaryRedirect,
              `${UrlHelper.getFullUrl(req)}/${AuthorizationController.OAUTH_DIALOG_PATH
              }`
            );
          }
        }
      } else {
        throw Error("No session defined. Express session required.");
      }
    } catch (e) {
      return OauthHelper.throwError(req, res, {
        error: "server_error",
        error_description:
          "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
        state: data.state,
        extra: serializeError(e),
      });
    }
  };

  /**
 * Get authorization dialog
 * @param req request
 * @param res response
 */
  dialog = async (req: Request, res: Response) => {
    // login path
    const authLoginPath =
      this.oauthContext.loginPagePath.length !== 0
        ? path.join(...this.oauthContext.loginPagePath)
        : path.join(...[__dirname, "..", "views", "login", "login.ejs"]);

    if (req.session) {
      const payload: {
        oauthAuthCodeId: string;
        order?: "cancel";
        inputs?: {
          [key: string]: string;
        };
        error?: {
          message: string;
          errors: {
            [key: string]: string;
          };
        };
      } = {
        oauthAuthCodeId: (req.session as any).oauthAuthCodeId,
        error: (req.session as any).error,
        inputs: (req.session as any).inputs,
        order: req.query.order as any,
      };

      // load auth code
      const oauthCode = await OauthAuthCode.findById<IOauthAuthCode>(payload.oauthAuthCodeId);

      // load scopes
      if (oauthCode) {
        /**
         * Authentification cancelled
         * ******************************
         */
        if (payload.order === "cancel") {
          // clear error
          (req.session as any).error = undefined;

          return OauthHelper.throwError(
            req,
            res,
            {
              error: "access_denied",
              error_description: "The resource owner denied the request.",
              state: req.cookies?.[this.oauthContext.stateCookieVariableName],
            },
            oauthCode.redirectUri
          );
        } else {
          /**
           * Render login page
           */
          return res.render(authLoginPath, {
            csrfToken: req.csrfToken(),
            providerName: this.oauthContext.providerName,
            currentYear: new Date().getFullYear(),
            formAction: `${UrlHelper.getFullUrl(req)}/${AuthorizationController.OAUTH_AUTHORIZE_SUBMIT_PATH
              }`,
            cancelUrl: `${UrlHelper.getFullUrl(req)}/${AuthorizationController.OAUTH_DIALOG_PATH
              }?order=cancel`,
            error: payload.error,
            inputs: payload.inputs ?? {
              username: "",
              password: "",
            },
            client: {
              name: oauthCode.client.name,
              domaine: oauthCode.client.domaine,
              logo: oauthCode.client.logo,
              description: oauthCode.client.description,
              internal: oauthCode.client.internal,
              clientType: oauthCode.client.clientType,
              clientProfile: oauthCode.client.clientProfile,
              scope: oauthCode.client.scope,
            } as Partial<IOauthClient>,
            strategies: OauthStrategy.renderOptions((identifier: string) => {
              return `${UrlHelper.getFullUrl(req)}/${AuthorizationController.OAUTH_STRATEGY_PATH
                }`.replace(":identifier", identifier);
            }, this.oauthContext.strategies),
          });
        }
      } else {
        return OauthHelper.throwError(req, res, {
          error: "server_error",
          error_description: "Authorization code instance not found.",
        });
      }
    } else {
      // no session
      return OauthHelper.throwError(req, res, {
        error: "server_error",
        error_description:
          "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
        extra: {
          message: "Express session is missing",
        },
      });
    }
  };

  /**
   * Authentification of an end-user from dialog view
   * ------------------------
   * Handle oauth dialog form submission
   */
  authenticate = async (req: Request, res: Response) => {
    // Form data
    const formData = req.query as {
      username: string;
      password: string;
    };

    /**
     * load auth code
     * *****************************************
     */
    const oauthCode = await OauthAuthCode.findById<IOauthAuthCode>(
      (req.session as any)?.oauthAuthCodeId
    );

    if (oauthCode) {
      try {
        // checking required field
        const requiredFields = Obj.missingKeys<any>(
          ["username", "password"],
          formData
        );

        if (requiredFields.length !== 0) {
          // set session
          if (req.session) {
            (req.session as any).error = {
              message: `${requiredFields.join(", ")} ${requiredFields.length > 1 ? "are" : "is"
                } required.`,
            };
            (req.session as any).inputs = formData;
          } else {
            throw Error("No session defined. Express session required.");
          }

          return res.redirect(
            HttpStatus.MovedPermanently,
            `${UrlHelper.getFullUrl(req)}/${AuthorizationController.OAUTH_DIALOG_PATH
            }`
          );
        }

        const endUserData = await this.oauthContext.authenticationLogic(
          formData.username,
          formData.password
        );

        if (!endUserData) {
          // set session
          if (req.session) {
            (req.session as any).error = {
              message: `Given credentials are not valid or do not match any record.`,
            };
            (req.session as any).inputs = formData;
          } else {
            throw Error("No session defined. Express session required.");
          }

          return res.redirect(
            HttpStatus.MovedPermanently,
            `${UrlHelper.getFullUrl(req)}/${AuthorizationController.OAUTH_DIALOG_PATH
            }`
          );
        }

        /**
         * Refresh session for next use, Save current user data
         * **********************************************
         */
        req.session?.regenerate(function (err: any) {
          if (err) {
            throw Error("Failed to regenerate session.");
          } else {
            const currentData: ISessionCurrentData = {
              responseType: oauthCode.responseType,
              authData: endUserData,
            };

            if (req.session) {
              (req.session as any).currentData = currentData;
            } else {
              throw Error("Unable to access to session");
            }
          }
        });

        return await AuthorizationHelper.run(
          {
            req,
            res,
            oauthContext: this.oauthContext,
            oauthCodeId: oauthCode._id,
            sessionCurrentData: {
              responseType: oauthCode.responseType,
              authData: endUserData,
            },
            state: req.cookies?.[this.oauthContext.stateCookieVariableName]
          }
        );
      } catch (e) {
        return OauthHelper.throwError(req, res, {
          error: "server_error",
          error_description:
            "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
          state: req.cookies?.[this.oauthContext.stateCookieVariableName],
          extra: e,
        });
      }
    } else {
      return OauthHelper.throwError(req, res, {
        error: "access_denied",
        error_description: "Request denied. Data is corrupt.",
      });
    }
  };
}

export default AuthorizationController;
