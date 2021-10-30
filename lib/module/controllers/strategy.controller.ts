import { HttpStatus, Obj } from "@noreajs/common";
import { query, Request, Response } from "express";
import { injectQueryParams } from "oauth-v2-client";
import OauthHelper from "../helpers/OauthHelper";
import UrlHelper from "../helpers/UrlHelper";
import ISessionCurrentData from "../interfaces/ISessionCurrentData";
import OauthAuthCode, { IOauthAuthCode } from "../models/OauthAuthCode";
import OauthStrategy from "../strategy/OauthStrategy";
import AuthorizationController from "./authorization.controller";
import OauthController from "./oauth.controller";
import { v4 as uuidV4 } from "uuid";

class StrategyController extends OauthController {
  static OAUTH_STRATEGY_CALLBACK_PATH =
    "oauth/v2/strategy/callback/:identifier";

  /**
   * Get authorization token
   * @param req request
   * @param res response
   */
  redirect = async (req: Request, res: Response) => {
    // session exists
    if (req.session) {
      // load strategy
      const strategy = this.oauthContext.strategies.find(
        (s) => s.options.identifier === req.params.identifier
      );

      /**
       * Load session auth code
       */
      const authCode = await OauthAuthCode.findById(
        (req.session as any).oauthAuthCodeId
      );

      // strategy exists
      if (strategy) {
        // auth code exist
        if (authCode) {
          /**
           * Strategy state
           * -------------------
           */
          // set strategy state
          authCode.strategyState = uuidV4();
          // save change
          await authCode.save();

          switch (strategy.options.grant) {
            case "authorization_code": {
              // get the redirection uri
              const redirectUri =
                strategy.options.client.authorizationCode.getAuthUri({
                  state: authCode.strategyState,
                  callbackUrl: `${UrlHelper.getFullUrl(req)}/${
                    StrategyController.OAUTH_STRATEGY_CALLBACK_PATH
                  }`.replace(":identifier", strategy.options.identifier),
                });

              // redirect
              return res.redirect(HttpStatus.TemporaryRedirect, redirectUri);
            }

            case "authorization_code_pkce": {
              // get the redirection uri
              const redirectUri =
                strategy.options.client.authorizationCodePKCE.getAuthUri({
                  state: authCode.strategyState,
                  callbackUrl: `${UrlHelper.getFullUrl(req)}/${
                    StrategyController.OAUTH_STRATEGY_CALLBACK_PATH
                  }`.replace(":identifier", strategy.options.identifier),
                });

              // redirect
              return res.redirect(HttpStatus.TemporaryRedirect, redirectUri);
            }

            case "implicit": {
              // get redirection uri
              const redirectUri = strategy.options.client.implicit.getAuthUri({
                state: authCode.strategyState,
                callbackUrl: `${UrlHelper.getFullUrl(req)}/${
                  StrategyController.OAUTH_STRATEGY_CALLBACK_PATH
                }`.replace(":identifier", strategy.options.identifier),
              });

              // redirect
              return res.redirect(HttpStatus.TemporaryRedirect, redirectUri);
            }

            default:
              return OauthHelper.throwError(
                req,
                res,
                {
                  error: "access_denied",
                  error_description: `The grant "${strategy.options.grant}" doesn't support redirection.`,
                  state: authCode.state,
                },
                authCode.redirectUri
              );
          }
        } else {
          try {
            // destroy the session
            (req.session as any).destroy(() => {});
          } catch (error) {}

          return OauthHelper.throwError(req, res, {
            error: "access_denied",
            error_description: "Authorization code instance not found.",
            method: "redirect",
          } as any);
        }
      } else {
        return OauthHelper.throwError(
          req,
          res,
          Obj.merge(
            req.query,
            {
              error: "access_denied",
              error_description: `Oauth v2 strategy ${req.params.identifier} not found.`,
            },
            "left"
          ),
          authCode?.redirectUri
        );
      }
    } else {
      throw Error("No session defined. Express session required.");
    }
  };

  /**
   * Get authorization token
   * @param req request
   * @param res response
   */
  authorize = async (req: Request, res: Response) => {
    // session exists

    if (req.session) {
      // load strategy
      const strategy = this.oauthContext.strategies.find(
        (s) => s.options.identifier === req.params.identifier
      );

      /**
       * Load session auth code
       */
      const authCode = await OauthAuthCode.findById(
        (req.session as any).oauthAuthCodeId
      );

      // strategy exists
      if (strategy) {
        // auth code exist
        if (authCode) {
          switch (strategy.options.grant) {
            case "password":
              strategy.options.client.password.getToken({
                username: req.body.username,
                password: req.body.password,
                onSuccess: async () => {
                  return this.lookupAndRedirect(req, res, authCode, strategy);
                },
                onError: (error) => {
                  return OauthHelper.throwError(
                    req,
                    res,
                    {
                      error: "access_denied",
                      error_description:
                        error.message ??
                        `Failed to get ${strategy.options.identifier} token.`,
                      state: authCode.state,
                    },
                    authCode.redirectUri
                  );
                },
              });
              break;

            default:
              return OauthHelper.throwError(
                req,
                res,
                {
                  error: "access_denied",
                  error_description: `The grant "${strategy.options.grant}" doesn't support redirection.`,
                  state: authCode.state,
                },
                authCode.redirectUri
              );
          }
        }
      } else {
        return OauthHelper.throwError(
          req,
          res,
          Obj.merge(
            req.query,
            {
              error: "access_denied",
              error_description: `Oauth v2 strategy ${req.params.identifier} not found.`,
            },
            "left"
          ),
          authCode?.redirectUri
        );
      }
    } else {
      throw Error("No session defined. Express session required.");
    }
  };

  /**
   * Get authorization token
   * @param req request
   * @param res response
   */
  callback = async (req: Request, res: Response) => {
    // load strategy
    const strategy = this.oauthContext.strategies.find(
      (s) => s.options.identifier === req.params.identifier
    );

    /**
     * Load auth code
     */
    const authCode = await OauthAuthCode.findOne({
      strategyState: req.query.state as any,
    });

    // strategy exits
    if (strategy) {
      // auth code exist
      if (authCode) {
        /**
         * Authentication failed
         * --------------------------
         */
        if (Object.keys(req.query).includes("error")) {
          // return the error
          return OauthHelper.throwError(
            req,
            res,
            Obj.merge(req.query, { state: authCode.state }, "right"),
            authCode.redirectUri
          );
        } else {
          switch (strategy.options.grant) {
            case "authorization_code":
              await strategy.options.client.authorizationCode.getToken({
                state: authCode.state,
                callbackUrl: req.originalUrl,
                onSuccess: async (_token) => {
                  return this.lookupAndRedirect(req, res, authCode, strategy);
                },
                onError: (error) => {
                  return OauthHelper.throwError(
                    req,
                    res,
                    {
                      error: "access_denied",
                      error_description:
                        error.message ??
                        `Failed to get ${strategy.options.identifier} token.`,
                      state: authCode.state,
                    },
                    authCode.redirectUri
                  );
                },
              });
              break;

            case "authorization_code_pkce":
              await strategy.options.client.authorizationCodePKCE.getToken({
                state: authCode.state,
                callbackUrl: req.originalUrl,
                onSuccess: () => {
                  return this.lookupAndRedirect(req, res, authCode, strategy);
                },
                onError: (error) => {
                  return OauthHelper.throwError(
                    req,
                    res,
                    {
                      error: "access_denied",
                      error_description:
                        error.message ??
                        `Failed to get ${strategy.options.identifier} token.`,
                      state: authCode.state,
                    },
                    authCode.redirectUri
                  );
                },
              });
              break;

            case "implicit":
              // extract token
              strategy.options.client.implicit.getToken(
                req.originalUrl,
                authCode.state
              );

              return this.lookupAndRedirect(req, res, authCode, strategy);

            default:
              return OauthHelper.throwError(
                req,
                res,
                {
                  error: "access_denied",
                  error_description: `The grant "${strategy.options.grant}" doesn't support redirection.`,
                  state: authCode.state,
                },
                authCode.redirectUri
              );
          }
        }
      } else {
        return OauthHelper.throwError(req, res, {
          error: "access_denied",
          error_description: "Authorization code instance not found.",
          strategy_state: req.query.state,
        } as any);
      }
    } else {
      return OauthHelper.throwError(
        req,
        res,
        Obj.merge(
          req.query,
          {
            error: "access_denied",
            error_description: `Oauth v2 strategy ${req.params.identifier} not found.`,
          },
          "left"
        ),
        authCode?.redirectUri
      );
    }
  };

  /**
   * Lookup end user and redirect
   * @param req express request
   * @param res express response
   * @param authCode authorization code instance
   * @param strategy strategy
   */
  private async lookupAndRedirect(
    req: Request,
    res: Response,
    authCode: IOauthAuthCode,
    strategy: OauthStrategy
  ) {
    // lookup user
    const endUserData = await strategy.userLookup(strategy.options.client);

    /**
     * User exist
     */
    if (endUserData) {
      const currentData: ISessionCurrentData = {
        responseType: authCode.responseType,
        authData: endUserData,
      };

      if (req.session) {
        (req.session as any).currentData = currentData;
      } else {
        throw Error("Unable to access to session");
      }

      /**
       * Redirect for internal token generation
       * =============================================
       */
      const queryParams: any = {
        client_id: authCode.client.clientId,
        scope: authCode.scope,
        response_type: authCode.responseType,
        redirect_uri: authCode.redirectUri,
        state: authCode.state,
        code_challenge_method: authCode.codeChallengeMethod,
        code_challenge: authCode.codeChallenge,
      };

      return res.redirect(
        HttpStatus.MovedPermanently,
        injectQueryParams(
          `${UrlHelper.getFullUrl(req)}/${
            AuthorizationController.OAUTH_AUTHORIZE_PATH
          }`,
          Obj.cleanWithEmpty(queryParams)
        )
      );
    } else {
      return OauthHelper.throwError(
        req,
        res,
        Obj.merge(
          Obj.extend({ data: req.query, omits: ["code"] }),
          {
            error: "access_denied",
            error_description: `No account is associated with your ${`${
              strategy.options.providerName ?? strategy.options.identifier
            }`.toLowerCase()} profile.`,
          },
          "left"
        ),
        authCode?.redirectUri
      );
    }
  }
}

export default StrategyController;
