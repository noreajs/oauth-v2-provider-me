import { Obj } from "@noreajs/common";
import { Request, Response } from "express";
import { injectQueryParams, TokenResponse } from "oauth-v2-client";
import { v4 as uuidV4 } from "uuid";
import HttpStatus from "../helpers/HttpStatus";
import OauthHelper from "../helpers/OauthHelper";
import UrlHelper from "../helpers/UrlHelper";
import ISessionCurrentData from "../interfaces/ISessionCurrentData";
import OauthAuthCode, { IOauthAuthCode } from "../models/OauthAuthCode";
import OauthContext from "../OauthContext";
import OauthStrategy from "../strategy/OauthStrategy";
import AuthorizationController from "./authorization.controller";
import OauthController from "./oauth.controller";

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
      const authCode = await OauthAuthCode.findById<IOauthAuthCode>(
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
          const strategyState = uuidV4();
          // set strategy state
          (req.session as any).strategyState = strategyState;

          switch (strategy.options.grant) {
            case "authorization_code": {
              // get the redirection uri
              const redirectUri =
                strategy.options.client.authorizationCode.getAuthUri({
                  state: strategyState
                });
              // redirect
              return res.redirect(HttpStatus.TemporaryRedirect, redirectUri);
            }

            case "authorization_code_pkce": {
              // get the redirection uri
              const redirectUri =
                strategy.options.client.authorizationCodePKCE.getAuthUri({
                  state: strategyState
                });

              // redirect
              return res.redirect(HttpStatus.TemporaryRedirect, redirectUri);
            }

            case "implicit": {
              // get redirection uri
              const redirectUri = strategy.options.client.implicit.getAuthUri({
                state: strategyState
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
                  state: req.cookies?.[this.oauthContext.stateCookieVariableName],
                },
                authCode.redirectUri
              );
          }
        } else {
          try {
            // destroy the session
            (req.session as any).destroy(() => { });
          } catch (error) { }

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
      const authCode = await OauthAuthCode.findById<IOauthAuthCode>(
        (req.session as any).oauthAuthCodeId
      );

      // strategy exists
      if (strategy) {
        // auth code exist
        if (authCode) {
          switch (strategy.options.grant) {
            case "password":
              return new Promise(async (resolve, reject) => {
                await strategy.options.client.password.getToken<TokenResponse>({
                  username: req.body.username,
                  password: req.body.password,
                  onSuccess: async (token) => {
                    resolve(await this.lookupAndRedirect({
                      context: this.oauthContext, req, res, authCode, strategy, token
                    }))
                  },
                  onError: (error: any) => {
                    reject(OauthHelper.throwError(
                      req,
                      res,
                      {
                        error: "access_denied",
                        error_description:
                          error.message ??
                          `Failed to get ${strategy.options.identifier} token.`,
                        state: req.cookies?.[this.oauthContext.stateCookieVariableName],
                      },
                      authCode.redirectUri
                    ));
                  },
                });
              })

            default:
              return OauthHelper.throwError(
                req,
                res,
                {
                  error: "access_denied",
                  error_description: `The grant "${strategy.options.grant}" doesn't support redirection.`,
                  state: req.cookies?.[this.oauthContext.stateCookieVariableName],
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
    const authCode = await OauthAuthCode.findById<IOauthAuthCode>(
      (req.session as any).oauthAuthCodeId
    );

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
            Obj.merge(req.query, { state: req.cookies[this.oauthContext.stateCookieVariableName] }, "right"),
            authCode.redirectUri
          );
        } else {
          switch (strategy.options.grant) {
            case "authorization_code":
              return new Promise(async (resolve, reject) => {
                await strategy.options.client.authorizationCode.getToken<TokenResponse>({
                  state: (req.session as any)?.strategyState,
                  callbackUrl: req.originalUrl,
                  onSuccess: async (token) => {
                    resolve(await this.lookupAndRedirect({ context: this.oauthContext, req, res, authCode, strategy, token }))
                  },
                  onError: (error: any) => {
                    reject(OauthHelper.throwError(
                      req,
                      res,
                      {
                        error: "access_denied",
                        error_description:
                          error.message ??
                          `Failed to get ${strategy.options.identifier} token.`,
                        state: req.cookies[this.oauthContext.stateCookieVariableName],
                      },
                      authCode.redirectUri
                    ))
                  },
                });
              })

            case "authorization_code_pkce":
              return new Promise(async (resolve, reject) => {
                await strategy.options.client.authorizationCodePKCE.getToken<TokenResponse>({
                  state: (req.session as any)?.strategyState,
                  callbackUrl: req.originalUrl,
                  onSuccess: async (token) => {
                    resolve(await this.lookupAndRedirect({ context: this.oauthContext, req, res, authCode, strategy, token }))
                  },
                  onError: (error: any) => {
                    reject(OauthHelper.throwError(
                      req,
                      res,
                      {
                        error: "access_denied",
                        error_description:
                          error.message ??
                          `Failed to get ${strategy.options.identifier} token.`,
                        state: req.cookies[this.oauthContext.stateCookieVariableName],
                      },
                      authCode.redirectUri
                    ))
                  },
                });
              })

            case "implicit":
              // extract token
              const token = strategy.options.client.implicit.getToken<TokenResponse>(
                req.originalUrl,
                (req.session as any)?.strategyState
              );

              return this.lookupAndRedirect({ context: this.oauthContext, req, res, authCode, strategy, token });

            default:
              return OauthHelper.throwError(
                req,
                res,
                {
                  error: "access_denied",
                  error_description: `The grant "${strategy.options.grant} " doesn't support redirection.`,
                  state: req.cookies[this.oauthContext.stateCookieVariableName],
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
    params: {
      context: OauthContext,
      req: Request,
      res: Response,
      authCode: IOauthAuthCode,
      strategy: OauthStrategy,
      token: TokenResponse
    }
  ) {
    // lookup user
    const endUserData = await params.strategy.userLookup(params.strategy.options.client, params.token);

    /**
     * User exist
     */
    if (endUserData) {
      const currentData: ISessionCurrentData = {
        responseType: params.authCode.responseType,
        authData: endUserData,
      };

      if (params.req.session) {
        (params.req.session as any).currentData = currentData;
      } else {
        throw Error("Unable to access to session");
      }

      /**
       * Redirect for internal token generation
       * =============================================
       */
      const queryParams: any = {
        client_id: params.authCode.client.clientId,
        scope: params.authCode.scope,
        response_type: params.authCode.responseType,
        redirect_uri: params.authCode.redirectUri,
        state: params.req.cookies[params.context.stateCookieVariableName],
        code_challenge_method: params.authCode.codeChallengeMethod,
        code_challenge: params.req.cookies[params.context.codeChallengeCookieVariableName],
      };

      return params.res.redirect(
        HttpStatus.MovedPermanently,
        injectQueryParams(
          `${UrlHelper.getFullUrl(params.req)}/${AuthorizationController.OAUTH_AUTHORIZE_PATH
          }`,
          Obj.cleanWithEmpty(queryParams)
        )
      );
    } else {
      return OauthHelper.throwError(
        params.req,
        params.res,
        Obj.merge(
          Obj.extend({ data: params.req.query, omits: ["code", "state"] }),
          {
            state: params.req.cookies?.[this.oauthContext.stateCookieVariableName],
            error: "access_denied",
            error_description: `No account is associated with your ${`${params.strategy.options.providerName ?? params.strategy.options.identifier
              }`.toLowerCase()} profile.`,
          },
          "left"
        ),
        params.authCode?.redirectUri
      );
    }
  }
}

export default StrategyController;
