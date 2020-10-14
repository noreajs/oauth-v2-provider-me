import { Application, Router } from "express";
import oauthController from "../controllers/oauth.controller";
import oauthClientRoutes from "./oauth-client.routes";
import authorizationRoutes from "./authorization.routes";
import accessTokenRoutes from "./access-token.routes";
import OauthContext from "../OauthContext";
import oauthScopeRoutes from "./oauth-scope.routes";
import purgeRoutes from "./purge.routes";
import strategyRoutes from "./strategy.routes";

export default (app: Application, oauthContext: OauthContext) => {
  /**
   * Auth routes
   */
  const oauthModule = Router({
    mergeParams: true,
  });

  /**
   * Clients routes
   */
  oauthClientRoutes(oauthModule, oauthContext);

  /**
   * Scope routes
   */
  oauthScopeRoutes(oauthModule, oauthContext);

  /**
   * Authorization routes
   */
  authorizationRoutes(oauthModule, oauthContext);

  /**
   * Access tokens routes
   */
  accessTokenRoutes(oauthModule, oauthContext);

  /**
   * Strategy routes
   */
  strategyRoutes(oauthModule, oauthContext);

  /**
   * Purge tokens and codes
   */
  purgeRoutes(oauthModule, oauthContext);

  /**
   * Get token
   * For test purpose
   */
  oauthModule
    .route("/callback")
    .get([new oauthController(oauthContext).forward]);

  /**
   * Inject oauth v2
   */
  app.use("/oauth/v2", oauthModule);
};
