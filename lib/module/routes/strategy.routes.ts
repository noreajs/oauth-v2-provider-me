import OauthContext from "../OauthContext";
import { Router } from "express";
import oauthMiddleware from "../middlewares/oauth.middleware";
import StrategyController from "../controllers/strategy.controller";

export default (module: Router, oauthContext: OauthContext) => {
  /**
   * Oauth strategy authorization callback
   */
  module
    .route("/strategy/callback/:identifier")
    .get([new StrategyController(oauthContext).callback]);

  /**
   * Oauth strategy authentication (implicit and authorization code grants)
   */
  module
    .route("/strategy/:identifier")
    .get([
      ...oauthMiddleware.verifyCsrfToken(),
      new StrategyController(oauthContext).redirect]);

  /**
   * Oauth strategy authentication (password grant)
   */
  module
    .route("/strategy/:identifier")
    .post([
      ...oauthMiddleware.verifyCsrfToken(),
      new StrategyController(oauthContext).authorize,
    ]);
};
