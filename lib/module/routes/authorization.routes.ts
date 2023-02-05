import { Router } from "express";
import authorizationController from "../controllers/authorization.controller";
import authorizationMiddleware from "../middlewares/authorization.middleware";
import oauthMiddleware from "../middlewares/oauth.middleware";
import OauthContext from "../OauthContext";

export default (module: Router, oauthContext: OauthContext) => {
  /**
   * Authorize
   */
  module
    .route("/authorize")
    .get([
      authorizationMiddleware.validRequestRequired,
      new authorizationController(oauthContext).authorize,
    ]);

  /**
  * Get authorization dialog
  */
  module
    .route("/dialog")
    .get([
      ...oauthMiddleware.injectCsrfToken(),
      new authorizationController(oauthContext).dialog,
    ]);

  /**
   * Authenticate the user
   */
  module
    .route("/authorize-submit")
    .get([
      ...oauthMiddleware.verifyCsrfToken(),
      new authorizationController(oauthContext).authenticate,
    ]);
};
