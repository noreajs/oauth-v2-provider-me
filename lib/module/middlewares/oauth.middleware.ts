import { urlencoded } from "body-parser";
import { NextFunction, Request, Response } from "express";
const crsf = require("csurf");

class OauthMiddleware {
  /**
   * Authorization request validation required
   * @param req request
   * @param res response
   * @param next next function
   */
  async authorize(req: Request, res: Response, next: NextFunction) { }

  /**
   * Inject crsf token
   */
  injectCsrfToken() {
    return [crsf({ cookie: true })];
  }

  /**
   * Verify csrf token
   */
  verifyCsrfToken() {
    const urlencodedParser = urlencoded({ extended: false });
    return [urlencodedParser, crsf({ cookie: true })];
  }
}

export default new OauthMiddleware();
