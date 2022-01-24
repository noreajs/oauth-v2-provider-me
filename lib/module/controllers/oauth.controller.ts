import { Request, Response } from "express";
import OauthContext from "../OauthContext";
import { OauthStrategy } from "../..";
import HttpStatus from "../helpers/HttpStatus";

class OauthController {
  oauthContext: OauthContext;

  constructor(oauthContext: OauthContext) {
    this.oauthContext = oauthContext;
  }

  /**
   * Generate token
   * @param req request
   * @param res response
   */
  async forward(req: Request, res: Response) {
    return res.status(HttpStatus.Ok).json({
      query: req.query,
      body: req.body,
    });
  }
}

export default OauthController;
