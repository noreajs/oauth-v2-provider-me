import OauthController from "./oauth.controller";
import OauthScope, { IOauthScope } from "../models/OauthScope";
import { HttpStatus } from "@noreajs/common";
import { Request, Response } from "express";
import { serializeError } from "serialize-error";
import { linearizeErrors } from "@noreajs/mongoose";

export default class OauthScopeController extends OauthController {
  /**
   * Get all scopes
   * @param req request
   * @param res response
   */
  async all(req: Request, res: Response) {
    await OauthScope.paginate()
      .then((result) => {
        return res.status(HttpStatus.Ok).json(result);
      })
      .catch((e) => {
        return res
          .status(HttpStatus.InternalServerError)
          .json(serializeError(e));
      });
  }

  /**
   * Create a scope
   * @param req request
   * @param res response
   */
  create = async (req: Request, res: Response) => {
    try {
      // create a new oauth scope
      const scope = await new OauthScope({
        name: req.body.name,
        description: req.body.domaine,
        parent: req.body.parent,
      } as Partial<IOauthScope>).save();

      return res.status(HttpStatus.Created).json(scope);
    } catch (e) {
      linearizeErrors(e);
      return res.status(HttpStatus.InternalServerError).json(serializeError(e));
    }
  };

  /**
   * Edit a scope
   * @param req request
   * @param res response
   */
  async edit(req: Request, res: Response) {
    try {
      // load client
      const scope = await OauthScope.findById(req.params.scopeId);

      if (scope) {
        // apply changes
        scope.set({
          name: req.body.name || scope.name,
          description: req.body.domaine || scope.description,
          parent: req.body.parent || scope.parent._id,
        } as Partial<IOauthScope>);
        // change approval state
        if (req.body.revoked !== undefined) {
          scope.set({
            revokedAt: req.body.revoked ? new Date() : undefined,
          });
        }

        // save changes
        await scope.save();

        return res.status(HttpStatus.Ok).json(scope);
      } else {
        return res.status(HttpStatus.NotFound).send();
      }
    } catch (e) {
      linearizeErrors(e);
      return res.status(HttpStatus.InternalServerError).json(serializeError(e));
    }
  }

  /**
   * Get scope details
   * @param req request
   * @param res response
   */
  async show(req: Request, res: Response) {
    try {
      // load scope
      const scope = await OauthScope.findById(req.params.scopeId);

      if (scope) {
        return res.status(HttpStatus.Ok).json(scope);
      } else {
        return res.status(HttpStatus.NotFound).send();
      }
    } catch (e) {
      return res.status(HttpStatus.InternalServerError).json(serializeError(e));
    }
  }

  /**
   * Delete a scope
   * @param req request
   * @param res response
   */
  async delete(req: Request, res: Response) {
    try {
      // load scope
      const scope = await OauthScope.findById(req.params.scopeId);

      if (scope) {
        // remove the scope
        await scope.remove();
        return res.status(HttpStatus.Ok).send();
      } else {
        return res.status(HttpStatus.NotFound).send();
      }
    } catch (e) {
      return res.status(HttpStatus.InternalServerError).json(serializeError(e));
    }
  }
}
