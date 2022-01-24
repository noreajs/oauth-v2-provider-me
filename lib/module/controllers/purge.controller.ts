import { Request, Response } from "express";
import moment from "moment";
import OauthController from "./oauth.controller";
import OauthAccessToken from "../models/OauthAccessToken";
import OauthAuthCode from "../models/OauthAuthCode";
import HttpStatus from "../helpers/HttpStatus";

type PurgeType = "revoked" | "expired";
const PurgeTypeList = ["revoked", "expired"];

class PurgeController extends OauthController {
  /**
   * Purge expired and revoked tokens and codes
   * @param req request
   * @param res response
   */
  async purge(req: Request, res: Response) {
    try {
      // purge type
      const purgeType = req.query.type as PurgeType;

      // init counter
      let purgedTokens = 0;
      let purgedCodes = 0;

      switch (purgeType) {
        case "revoked": {
          // count tokens
          purgedTokens = await OauthAccessToken.countDocuments({
            revokedAt: { $exists: true },
          });

          // remove tokens
          await OauthAccessToken.remove({ revokedAt: { $exists: true } });

          // count code
          purgedCodes = await OauthAuthCode.countDocuments({
            revokedAt: { $exists: true },
          });

          // remove tokens
          await OauthAuthCode.remove({ revokedAt: { $exists: true } });

          break;
        }

        case "expired": {
          // count tokens
          purgedTokens = await OauthAccessToken.countDocuments({
            expiresAt: { $gt: moment().toDate() },
          });

          // remove tokens
          OauthAccessToken.remove({ expiresAt: { $gt: moment().toDate() } });

          // count codes
          purgedCodes = await OauthAuthCode.countDocuments({
            expiresAt: { $gt: moment().toDate() },
          });

          // remove tokens
          OauthAuthCode.remove({ expiresAt: { $gt: moment().toDate() } });

          break;
        }
        default: {
          // count tokens
          purgedTokens = await OauthAccessToken.countDocuments({
            $or: [
              { revokedAt: { $exists: true } },
              { expiresAt: { $gt: moment().toDate() } },
            ],
          });

          // remove tokens
          await OauthAccessToken.remove({
            $or: [
              { revokedAt: { $exists: true } },
              { expiresAt: { $gt: moment().toDate() } },
            ],
          });

          // count codes
          purgedCodes = await OauthAuthCode.countDocuments({
            $or: [
              { revokedAt: { $exists: true } },
              { expiresAt: { $gt: moment().toDate() } },
            ],
          });

          // remove tokens
          await OauthAuthCode.remove({
            $or: [
              { revokedAt: { $exists: true } },
              { expiresAt: { $gt: moment().toDate() } },
            ],
          });

          break;
        }
      }
      return res.status(HttpStatus.Ok).json({
        target: PurgeTypeList.includes(purgeType)
          ? purgeType
          : PurgeTypeList.join(" or "),
        purgedTokens: purgedTokens,
        purgeCodes: purgedCodes,
      });
    } catch (error) {
      return res.status(HttpStatus.InternalServerError).json(error);
    }
  }

  /**
   * Purge expired and revoked tokens
   * @param req request
   * @param res response
   */
  async purgeTokens(req: Request, res: Response) {
    try {
      // purge type
      const purgeType = req.query.type as PurgeType;

      // count purged tokens
      let purgedTokens = 0;

      switch (purgeType) {
        case "revoked":
          // count
          purgedTokens = await OauthAccessToken.countDocuments({
            revokedAt: { $exists: true },
          });
          // remove tokens
          await OauthAccessToken.remove({ revokedAt: { $exists: true } });
          break;
        case "expired":
          // count
          purgedTokens = await OauthAccessToken.countDocuments({
            expiresAt: { $gt: moment().toDate() },
          });
          // remove tokens
          OauthAccessToken.remove({ expiresAt: { $gt: moment().toDate() } });
          break;
        default:
          // count
          purgedTokens = await OauthAccessToken.countDocuments({
            $or: [
              { revokedAt: { $exists: true } },
              { expiresAt: { $gt: moment().toDate() } },
            ],
          });
          // remove tokens
          await OauthAccessToken.remove({
            $or: [
              { revokedAt: { $exists: true } },
              { expiresAt: { $gt: moment().toDate() } },
            ],
          });
          break;
      }
      return res.status(HttpStatus.Ok).json({
        target: PurgeTypeList.includes(purgeType)
          ? purgeType
          : PurgeTypeList.join(" or "),
        purgedTokens: purgedTokens,
      });
    } catch (error) {
      return res.status(HttpStatus.InternalServerError).json(error);
    }
  }

  /**
   * Purge expired and revoked codes
   * @param req request
   * @param res response
   */
  async purgeCodes(req: Request, res: Response) {
    try {
      // purge type
      const purgeType = req.query.type as PurgeType;

      // count purged codes
      let purgedCodes = 0;

      switch (purgeType) {
        case "revoked":
          // count
          purgedCodes = await OauthAuthCode.countDocuments({
            revokedAt: { $exists: true },
          });
          // remove tokens
          await OauthAuthCode.remove({ revokedAt: { $exists: true } });
          break;
        case "expired":
          // count
          purgedCodes = await OauthAuthCode.countDocuments({
            expiresAt: { $gt: moment().toDate() },
          });
          // remove tokens
          OauthAuthCode.remove({ expiresAt: { $gt: moment().toDate() } });
          break;
        default:
          // count
          purgedCodes = await OauthAuthCode.countDocuments({
            $or: [
              { revokedAt: { $exists: true } },
              { expiresAt: { $gt: moment().toDate() } },
            ],
          });
          // remove tokens
          await OauthAuthCode.remove({
            $or: [
              { revokedAt: { $exists: true } },
              { expiresAt: { $gt: moment().toDate() } },
            ],
          });
          break;
      }
      return res.status(HttpStatus.Ok).json({
        target: PurgeTypeList.includes(purgeType)
          ? purgeType
          : PurgeTypeList.join(" or "),
        purgedCodes: purgedCodes,
      });
    } catch (error) {
      return res.status(HttpStatus.InternalServerError).json(error);
    }
  }
}

export default PurgeController;
