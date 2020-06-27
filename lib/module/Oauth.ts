import { Application, Request, Response, NextFunction } from "express";
import { IOauthContext } from "./interfaces/IOauthContext";
import oauthRoutes from "./routes/oauth.routes";
import OauthContext from "./OauthContext";
import jwt from "jsonwebtoken";
import { IJwtTokenPayload } from "./interfaces/IJwt";
import OauthAccessToken from "./models/OauthAccessToken";
import { HttpStatus, replaceAllMatch } from "@noreajs/common";
import IOauthInitMethodParams from "./interfaces/IOauthInitMethodParams";
import session from "express-session";
import colors from "colors";

export default class Oauth {
  static ERRORS = {
    /**
     * Access Token not approved
     */
    TOKEN_NOT_APPROVED: "Access Token not approved",

    /**
     * Insufficient scope
     */
    INSUFFICIENT_SCOPE: "Insufficient scope",

    /**
     * Invalid access token
     */
    INVALID_TOKEN: "Invalid access token",

    /**
     * Access Token expired
     */
    TOKEN_EXPIRED: "Access Token expired",

    /**
     * No Oauth instance running on this server
     */
    NO_INSTANCE: "No Oauth instance running on this server",

    /**
     * Authorization Header Required
     */
    AUTH_HEADER_REQUIRED: "Authorization Header Required",
  };

  private static instance: Oauth;
  context: OauthContext;
  app: Application;

  /**
   * Oauth constructor
   * @param app express application
   * @param context oauth context
   * @param params optional params
   */
  private constructor(
    app: Application,
    context: OauthContext,
    params?: IOauthInitMethodParams
  ) {
    // express app
    this.app = app;
    // oauth provider context
    this.context = context;
    // initialize oauth instance
    this.initialize(params);
  }

  /**
   * Initialize oauth instance
   * @param params optional params
   */
  private initialize(params?: IOauthInitMethodParams) {
    /**
     * Watch session existance
     */
    this.app.use((req, res, next) => {
      /**
       * Check session existance
       */
      if (!req.session) {
        console.log(
          colors.red("Oauth v2 provider server warning - Express session")
        );
        console.log(
          colors.yellow(
            "An express session is required for the proper functioning of the package. The sessionOptions attribute in the third parameter of the Oauth.init method is required."
          )
        );
        console.log(
          colors.green(
            "You can also initialize Express session before initializing Oauth."
          )
        );
        next("Express session configuration is required.");
      } else {
        next();
      }
    });

    /**
     * Set session if defined
     */
    if (params && params.sessionOptions) {
      this.app.use(
        session({
          secret: params.sessionOptions.secret ?? this.context.secretKey,
          resave: params.sessionOptions.resave ?? false,
          saveUninitialized: params.sessionOptions.saveUninitialized ?? true,
          name:
            params.sessionOptions.name ??
            `${replaceAllMatch(
              this.context.providerName.toLocaleLowerCase(),
              /\s/g,
              "-"
            )}.sid`,
          cookie: params.sessionOptions.cookie ?? {
            httpOnly: true,
            secure: this.app.get("env") === "production",
            maxAge: 1000 * 60 * 60, // 1 hour
          },
          store: params.sessionOptions.store,
        })
      );

      /**
       * Notification about a potential vulnerability
       */
      if (
        this.app.get("env") === "production" &&
        !params.sessionOptions.store
      ) {
        console.log(
          colors.red("Oauth v2 provider server warning - Express session")
        );
        console.log(
          colors.yellow(
            "Session IDs are stored in memory and this is not optimal for a production environment. Set a session store in sessionOptions while initializing the package."
          )
        );
      }
    }

    // set the view engine to ejs
    this.app.set("view engine", "ejs");

    // Add oauth routes
    oauthRoutes(this.app, this.context);
  }

  /**
   * Get oauth instance
   */
  public static getInstance(): Oauth {
    return Oauth.instance;
  }

  /**
   * Initialize oauth 2 module
   * @param app express application
   * @param context oauth 2 context
   * @param params optional params
   */
  static init(
    app: Application,
    initContext: IOauthContext,
    params?: IOauthInitMethodParams
  ) {
    // create context
    Oauth.instance = new Oauth(app, new OauthContext(initContext), params);
  }

  /**
   * Verify an access token
   * @param token access token without the token type (Bearer, Token or everything else)
   * @param success success callback
   * @param error error callback which is a method with two parameters, reason and authError. authError = true means that the error is related to the token and false if it is and internal probleme
   * @param scope scope to be checked in the access token
   */
  static async verifyToken(
    token: string,
    success: (userId: string, lookupData?: any) => Promise<void> | void,
    error: (reason: string, authError: boolean) => Promise<void> | void,
    scope?: string
  ) {
    // get auth instance
    const oauth = Oauth.getInstance();
    // check instance existance
    if (oauth) {
      // get oauth context
      const oauthContext = oauth.context;
      try {
        // Verify token signature
        const tokenData = jwt.verify(token, oauthContext.secretKey, {
          algorithms: [oauthContext.jwtAlgorithm],
        }) as IJwtTokenPayload;

        // load access token
        const accessToken = await OauthAccessToken.findById(tokenData.jti);

        // access token must exist localy
        if (accessToken) {
          // revocation state
          if (accessToken.revokedAt) {
            error(Oauth.ERRORS.TOKEN_NOT_APPROVED, true);
          } else {
            // lookup sub for other grant but client_credentials
            let user = undefined;
            if (
              accessToken.grant !== "client_credentials" &&
              oauthContext.subLookup
            ) {
              user = await oauthContext.subLookup(accessToken.userId);
            }

            // scope validation if exist
            if (scope) {
              const tokenScope = tokenData.scope ?? accessToken.scope;
              const tokenScopeParts = tokenScope.split(" ");
              const scopeParts = scope.split(" ");
              for (const item of tokenScopeParts) {
                if (!scopeParts.includes(item)) {
                  error(Oauth.ERRORS.INSUFFICIENT_SCOPE, true);
                }
              }

              // the user can access to the resource
              success(accessToken.userId, user);
            } else {
              // the user can access to the resource
              success(accessToken.userId, user);
            }
          }
        } else {
          error(Oauth.ERRORS.INVALID_TOKEN, true);
        }
      } catch (err) {
        error(Oauth.ERRORS.TOKEN_EXPIRED, true);
      }
    } else {
      console.warn(
        "The Oauth.context static property is not defined. Make sure you have initialized the Oauth package as described in the documentation."
      );
      // the user can access to the resource
      error(Oauth.ERRORS.NO_INSTANCE, false);
    }
  }

  /**
   * Validate user access token
   * @param scope scope needed - Optional
   */
  static authorize(scope?: string) {
    return async (req: Request, res: Response, next: NextFunction) => {
      // get auth instance
      const oauth = Oauth.getInstance();
      // check instance existance
      if (oauth) {
        // get oauth context
        const oauthContext = oauth.context;
        // authorization server
        const authorization =
          req.headers["authorization"] ?? req.headers["proxy-authorization"];
        // authorization required
        if (authorization) {
          // bearer token required
          if (authorization.startsWith(oauthContext.tokenType)) {
            // token parts
            const parts = authorization.split(" ");
            try {
              // verify the token
              await Oauth.verifyToken(
                parts[1],
                (userId, user) => {
                  res.locals.user = user;
                  // continue
                  next();
                },
                (reason: string, authError: boolean) => {
                  if (authError) {
                    res.status(HttpStatus.Unauthorized).json({
                      message: reason,
                    });
                    return;
                  } else {
                    // continue
                    next();
                  }
                },
                scope
              );
            } catch (error) {
              return res.status(HttpStatus.Unauthorized).json({
                message: Oauth.ERRORS.TOKEN_EXPIRED,
              });
            }
          } else {
            return res.status(HttpStatus.Unauthorized).json({
              message: `${oauthContext.tokenType} Token type required`,
            });
          }
        } else {
          return res.status(HttpStatus.Unauthorized).json({
            message: Oauth.ERRORS.AUTH_HEADER_REQUIRED,
          });
        }
      } else {
        console.warn(
          "The Oauth.context static property is not defined. Make sure you have initialized the Oauth package as described in the documentation."
        );
        // the user can access to the resource
        next();
      }
    };
  }
}
