import { OauthScope } from "../..";
import { Obj, Arr } from "@noreajs/common";
import { HookNextFunction } from "mongoose";

class OauthScopeProvider {
  /**
   * Validate scopes
   * @param scope scope
   */
  async validateScopes(scope: string) {
    if (scope && scope !== "*") {
      const scopes = scope.split(" ");

      const oauthScopes = await OauthScope.find({
        name: { $in: scopes },
      });
      // missing scopes
      return Arr.missing(scopes, Obj.pluck(oauthScopes, "name"));
    }
    return [];
  }

  /**
   * Validate scopes
   * @param scope scope
   * @param next Mongoose Hook Next Function
   */
  async validateScopesHook(scope: string, next: HookNextFunction) {
    const r = await this.validateScopes(scope);
    if (r.length !== 0) {
      next({
        name: "Scope validation failed",
        message: `Missing or not yet created ${
          r.length == 1 ? "scope" : "scopes"
        }: ${r.join(", ")}.`,
      });
    }
  }
}

export default new OauthScopeProvider();
