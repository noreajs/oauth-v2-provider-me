import { Request } from "express";

class UrlHelper {
  injectQueryParams(uri: string, params: any) {
    const uriObj = new URL(uri);
    for (const key in params) {
      if (params.hasOwnProperty(key)) {
        uriObj.searchParams.append(key, params[key]);
      }
    }
    return uriObj.toString();
  }

  getFullUrl(req: Request) {
    return req.protocol + "://" + req.get('host');
  }
}

export default new UrlHelper();
