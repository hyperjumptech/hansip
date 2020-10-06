import { getSavedTokens, refreshSavedToken } from "./user";

const baseURL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8088";

const authorizedPost = (
  path: string,
  body: Object,
  accessToken?: string,
  method?: string
): Promise<any> => {
  var tokenToUse = accessToken;
  if (!tokenToUse) {
    tokenToUse = getSavedTokens().access_token;
  }
  return fetch(`${baseURL}/api/v1${path}`, {
    method: method || "POST",
    headers: {
      "Content-type": "application/json",
      Authorization: `Bearer ${tokenToUse}`
    },
    body: JSON.stringify(body)
  }).then((res) => res.json());
};

export const post = (
  path: string,
  body: Object,
  accessToken?: string,
  method?: string,
  refreshToken?: string,
  skipRefreshToken?: boolean
): Promise<any> => {
  // simply send the request if skipRefreshToken is true
  if (skipRefreshToken) {
    return authorizedPost(path, body, accessToken, method);
  }

  // get the refresh token from local storage if needed
  var refreshTokenToUse = refreshToken;
  if (!refreshTokenToUse) {
    refreshTokenToUse = getSavedTokens().refresh_token;
  }

  if (!refreshTokenToUse) {
    return authorizedPost(path, body, accessToken, method);
  }

  // refresh the access token first before sending the the request
  return refreshSavedToken(refreshTokenToUse).then(() =>
    authorizedPost(path, body, accessToken, method)
  );
};

export const get = (
  path: string,
  searchParams?: Object,
  accessToken?: string,
  responseTransform?: (response: any) => Promise<any>
): Promise<any> => {
  var tokenToUse = accessToken;
  if (!tokenToUse) {
    tokenToUse = getSavedTokens().access_token;
  }
  const theURL = new URL(`${baseURL}/api/v1${path}`);
  if (searchParams) {
    const keys = Object.keys(searchParams);
    for (let index = 0; index < keys.length; index++) {
      const key = keys[index];
      const val = searchParams[key];
      theURL.searchParams.append(key, val);
    }
  }
  var headers: HeadersInit = {
    "Content-type": "application/json"
  };
  if (tokenToUse) {
    headers = {
      ...headers,
      Authorization: `Bearer ${tokenToUse}`
    };
  }
  const jsonTransform = (res) => res.json();
  return fetch(theURL.toString(), {
    headers
  }).then(responseTransform || jsonTransform);
};
