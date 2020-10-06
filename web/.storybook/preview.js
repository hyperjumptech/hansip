import "../styles/index.css";
import React from "react";
import { RouterContext } from "next/dist/next-server/lib/router-context";
import { NextRouter } from "next/router";
import MyApp from "../pages/_app";
const mockRouter: NextRouter = {
  basePath: "",
  pathname: "/",
  route: "/",
  asPath: "/",
  query: {},
  push: (url) => Promise.resolve(true),
  replace: (url) => Promise.resolve(true),
  reload: () => {},
  back: () => {},
  prefetch: (url) => Promise.resolve(),
  beforePopState: () => {},
  events: {
    on: () => {},
    off: () => {},
    emit: () => {}
  },
  isFallback: false
};

export const decorators = [
  (Story) => (
    <RouterContext.Provider value={{ ...mockRouter }}>
      <MyApp Component={Story} pageProps={{}} />
    </RouterContext.Provider>
  )
];
