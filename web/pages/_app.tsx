import React, { useEffect, useRef } from "react";
import "../styles/index.css";

import { config } from "@fortawesome/fontawesome-svg-core";
import "@fortawesome/fontawesome-svg-core/styles.css"; // Import the CSS
import { LanguageContext, defaultLanguageContext } from "../components/locales";
config.autoAddCss = false; // Tell Font Awesome to skip adding the CSS automatically since it's being imported above
import { useState, useCallback } from "react";
import dayjs from "dayjs";
import localizedFormat from "dayjs/plugin/localizedFormat";
import { UserContext, defaultUserContext, useWhoAmI } from "../data/user";
import { useRouter } from "next/router";
dayjs.extend(localizedFormat);

const publicPages = ["/", "/activate", "/recover"];
const isPrivatePage = (pathname: string): boolean => {
  return publicPages.indexOf(pathname) === -1;
};

interface MyAppProps {
  Component: React.ElementType;
  pageProps: any;
}
function MyApp({ Component, pageProps }: MyAppProps) {
  const [langContext, setLangContext] = useState(defaultLanguageContext);
  const [currentUser, setCurrentUser] = useState(null);
  const updateLanguage = useCallback(
    (selectedLanguage) => {
      setLangContext({
        ...langContext,
        selected: selectedLanguage
      });
    },
    [langContext]
  );

  const { data: user, loading, error } = useWhoAmI();
  const router = useRouter();
  const pathname = router.pathname;

  useEffect(() => {
    if (user) {
      setCurrentUser(user);
    }
  }, [user]);

  useEffect(() => {
    if (!isPrivatePage(pathname) && !user) {
      return;
    }

    if (loading) {
      return;
    }

    if (user) {
      if (pathname === "/") {
        router.replace("/dashboard/users/list");
        return;
      }
    } else {
      router.replace("/");
      setCurrentUser(null);
      return;
    }

    if (error) {
      router.replace("/");
    }
  }, [user, loading, error, pathname]);

  if (
    (loading && !currentUser) ||
    (isPrivatePage(pathname) && !currentUser) ||
    (pathname === "/" && currentUser)
  ) {
    return null;
  }

  return (
    <LanguageContext.Provider value={{ ...langContext, updateLanguage }}>
      <UserContext.Provider value={currentUser}>
        <div className="bg-gray-100 font-family-karla flex">
          <Component {...pageProps} />
        </div>
      </UserContext.Provider>
    </LanguageContext.Provider>
  );
}

export default MyApp;
