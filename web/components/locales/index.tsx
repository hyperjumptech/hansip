import React, { createContext, useContext } from "react";
import idStrings from "./id.json";
import enStrings from "./en.json";

export const defaultLanguageContext = {
  languages: {
    id: idStrings,
    en: enStrings
  },
  selected: "id",
  updateLanguage: (lang: string): void => {}
};

export const LanguageContext = createContext(defaultLanguageContext);
LanguageContext.displayName = "LanguageContext";

const escapeRegex = (value: string) =>
  value.replace(/[\-\[\]{}()*+?.,\\\^$|#\s]/g, "\\$&");

export const stringWithFormat = (message: string, params?: Object) => {
  var result = message || "";
  if (params) {
    Object.keys(params).forEach(function (key) {
      result = result.replace(new RegExp(escapeRegex(key), "g"), params[key]);
    });
  }

  return result;
};

export const useLocale = () => {
  const language = useContext(LanguageContext);
  const strings = language.languages[language.selected];

  return {
    selectedLanguage: language.selected,
    languages: language.languages,
    strings: (key: string): string => stringWithFormat(strings[key]),
    stringWithFormat
  };
};
