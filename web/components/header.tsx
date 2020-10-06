import React, { useContext } from "react";
import Select, { CaretDown } from "./select";
import { LanguageContext, useLocale } from "./locales";
import { useUser } from "../data/user";
import Dropdown from "./dropdown";

const AccountDropdown = () => {
  const user = useUser();
  const { strings } = useLocale();
  return (
    <Dropdown
      current={
        <div className="border border-gray-400 hover:border-gray-500 px-4 py-2  rounded shadow flex flex-row items-center space-x-2 bg-white">
          <p>{user.email}</p>
          <div className=" inline-block">
            <CaretDown />
          </div>
        </div>
      }>
      <a
        href="/dashboard/settings"
        className="block px-4 py-2 account-link hover:text-white">
        {strings("settings")}
      </a>
      <a
        href="/logout"
        className="block px-4 py-2 account-link hover:text-white">
        {strings("sign-out")}
      </a>
    </Dropdown>
  );
};

interface DesktopHeaderProps {
  showLogo?: boolean;
}
const DesktopHeader = ({ showLogo }: DesktopHeaderProps) => {
  const language = useContext(LanguageContext);
  const user = useUser();
  return (
    <header className="w-full flex items-center justify-between bg-white py-2 px-6 space-x-2 bg-opacity-25">
      {showLogo && <h1 className=" text-3xl font-bold text-white">HANSIP</h1>}
      {!showLogo && <div></div>}
      <div className={`relative  flex justify-end items-center`}>
        <Select
          onChange={(event) => {
            language.updateLanguage(event.target.value);
          }}
          value={language.selected}
          options={[
            {
              title: "Bahasa",
              value: "id"
            },
            {
              title: "English",
              value: "en"
            }
          ]}
        />
        {user && user.rec_id && (
          <div className={`relative  flex justify-end`}>
            <AccountDropdown />
          </div>
        )}
      </div>
    </header>
  );
};

export default DesktopHeader;
