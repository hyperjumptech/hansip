import { faSpinner } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useRouter } from "next/router";
import React, { useEffect, useState } from "react";
import DesktopHeader from "../components/header";
import { LabelInput } from "../components/label-input";
import { useLocale } from "../components/locales";
import { post } from "../data/requests";

const ActivatePageView = ({
  isLoading,
  password,
  setPassword,
  onSubmit,
  error
}) => {
  const { strings } = useLocale();

  return (
    <div className="bg-gradient w-full h-screen flex flex-col  items-center">
      <DesktopHeader />
      <div className="w-full max-w-md mt-4 ">
        <div className="bg-white p-4 rounded-md mx-4 shadow-lg">
          <h1 className="block text-4xl font-bold mb-4">
            {strings("activate")}
          </h1>
          {error && (
            <div className="w-full rounded-md bg-red-400 text-white p-4">
              {error}
            </div>
          )}
          <form onSubmit={onSubmit}>
            <LabelInput
              className="mt-6"
              id="password"
              disabled={isLoading}
              labelText={strings("new-password")}
              inputType="password"
              placeholder={strings("password-placeholder")}
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
              }}
            />
            <button
              disabled={isLoading}
              type="submit"
              className="btn-blue mt-6">
              {isLoading ? (
                <FontAwesomeIcon icon={faSpinner} className="animate-spin" />
              ) : (
                strings("save")
              )}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};

const ActivatePageInvalid = () => {
  const { strings } = useLocale();
  return (
    <div className="bg-gradient w-full h-screen flex flex-col  items-center">
      <DesktopHeader />
      <div className="w-full max-w-md mt-4 ">
        <div className="  bg-white p-4 rounded-md mx-4 shadow-lg">
          <p>{strings("activation-error")}</p>
        </div>
      </div>
    </div>
  );
};

const ActivatePage = () => {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  if (!router.query || !router.query["email"] || !router.query["code"]) {
    return <ActivatePageInvalid />;
  }

  // WORKAROUND: When the email contains '+' character, router.query strips it off.
  // So we directly get the email from the path.
  const email = decodeURIComponent(
    router.asPath
      .split("?")[1]
      .split("&")
      .map((q) => q.split("="))
      .filter((q) => q[0] === "email")[0][1]
  );

  return (
    <div className="bg-gradient w-full h-screen flex flex-col  items-center">
      <ActivatePageView
        error={error}
        password={password}
        setPassword={setPassword}
        isLoading={isLoading}
        onSubmit={(e) => {
          e.preventDefault();

          setIsLoading(true);
          post("/management/user/activate", {
            email,
            activation_token: router.query["code"],
            new_passphrase: password
          })
            .then((response) => {
              if (response.status === "SUCCESS") {
                router.replace("/");
              } else {
                setError(response.message);
                setIsLoading(false);
              }
            })
            .catch((error) => {
              setError(error.message);
              setIsLoading(false);
            });
        }}
      />
    </div>
  );
};

export default ActivatePage;
