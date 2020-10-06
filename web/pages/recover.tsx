import { faSpinner } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useRouter } from "next/router";
import React, { useEffect, useState } from "react";
import DesktopHeader from "../components/header";
import { LabelInput } from "../components/label-input";
import { useLocale } from "../components/locales";
import { post } from "../data/requests";

const RecoverPasswordView = ({
  onSubmit,
  isLoading,
  password,
  setPassword,
  error
}) => {
  const { strings } = useLocale();
  return (
    <div>
      <h1 className="block text-4xl font-bold mb-4">
        {strings("update-password")}
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
          labelText={strings("password")}
          inputType="password"
          placeholder=""
          value={password}
          onChange={(e) => {
            setPassword(e.target.value);
          }}
        />
        <button disabled={isLoading} type="submit" className="btn-blue mt-4">
          {isLoading ? (
            <FontAwesomeIcon icon={faSpinner} className="animate-spin" />
          ) : (
            strings("save")
          )}
        </button>
      </form>
    </div>
  );
};

const RecoverPasswordPage = () => {
  const router = useRouter();
  const code = router.query?.code ?? "";
  const { strings } = useLocale();
  const [isLoading, setIsLoading] = useState(false);
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);

  return (
    <div className="bg-gradient w-full h-screen flex flex-col  items-center">
      <DesktopHeader />
      <div className="w-full max-w-md mt-4 ">
        <div className="  bg-white p-4 rounded-md mx-4 shadow-lg">
          {!code && <p>{strings("recovery-link-error")}</p>}
          {code && (
            <RecoverPasswordView
              {...{
                error,
                password,
                setPassword,
                onSubmit: (e) => {
                  e.preventDefault();
                  setIsLoading(true);
                  post("/recovery/resetPassphrase", {
                    passphraseResetToken: code,
                    newPassphrase: password
                  }).then((response) => {
                    if (response.status === "SUCCESS") {
                      alert(strings("password-reseted"));
                      router.replace("/");
                    } else {
                      setError(response.message);
                      setIsLoading(false);
                    }
                  });
                },
                isLoading
              }}
            />
          )}
        </div>
      </div>
    </div>
  );
};

export default RecoverPasswordPage;
