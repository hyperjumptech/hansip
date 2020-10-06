import { faArrowLeft, faSpinner } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import React, { useState, FormEvent, useRef } from "react";
import { LabelInput } from "../components/label-input";
import { useLocale } from "../components/locales";
import { post } from "../data/requests";
import { setTokenFromResponse } from "../data/user";

type LoginSignupFormState = "login" | "forgot" | "reset" | "2fa" | "backupCode";

const LoginSignupFormStates = {
  login: {
    title: "login",
    submitButton: "login",
    secondaryButton: "forgot-password",
    info: "",
    backButton: "",
    previousState: "",
    secondaryState: "forgot"
  },
  "2fa": {
    title: "login-confirmation",
    submitButton: "send",
    secondaryButton: "2fa-no-authenticator",
    info: "2fa-info",
    backButton: "back-to-login",
    previousState: "login",
    secondaryState: "backupCode"
  },
  backupCode: {
    title: "login-with-backup",
    submitButton: "send",
    backButton: "2fa-have-authenticator",
    info: "2fa-backup-info",
    secondaryButton: "",
    previousState: "2fa",
    secondaryState: ""
  },
  forgot: {
    title: "forgot-password",
    submitButton: "send",
    backButton: "back-to-login",
    info: "forgot-password-info",
    secondaryButton: "",
    previousState: "login",
    secondaryState: ""
  },
  reset: {
    title: "reset-password",
    submitButton: "reset",
    backButton: "back-to-login",
    info: "reset-password-info",
    secondaryButton: "",
    previousState: "login",
    secondaryState: ""
  }
};

interface LoginSignupFormData {
  email: string;
  password: string;
  resetToken: string;
  otp: string;
}

interface LoginSignupFormViewProps {
  formState: LoginSignupFormState;
  data: LoginSignupFormData;
  message: string;
  errorMessage: string;
  isLoading: boolean;
  onDataChange: (key: string, value: string) => void;
  errors?: any;
  onFormSubmit: (event: FormEvent) => void;
  goToPreviousState: () => void;
  onClickSecondaryButton: () => void;
}

const LoginSignupFormView = ({
  formState,
  message,
  errorMessage,
  isLoading,
  data: { email, password, resetToken, otp },
  errors,
  onDataChange,
  onFormSubmit,
  goToPreviousState,
  onClickSecondaryButton
}: LoginSignupFormViewProps) => {
  const { strings } = useLocale();
  return (
    <div className="w-full max-w-md ">
      <div className="  bg-white p-4 rounded-md mx-4 shadow-lg">
        <h1 className="block text-4xl font-bold mb-4">
          {strings(LoginSignupFormStates[formState].title)}
        </h1>
        {message && (
          <div className="w-full rounded-md bg-yellow-300 p-4">{message}</div>
        )}
        {errorMessage && (
          <div className="w-full rounded-md bg-red-400 text-white p-4">
            {errorMessage}
          </div>
        )}
        {LoginSignupFormStates[formState].info && (
          <div className="text-sm">
            {strings(LoginSignupFormStates[formState].info)}
          </div>
        )}
        <form onSubmit={onFormSubmit}>
          {formState !== "reset" &&
            formState !== "2fa" &&
            formState !== "backupCode" && (
              <LabelInput
                className="mt-6"
                id="email"
                disabled={isLoading}
                labelText={strings("email-address")}
                inputType="email"
                placeholder="admin@hansip"
                value={email}
                onChange={(e) => {
                  onDataChange("email", e.target.value);
                }}
              />
            )}

          {formState === "reset" && (
            <LabelInput
              className="mt-6"
              id="token"
              disabled={isLoading}
              labelText={strings("reset-code")}
              inputType="text"
              placeholder="ABCD"
              value={resetToken}
              onChange={(e) => {
                onDataChange("resetToken", e.target.value);
              }}
            />
          )}

          {(formState === "2fa" || formState === "backupCode") && (
            <LabelInput
              className="mt-6"
              id="otp"
              disabled={isLoading}
              labelText={strings(
                formState === "2fa" ? "otp" : "2fa-recovery-codes"
              )}
              inputType="text"
              placeholder="123456"
              value={otp}
              onChange={(e) => {
                onDataChange("otp", e.target.value);
              }}
            />
          )}

          {formState !== "forgot" &&
            formState !== "2fa" &&
            formState !== "backupCode" && (
              <LabelInput
                className="mt-6"
                id="password"
                disabled={isLoading}
                labelText={
                  formState === "reset"
                    ? strings("new-password")
                    : strings("password")
                }
                inputType="password"
                placeholder={strings("password-placeholder")}
                value={password}
                onChange={(e) => {
                  onDataChange("password", e.target.value);
                }}
              />
            )}
          <div className="mt-6 flex flex-row justify-between items-center">
            <button disabled={isLoading} type="submit" className="btn-blue">
              {isLoading ? (
                <FontAwesomeIcon icon={faSpinner} className="animate-spin" />
              ) : (
                strings(LoginSignupFormStates[formState].submitButton)
              )}
            </button>
            {LoginSignupFormStates[formState].secondaryButton && (
              <button
                disabled={isLoading}
                onClick={onClickSecondaryButton}
                className="btn-blue-underline text-right"
                type="button">
                {strings(LoginSignupFormStates[formState].secondaryButton)}
              </button>
            )}
          </div>
        </form>
      </div>
      {LoginSignupFormStates[formState].backButton && (
        <div className="mt-6 flex flex-row justify-between text-white mx-4">
          <button
            disabled={isLoading}
            onClick={goToPreviousState}
            className="btn-blue-underline text-white"
            type="button">
            <FontAwesomeIcon icon={faArrowLeft} className="mr-2" />
            {strings(LoginSignupFormStates[formState].backButton)}
          </button>
        </div>
      )}
    </div>
  );
};

const initialFormData: LoginSignupFormData = {
  email: "",
  password: "",
  resetToken: "",
  otp: ""
};

export default function IndexPage() {
  const [data, setData] = useState(initialFormData);
  const [formState, setFormState] = useState<LoginSignupFormState>("login");
  const [errors, setErrors] = useState(null);
  const [message, setMessage] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const twofaToken = useRef("");
  const { strings } = useLocale();

  return (
    <div className="bg-gradient w-full h-screen flex flex-col justify-center items-center">
      <LoginSignupFormView
        errorMessage={errorMessage}
        message={message}
        isLoading={isLoading}
        errors={errors}
        formState={formState}
        data={data}
        onDataChange={(key, val) => {
          setData((dat) => ({
            ...dat,
            [key]: val
          }));
        }}
        onFormSubmit={(event) => {
          event.preventDefault();
          setErrorMessage(null);
          setMessage(null);
          setErrors(null);
          setIsLoading(true);

          if (formState === "login") {
            post(`/auth/authenticate`, {
              email: data.email,
              passphrase: data.password
            })
              .then((response) => {
                if (response["status"] === "FAIL") {
                  setErrorMessage(response["message"]);
                } else {
                  console.log(response);
                  if (response.httpcode === 202) {
                    setFormState("2fa");
                    twofaToken.current = response.data["2FA_token"];
                  } else {
                    if (response["data"]) {
                      setTokenFromResponse(response);
                    }
                  }
                }
                setIsLoading(false);
              })
              .catch((err) => {
                console.log(err);
                setIsLoading(false);
              });
          } else if (formState === "2fa" || formState === "backupCode") {
            setIsLoading(true);

            const pathname =
              formState === "2fa" ? "/auth/2fa" : "/auth/authenticate2fa";
            const body =
              formState === "2fa"
                ? { "2FA_token": twofaToken.current, "2FA_otp": data.otp }
                : {
                    email: data.email,
                    passphrase: data.password,
                    "2FA_recovery_code": data.otp
                  };
            post(pathname, body)
              .then((response) => {
                if (response.status === "SUCCESS") {
                  setTokenFromResponse(response);
                } else {
                  setErrorMessage(response["message"]);
                }
                setIsLoading(false);
              })
              .catch((err) => {
                setIsLoading(false);
              });
          } else if (formState === "forgot") {
            setIsLoading(true);
            post("/recovery/recoverPassphrase", {
              email: data.email
            }).then(() => {
              setMessage(strings("password-recovery-email-sent"));
              setData(initialFormData);
              setFormState("login");
              setIsLoading(false);
            });
          }
        }}
        goToPreviousState={() =>
          setFormState(
            LoginSignupFormStates[formState]
              .previousState as LoginSignupFormState
          )
        }
        onClickSecondaryButton={() => {
          setFormState(
            LoginSignupFormStates[formState]
              .secondaryState as LoginSignupFormState
          );
        }}
      />
    </div>
  );
}
