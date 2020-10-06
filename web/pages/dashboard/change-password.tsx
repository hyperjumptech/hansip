import React, { useContext, useState, useEffect } from "react";
import { useLocale } from "../../components/locales";
import { LabelInput } from "../../components/label-input";
import CenteredLayout from "../../components/centered-layout";
import Link from "next/link";
import { PageTitle } from "../../components/page";
import { useRouter } from "next/router";
import { post } from "../../data/requests";
import { useUser } from "../../data/user";

interface ChangePasswordViewProps {
  isLoading: boolean;
  formState: {
    oldPassword: string;
    newPassword: string;
    repeatNewPassword: string;
  };
  errors?: {
    oldPassword: string;
    newPassword: string;
    repeatNewPassword: string;
  };
  error?: string;
  setFormState: (key: string, value: string) => void;
  onSubmit: () => void;
  returnPath?: string;
}
const ChangePasswordView = ({
  isLoading,
  formState: { oldPassword, newPassword, repeatNewPassword },
  errors,
  error,
  setFormState,
  onSubmit,
  returnPath
}: ChangePasswordViewProps) => {
  const { strings } = useLocale();

  return (
    <>
      <div className="mb-6">
        <PageTitle title={strings("change-password")} />
      </div>
      {error && (
        <div className="text-white bg-red-600 p-4 mb-3 rounded">{error}</div>
      )}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          onSubmit();
        }}>
        <LabelInput
          id="old-password"
          labelText={strings("old-password")}
          inputType="password"
          placeholder={strings("old-password")}
          value={oldPassword}
          disabled={isLoading}
          error={errors ? errors["oldPassword"] : null}
          onChange={(e) => setFormState("oldPassword", e.target.value)}
        />

        <LabelInput
          id="new-password"
          labelText={strings("new-password")}
          inputType="password"
          placeholder={strings("new-password")}
          value={newPassword}
          disabled={isLoading}
          error={errors ? errors["newPassword"] : null}
          onChange={(e) => setFormState("newPassword", e.target.value)}
        />

        <LabelInput
          id="repeat-new-password"
          labelText={strings("repeat-new-password")}
          inputType="password"
          placeholder={strings("repeat-new-password")}
          value={repeatNewPassword}
          disabled={isLoading}
          error={errors ? errors["repeatNewPassword"] : null}
          onChange={(e) => setFormState("repeatNewPassword", e.target.value)}
        />

        <div className=" mt-4 flex flex-row justify-between items-center">
          <button type="submit" className="btn-blue" disabled={isLoading}>
            {strings("save")}
          </button>
          <Link href={returnPath || "/dashboard"}>
            <a className="btn-blue-underline ">{strings("cancel")}</a>
          </Link>
        </div>
      </form>
    </>
  );
};

interface StatefulChangePasswordViewProps {
  returnPath?: string;
}
export const StatefulChangePasswordView = ({
  returnPath = "/dashboard"
}: StatefulChangePasswordViewProps) => {
  const { strings } = useLocale();
  const user = useUser();
  const router = useRouter();

  const [isLoading, setIsLoading] = useState(false);
  const [formState, setFormState] = useState({
    oldPassword: "",
    newPassword: "",
    repeatNewPassword: ""
  });
  const [errors, setErrors] = useState({
    oldPassword: "",
    newPassword: "",
    repeatNewPassword: ""
  });
  const [error, setError] = useState(null);

  useEffect(() => {
    if (
      formState.newPassword.length > 0 &&
      formState.newPassword !== formState.repeatNewPassword
    ) {
      setErrors({
        oldPassword: "",
        newPassword: "",
        repeatNewPassword: strings("new-passwords-mismatch")
      });
    } else {
      setErrors({
        oldPassword: "",
        newPassword: "",
        repeatNewPassword: ""
      });
    }
  }, [formState]);

  return (
    <ChangePasswordView
      returnPath={returnPath}
      isLoading={isLoading}
      formState={formState}
      error={error}
      errors={errors}
      setFormState={(key, val) =>
        setFormState((old) => ({
          ...old,
          [key]: val
        }))
      }
      onSubmit={() => {
        setIsLoading(true);

        post(`/management/user/${user.rec_id}/passwd`, {
          old_passphrase: formState.oldPassword,
          new_passphrase: formState.newPassword
        }).then((res) => {
          if (res["status"] === "SUCCESS") {
            router.push(returnPath);
          } else {
            if (res["httpcode"] === 406) {
              setError(strings("password-reset-error-406"));
            } else {
              setError(res["message"]);
            }
            setIsLoading(false);
          }
        });
      }}
    />
  );
};

const ChangePasswordPage = () => {
  return (
    <CenteredLayout>
      <StatefulChangePasswordView />
    </CenteredLayout>
  );
};

export default ChangePasswordPage;
