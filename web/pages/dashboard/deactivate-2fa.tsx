import Link from "next/link";
import { useRouter } from "next/router";
import React, { useState } from "react";
import CenteredLayout from "../../components/centered-layout";
import { LabelInput } from "../../components/label-input";
import { useLocale } from "../../components/locales";
import { post } from "../../data/requests";
import { UserType } from "../../data/use-get-users";
import { refreshMe, useUser } from "../../data/user";

const Deactivate2FAView = ({
  password,
  setPassword,
  error,
  isLoading,
  returnPath,
  onSubmit
}) => {
  const { strings } = useLocale();
  return (
    <>
      <h1 className="block text-4xl font-bold mb-4">
        {strings("disable-2fa")}
      </h1>
      <p className="mb-4">{strings("disable-2fa-prompt")}</p>
      <form onSubmit={onSubmit}>
        <LabelInput
          id="password"
          labelText={strings("password")}
          inputType="password"
          placeholder={strings("password")}
          value={password}
          disabled={isLoading}
          error={error}
          onChange={(e) => setPassword(e.target.value)}
        />
        <div className=" mt-4 flex flex-row justify-between items-center">
          <button type="submit" className="btn-blue" disabled={isLoading}>
            {strings("save")}
          </button>
          <Link href={returnPath}>
            <a className="btn-blue-underline ">{strings("cancel")}</a>
          </Link>
        </div>
      </form>
    </>
  );
};

interface StatefulDeactivate2FAViewProps {
  returnPath?: string;
  user: UserType;
}
export const StatefulDeactivate2FAView = ({
  returnPath = "/dashboard",
  user
}: StatefulDeactivate2FAViewProps) => {
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const router = useRouter();
  const { strings } = useLocale();

  return (
    <Deactivate2FAView
      returnPath={returnPath}
      password={password}
      setPassword={setPassword}
      error={error}
      isLoading={isLoading}
      onSubmit={(e) => {
        e.preventDefault();
        if (confirm(strings("disable-2fa-prompt"))) {
          setIsLoading(true);
          post("/auth/authenticate", {
            email: user.email,
            passphrase: password
          }).then((response) => {
            if (response.status === "SUCCESS") {
              return post(
                `/management/user/${user.rec_id}`,
                {
                  email: user.email,
                  enabled: true,
                  suspended: false,
                  enabled_2fa: false
                },
                null,
                "PUT"
              ).then((response) => {
                if (response.status === "SUCCESS") {
                  refreshMe();
                  router.replace(returnPath);
                } else {
                  setError(response.message);
                  setIsLoading(false);
                }
              });
            } else {
              setError(response.message);
              setIsLoading(false);
            }
          });
        }
      }}
    />
  );
};

const Deactivate2FAPage = () => {
  const user = useUser();
  return (
    <CenteredLayout>
      <StatefulDeactivate2FAView user={user} />
    </CenteredLayout>
  );
};

export default Deactivate2FAPage;
