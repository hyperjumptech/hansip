import React, { useContext } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faLock, faKey, faUnlock } from "@fortawesome/free-solid-svg-icons";
import { UserType } from "../../data/use-get-users";
import { useLocale } from "../../components/locales";
import Link from "next/link";
import CenteredLayout from "../../components/centered-layout";
import { useUser } from "../../data/user";
import { useRouter } from "next/router";

interface NonAAAAdminDashboardViewProps {
  user: UserType;
}

const buttonCSS =
  "rounded text-blue-500 shadow flex flex-col space-y-4 items-center py-5 px-2 bg-white";

interface SettingsButtonsProps {
  user: UserType;
}
export const SettingsButtons = ({ user }: SettingsButtonsProps) => {
  const { strings } = useLocale();
  return (
    <div className="grid grid-cols-2 gap-2">
      <Link href={`/dashboard/settings/change-password`}>
        <a type="button" className={buttonCSS}>
          <FontAwesomeIcon icon={faKey} />
          <span>{strings("change-password")}</span>
        </a>
      </Link>
      <Link
        href={
          user["enabled_2fa"]
            ? `/dashboard/settings/deactivate-2fa`
            : `/dashboard/settings/activate-2fa`
        }>
        <a type="button" className={buttonCSS}>
          <FontAwesomeIcon icon={user["enabled_2fa"] ? faUnlock : faLock} />
          <span>
            {strings(user["enabled_2fa"] ? "disable-2fa" : "enable-2fa")}
          </span>
        </a>
      </Link>
    </div>
  );
};

export const NonAAAAdminDashboardView = ({
  user
}: NonAAAAdminDashboardViewProps) => {
  const { strings } = useLocale();
  return (
    <CenteredLayout>
      <h1 className="block text-4xl font-bold mb-4">{strings("settings")}</h1>
      <SettingsButtons user={user} />
    </CenteredLayout>
  );
};

const DashboardPage = () => {
  const user = useUser();
  const router = useRouter();

  if (user) {
    router.replace("/dashboard/users/list");
    return null;
  }
  return null;
};

export default DashboardPage;
