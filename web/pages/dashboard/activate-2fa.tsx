import React, { useState, useEffect } from "react";
import CenteredLayout from "../../components/centered-layout";
import { useLocale } from "../../components/locales";
import { LabelInput } from "../../components/label-input";
import { useRouter } from "next/router";
import Link from "next/link";
import { get, post } from "../../data/requests";
import { qrcodeImageFromResponse } from "../../data/qrcode";

export const Activate2FAView = ({
  otp,
  setOtp,
  isLoading,
  error,
  onSubmit,
  image,
  returnPath
}) => {
  const { strings } = useLocale();
  return (
    <div className="flex flex-col">
      <h1 className="block text-4xl font-bold mb-4">{strings("enable-2fa")}</h1>
      {error && <div className="p-2 text-white bg-red-600">{error}</div>}
      <p>{strings("2fa-scan-info")}</p>
      <img className="my-4 w-48 self-center" src={image} />
      <p>{strings("2fa-enter-otp-info")}</p>
      <form onSubmit={onSubmit}>
        <LabelInput
          id="otp"
          labelText={""}
          inputType="text"
          placeholder={strings("otp")}
          value={otp}
          disabled={isLoading}
          onChange={(e) => setOtp(e.target.value)}
        />

        <div className=" mt-4 flex flex-row justify-between items-center">
          <button type="submit" className="btn-blue" disabled={isLoading}>
            {strings("send")}
          </button>
          <Link href={returnPath}>
            <a className="btn-blue-underline ">{strings("cancel")}</a>
          </Link>
        </div>
      </form>
    </div>
  );
};

export const SaveBackupCodesView = ({ backupCodes, onCloseClick }) => {
  const { strings } = useLocale();
  return (
    <div className="flex flex-col">
      <h1 className="block text-4xl font-bold mb-4">
        {strings("2fa-recovery-codes")}
      </h1>
      <div className="rounded bg-yellow-200 p-4 mb-4 ">
        {backupCodes.split(" ").map((b) => {
          return (
            <span key={b} className="mr-4">
              {`${b} `}
            </span>
          );
        })}
      </div>
      <ul className="ml-4 mb-4 list-disc list-outside">
        <li>{strings("2fa-recovery-codes-info-1")}</li>
        <li>{strings("2fa-recovery-codes-info-2")}</li>
        <li>
          <strong>{strings("2fa-recovery-codes-info-3")}</strong>
        </li>
      </ul>
      <button onClick={onCloseClick} type="button" className="btn-blue">
        {strings("2fa-close")}
      </button>
    </div>
  );
};

interface StatefulActivate2FAViewProps {
  returnPath?: string;
}
export const StatefulActivate2FAView = ({
  returnPath = "/dashboard"
}: StatefulActivate2FAViewProps) => {
  const router = useRouter();
  const { strings } = useLocale();
  const [otp, setOtp] = useState("");
  const [backupCodes, setBackupCodes] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [image, setImage] = useState("");

  useEffect(() => {
    // fetch qr code image
    get("/management/user/2FAQR", null, null, (response) => {
      return qrcodeImageFromResponse(response);
    })
      .then(setImage)
      .catch((err) => setError(err.message));
  }, []);

  return (
    <>
      {backupCodes && (
        <SaveBackupCodesView
          backupCodes={backupCodes}
          onCloseClick={(e) => {
            e.preventDefault();
            if (confirm(strings("2fa-close-prompt"))) {
              router.push(returnPath);
            }
          }}
        />
      )}
      {!backupCodes && (
        <Activate2FAView
          returnPath={returnPath}
          image={image}
          otp={otp}
          setOtp={setOtp}
          isLoading={isLoading}
          error={error}
          onSubmit={(e) => {
            e.preventDefault();

            setIsLoading(true);

            post("/management/user/activate2FA", {
              "2FA_token": otp
            })
              .then((response) => {
                if (response.status === "SUCCESS") {
                  setBackupCodes(response.data["2FA_recovery_codes"].join(" "));
                } else {
                  setError(response["message"]);
                }
                setIsLoading(false);
              })
              .catch((error) => {
                setError(error);
              });
          }}
        />
      )}
    </>
  );
};

const Activate2FAPage = () => {
  return (
    <CenteredLayout>
      <StatefulActivate2FAView />
    </CenteredLayout>
  );
};

export default Activate2FAPage;
