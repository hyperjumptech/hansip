import { useRouter } from "next/router";
import React from "react";
import DashboardLayout from "../../../components/dashboard-layout";
import { StatefulActivate2FAView } from "../activate-2fa";

const Activate2FAPage = () => {
  const router = useRouter();
  return (
    <DashboardLayout>
      <StatefulActivate2FAView
        returnPath={router.pathname.replace("activate-2fa", "")}
      />
    </DashboardLayout>
  );
};

export default Activate2FAPage;
