import React from "react";
import { useRouter } from "next/router";
import DashboardLayout from "../../../components/dashboard-layout";
import { StatefulChangePasswordView } from "../change-password";

const ChangePasswordPage = () => {
  const router = useRouter();
  return (
    <DashboardLayout>
      <StatefulChangePasswordView
        returnPath={router.pathname.replace("change-password", "")}
      />
    </DashboardLayout>
  );
};

export default ChangePasswordPage;
