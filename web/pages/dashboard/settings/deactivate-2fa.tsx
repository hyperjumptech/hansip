import { useRouter } from "next/router";
import React from "react";
import DashboardLayout from "../../../components/dashboard-layout";
import { useUser } from "../../../data/user";
import { StatefulDeactivate2FAView } from "../deactivate-2fa";

const Deactivate2FAPage = () => {
  const router = useRouter();
  const user = useUser();
  return (
    <DashboardLayout>
      <StatefulDeactivate2FAView
        user={user}
        returnPath={router.pathname.replace("deactivate-2fa", "")}
      />
    </DashboardLayout>
  );
};

export default Deactivate2FAPage;
