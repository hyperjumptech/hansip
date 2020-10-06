import React, { useEffect } from "react";
import { setTokenFromResponse } from "../data/user";

const LogoutPage = () => {
  useEffect(() => {
    setTokenFromResponse(null);
  }, []);
  return <div></div>;
};

export default LogoutPage;
