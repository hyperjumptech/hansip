import React from "react";
import DesktopHeader from "./header";

const CenteredLayout = ({ children }) => {
  return (
    <div className="w-full h-screen bg-gradient">
      <DesktopHeader showLogo={true} />
      <div className="w-full flex flex-col justify-center items-center mt-4 ">
        <div className="max-w-md w-full bg-white p-4 rounded-md">
          {children}
        </div>
      </div>
    </div>
  );
};

export default CenteredLayout;
