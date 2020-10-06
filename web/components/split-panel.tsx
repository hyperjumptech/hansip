import React, { useState } from "react";

interface SplitPanelProps {
  sideBar: JSX.Element;
  mobileMenuBar: JSX.Element;
  desktopHeader: JSX.Element;
  children: React.ReactNode;
}

export default function SplitPanel({
  sideBar,
  children,
  mobileMenuBar,
  desktopHeader
}: SplitPanelProps) {
  return (
    <>
      {sideBar}

      <div className="w-full flex flex-col h-screen overflow-y-hidden">
        {mobileMenuBar}
        {desktopHeader}
        {children}
      </div>
    </>
  );
}
