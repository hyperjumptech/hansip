import React, { useContext } from "react";
import SplitPanel from "./split-panel";
import SideBar, { MobileMenuBar } from "./sidebar";
import { sidebarItems } from "./menu-items";
import DesktopHeader from "./header";
import { useLocale } from "./locales";

export default function DashboardLayout({ children }) {
  const { strings } = useLocale();
  const sidebarItemsToUse = sidebarItems.map((s) => ({
    ...s,
    title: s ? strings(s.title) : ""
  }));

  return (
    <SplitPanel
      sideBar={<SideBar rows={sidebarItemsToUse} />}
      mobileMenuBar={<MobileMenuBar rows={sidebarItemsToUse} />}
      desktopHeader={<DesktopHeader />}>
      <div className="w-full overflow-x-hidden border-t flex flex-col ">
        <main
          className="w-full flex-grow p-6 "
          style={{ minHeight: "calc(100vh - 110px)" }}>
          {children}
        </main>
      </div>
    </SplitPanel>
  );
}
