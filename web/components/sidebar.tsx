import React, { useState, ReactNode } from "react";
import { useRouter } from "next/router";
import Link from "next/link";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faBars, faTimes } from "@fortawesome/free-solid-svg-icons";
import SiteConfig from "./site-config";

export interface RowItem {
  href: string;
  as: string;
  title: string;
  icon: ReactNode;
  indent?: number;
}
type SelectorFunction = (row: RowItem, index?: number) => boolean;
interface SideBarProps {
  rows: Array<RowItem>;
  selected?: SelectorFunction;
}

const useRouterForSelectedMenu = (
  defaultSelector: SelectorFunction
): SelectorFunction => {
  const router = useRouter();

  if (defaultSelector) return defaultSelector;

  return (row: RowItem, index?: number): boolean => {
    return router.asPath.indexOf(row.as) === 0;
  };
};

const RowNavItem = ({ row, isActive, isMobile = false }) => {
  if (!row.href || row.href.length === 0) {
    return (
      <div
        className={`flex items-center text-white py-2 pl-6  text-opacity-75`}>
        <span className={`pr-2 pl-${row.indent}`}>{row.icon}</span>
        {row.title}
      </div>
    );
  }
  return (
    <Link href={row.href} as={row.as}>
      <a
        className={`flex items-center ${
          isActive ? "active-nav-link" : ""
        } text-white ${isMobile ? "py-2 pl-4" : "py-2 pl-6"}  nav-item`}>
        <span className={`pr-2 pl-${row.indent}`}>{row.icon}</span>
        {row.title}
      </a>
    </Link>
  );
};

export default function SideBar({ rows = [], selected }: SideBarProps) {
  const selectedToUse = useRouterForSelectedMenu(selected);

  return (
    <aside className="relative bg-gradient h-screen w-64 hidden sm:block shadow-xl">
      <div className="p-6">
        <a
          href="index.html"
          className="text-white text-3xl font-semibold uppercase hover:text-gray-300">
          {SiteConfig.title}
        </a>
      </div>
      <nav className="text-white text-base font-semibold pt-3">
        {rows.map((row, i) => {
          return (
            <RowNavItem
              row={row}
              key={i}
              isActive={selectedToUse(row, i)}
              isMobile={false}
            />
          );
        })}
      </nav>
    </aside>
  );
}

export function MobileMenuBar({ rows = [], selected }: SideBarProps) {
  const selectedToUse = useRouterForSelectedMenu(selected);
  const [isOpen, setIsOpen] = useState(false);
  return (
    <header className="w-full bg-gradient py-5 px-6 sm:hidden">
      <div className="flex items-center justify-between">
        <a
          href="index.html"
          className="text-white text-3xl font-semibold uppercase hover:text-gray-300">
          Admin
        </a>
        <button
          onClick={() => {
            setIsOpen((isOpen) => !isOpen);
          }}
          className="text-white text-3xl focus:outline-none">
          <FontAwesomeIcon icon={isOpen ? faTimes : faBars} />
        </button>
      </div>

      <nav className={`flex flex-col pt-4 ${isOpen ? "" : "hidden"}`}>
        {rows.map((row, i) => {
          return (
            <RowNavItem
              row={row}
              key={i}
              isActive={selectedToUse(row, i)}
              isMobile={true}
            />
          );
        })}
      </nav>
    </header>
  );
}
