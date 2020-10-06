import React from "react";

import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faCogs,
  faUser,
  faUserFriends,
  faUserTie
} from "@fortawesome/free-solid-svg-icons";
import { RowItem } from "./sidebar";

export const sidebarItems: Array<RowItem> = [
  {
    href: "/dashboard/[resource]/list",
    as: "/dashboard/users/list",
    title: "users",
    icon: <FontAwesomeIcon icon={faUser} fixedWidth />
  },
  {
    href: "/dashboard/[resource]/list",
    as: "/dashboard/groups/list",
    title: "groups",
    icon: <FontAwesomeIcon icon={faUserFriends} fixedWidth />
  },
  {
    href: "/dashboard/[resource]/list",
    as: "/dashboard/roles/list",
    title: "roles",
    icon: <FontAwesomeIcon icon={faUserTie} fixedWidth />
  }
];
