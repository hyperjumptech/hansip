import React from "react";
import { SortOption } from "../data/fetcher";
import { RolesPageView } from "../components/resources/list/roles";

export default { title: "Pages/Roles" };

export const rolesList = () => {
  const props = {
    strings: require("../components/locales/en.json"),
    roles: require("../data/samples/resources/roles.json"),
    page: 1,
    order: "last_seen",
    sort: "DESC" as SortOption,
    onChangeOrder: () => {},
    onChangeSort: () => {}
  };
  return <RolesPageView {...props} />;
};
