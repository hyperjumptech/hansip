import React from "react";
import { SortOption } from "../data/fetcher";
import { UsersPageView } from "../components/resources/list/users";

export default { title: "Pages/Users" };

export const usersList = () => {
  const props = {
    strings: require("../components/locales/en.json"),
    users: require("../data/samples/resources/users.json"),
    page: 1,
    order: "last_seen",
    sort: "DESC" as SortOption,
    onChangeOrder: () => {},
    onChangeSort: () => {}
  };
  return <UsersPageView {...props} />;
};
