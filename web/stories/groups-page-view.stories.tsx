import React from "react";
import { SortOption } from "../data/fetcher";
import { GroupsPageView } from "../components/resources/list/groups";

export default { title: "Pages/Groups" };

export const groupsList = () => {
  const props = {
    strings: require("../components/locales/en.json"),
    groups: require("../data/samples/resources/groups.json"),
    page: 1,
    order: "last_seen",
    sort: "DESC" as SortOption,
    onChangeOrder: () => {},
    onChangeSort: () => {}
  };
  return <GroupsPageView {...props} />;
};
