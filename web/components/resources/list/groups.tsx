import React, { useContext } from "react";
import { SortOption } from "../../../data/fetcher";
import { useLocale } from "../../locales";
import { PageBody } from "../../page";
import { ResourcesListProps } from "..";
import Table from "../../table";
import { GroupType } from "../../../data/use-get-groups";
import Link from "next/link";

const headers = ["group_name", "description"];

interface GroupsPageViewProps {
  groups: Array<GroupType>;
}

export const GroupsPageView = ({ groups }: GroupsPageViewProps) => {
  return (
    <PageBody>
      <GroupsList headers={headers} rows={groups} />
    </PageBody>
  );
};

export const GroupsList = ({
  headers,
  rows: groups,
  onChangeRow
}: ResourcesListProps<GroupType>) => {
  const { strings } = useLocale();
  return (
    <Table
      headers={headers.map((h) => ({
        title: strings(h),
        key: h
      }))}
      rows={groups}
      colFunc={(row, col, rowObj, headerObj) => {
        return (
          <Link href={`/dashboard/groups/${rowObj["rec_id"]}/edit`}>
            <a>{rowObj[headerObj.key]}</a>
          </Link>
        );
      }}
    />
  );
};
