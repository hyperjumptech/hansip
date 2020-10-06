import React, { useContext } from "react";
import { useLocale } from "../../locales";
import { PageBody } from "../../page";
import { ResourcesListProps } from "..";
import Table from "../../table";
import { RoleType } from "../../../data/use-get-roles";
import Link from "next/link";

const headers = ["role_name", "description"];

interface RolesPageViewProps {
  roles: Array<RoleType>;
}

export const RolesPageView = ({ roles }: RolesPageViewProps) => {
  return (
    <PageBody>
      <RolesList headers={headers} rows={roles} />
    </PageBody>
  );
};

export const RolesList = ({
  headers,
  rows: roles,
  onChangeRow
}: ResourcesListProps<RoleType>) => {
  const { strings } = useLocale();
  return (
    <Table
      headers={headers.map((h) => ({
        title: strings(h),
        key: h
      }))}
      rows={roles}
      colFunc={(row, col, rowObj, headerObj) => {
        return (
          <Link href={`/dashboard/roles/${rowObj["rec_id"]}/edit`}>
            <a>{rowObj[headerObj.key]}</a>
          </Link>
        );
      }}
    />
  );
};
