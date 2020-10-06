import React, { useContext } from "react";
import { UserType } from "../../../data/use-get-users";
import { useLocale } from "../../locales";
import { PageBody } from "../../page";
import { ResourcesListProps } from "..";
import Table from "../../table";
import Select from "../../select";
import Link from "next/link";
import { useUser } from "../../../data/user";

const headers = ["email"];

interface UsersPageViewProps {
  users: Array<UserType>;
}

export const UsersPageView = ({ users }: UsersPageViewProps) => {
  return (
    <PageBody>
      <UsersList
        headers={headers}
        rows={users}
        onChangeRow={(row, key, value) => {
          console.log({
            row,
            key,
            value
          });
        }}
      />
    </PageBody>
  );
};

export const UsersList = ({
  headers,
  rows: users,
  onChangeRow
}: ResourcesListProps<UserType>) => {
  const user = useUser();
  const { strings } = useLocale();
  return (
    <Table
      headers={headers.map((h) => ({
        title: strings(h),
        key: h
      }))}
      rows={users}
      colFunc={(row, col, rowObj, headerObj) => {
        if (headerObj.key === "enabled" || headerObj.key === "suspended") {
          return (
            <Select
              disabled={rowObj["rec_id"] === user.rec_id}
              value={rowObj[headerObj.key]}
              options={[
                {
                  title: strings("yes"),
                  value: true
                },
                {
                  title: strings("no"),
                  value: false
                }
              ]}
              onChange={(event) => {
                onChangeRow(rowObj, headerObj.key, event.target.value);
              }}
            />
          );
        }

        if (headerObj.key === "email") {
          return (
            <Link href={`/dashboard/users/${rowObj["rec_id"]}/edit`}>
              <a className="underline">{rowObj[headerObj.key]}</a>
            </Link>
          );
        }
        return rowObj[headerObj.key];
      }}
    />
  );
};
