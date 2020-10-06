import useSWR from "swr";
import fetcher, { DataPagingType, DataPagingQueryType } from "./fetcher";
import { RoleType } from "./use-get-roles";
import { GroupType } from "./use-get-groups";
import { UserFormInitialData } from "../components/resources/form/user";

export interface UserType {
  rec_id: string;
  email: string;
  enabled: boolean;
  suspended: boolean;
  last_seen: string;
  last_login: string;
  enabled_2fa: boolean;
  access_token?: string;
  refresh_token?: string;
  roles?: Array<RoleType>;
  groups?: Array<GroupType>;
  password?: string;
}

export const EmptyUser: UserType = {
  rec_id: "",
  email: "",
  enabled: true,
  suspended: false,
  last_login: "",
  last_seen: "",
  enabled_2fa: false
  // roles: [
  //   {
  //     rec_id: "",
  //     role_name: "admin@aaa"
  //   }
  // ]
};

export interface GetUsersResult {
  data: null | {
    users: Array<UserType>;
    page: DataPagingType;
  };
  loading: boolean;
  error: Error;
}

const USE_DUMMY_DATA = process.env.NEXT_PUBLIC_USE_DUMMY_DATA;

const sampleUsers = (page: number) => {
  if (USE_DUMMY_DATA !== "true") {
    return null;
  }
  const jsons = [
    require("./samples/api/management/users-1.json"),
    require("./samples/api/management/users-2.json")
  ];

  return jsons[page - 1];
};

const sampleUser = () => {
  if (USE_DUMMY_DATA !== "true") {
    return null;
  }
  return require("./samples/api/management/user-1.json");
};

const sampleUserRoles = () => {
  if (USE_DUMMY_DATA !== "true") {
    return null;
  }
  return require("./samples/api/management/user-1-roles.json");
};

const sampleUserGroups = () => {
  if (USE_DUMMY_DATA !== "true") {
    return null;
  }
  return require("./samples/api/management/user-1-groups.json");
};

const sampleRoles = () => {
  if (USE_DUMMY_DATA !== "true") {
    return null;
  }
  return require("./samples/api/management/roles-1.json");
};

const sampleGroups = () => {
  if (USE_DUMMY_DATA !== "true") {
    return null;
  }
  return require("./samples/api/management/groups-1.json");
};

const useGetUsers = ({
  page_no,
  page_size,
  order_by,
  sort
}: DataPagingQueryType): GetUsersResult => {
  const { data, error } = useSWR(
    ["/management/users", page_no, page_size, order_by, sort],
    (url, page_no, page_size, order_by, sort) => {
      return fetcher(
        url,
        { page_no, page_size, order_by, sort },
        sampleUsers(page_no)
      );
    }
  );

  return {
    data: data ? data.data : null,
    loading: !error && !data,
    error
  };
};

export interface GetUserResult {
  data: null | UserFormInitialData;
  loading: boolean;
  error: Error;
}
export const useGetUser = (userId: string): GetUserResult => {
  const { data: userData, error: userError } = useSWR(
    `/management/user/${userId}`,
    (url) => {
      return fetcher(url, null, sampleUser());
    }
  );
  const { data: userGroupsData, error: groupError } = useSWR(
    `/management/user/${userId}/groups`,
    (url) => {
      return fetcher(
        url,
        { page_no: 1, page_size: 100, order_by: "group_name", sort: "desc" },
        sampleUserGroups()
      );
    }
  );
  const { data: userRolesData, error: roleError } = useSWR(
    `/management/user/${userId}/roles`,
    (url) => {
      return fetcher(
        url,
        { page_no: 1, page_size: 100, order_by: "role_name", sort: "desc" },
        sampleUserRoles()
      );
    }
  );
  const { data: rolesData, error: rolesError } = useSWR(
    `/management/roles`,
    (url) => {
      return fetcher(
        url,
        { page_no: 1, page_size: 100, order_by: "role_name", sort: "desc" },
        sampleRoles()
      );
    }
  );
  const { data: groupsData, error: groupsError } = useSWR(
    `/management/groups`,
    (url) => {
      return fetcher(
        url,
        { page_no: 1, page_size: 100, order_by: "group_name", sort: "desc" },
        sampleGroups()
      );
    }
  );

  const data: UserFormInitialData = {
    user: {
      ...(userData && userData.data ? userData.data : {}),
      roles:
        userRolesData && userRolesData.data ? userRolesData.data.roles : [],
      groups:
        userGroupsData && userGroupsData.data ? userGroupsData.data.groups : []
    },
    roles: rolesData && rolesData.data ? rolesData.data.roles : [],
    groups: groupsData && groupsData.data ? groupsData.data.groups : []
  };

  var error = userError;
  if (!error) error = groupError;
  if (!error) error = roleError;
  if (!error) error = rolesError;
  if (!error) error = groupsError;

  const loading =
    !userError &&
    !groupError &&
    !roleError &&
    !rolesError &&
    !groupsError &&
    (!userData ||
      !userRolesData ||
      !userGroupsData ||
      !rolesData ||
      !groupsData);

  return {
    data:
      userData && userGroupsData && userRolesData && rolesData && groupsData
        ? data
        : null,
    loading,
    error
  };
};

export default useGetUsers;

export const isAAAAdmin = (user: UserType): boolean => {
  return user && user.roles
    ? user.roles.findIndex((r) => r.role_name === "admin@aaa") > -1
    : false;
};
