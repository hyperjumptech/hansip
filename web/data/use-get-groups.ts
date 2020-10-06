import useSWR from "swr";
import { GroupFormInitialData } from "../components/resources/form/group";
import fetcher, { DataPagingType, DataPagingQueryType } from "./fetcher";
import { RoleType } from "./use-get-roles";

export interface GroupType {
  rec_id: string;
  group_name: string;
  description?: string;
  roles?: Array<RoleType>;
}

export const EmptyGroup: GroupType = {
  rec_id: "",
  group_name: "",
  description: "",
  roles: []
};

export interface GetGroupsResult {
  data: null | {
    groups: Array<GroupType>;
    page: DataPagingType;
  };
  loading: boolean;
  error: Error;
}

const USE_DUMMY_DATA = process.env.NEXT_PUBLIC_USE_DUMMY_DATA;

const sampleGroups = (page: number) => {
  if (USE_DUMMY_DATA !== "true") {
    return null;
  }
  const jsons = [
    require("./samples/api/management/groups-1.json"),
    require("./samples/api/management/groups-2.json")
  ];

  return jsons[page - 1];
};

const sampleGroup = () => {
  if (USE_DUMMY_DATA !== "true") {
    return null;
  }
  return require("./samples/api/management/group-1.json");
};

const useGetGroups = ({
  page_no,
  page_size,
  order_by,
  sort
}: DataPagingQueryType): GetGroupsResult => {
  const { data, error } = useSWR(
    ["/management/groups", page_no, page_size, order_by, sort],
    (url, page_no, page_size, order_by, sort) => {
      return fetcher(
        url,
        {
          page_no,
          page_size,
          order_by,
          sort
        },
        sampleGroups(page_no)
      );
    }
  );

  return {
    data: data ? data.data : null,
    loading: !error && !data,
    error
  };
};

export interface GetGroupResult {
  data: null | GroupFormInitialData;
  loading: boolean;
  error: Error;
}
export const useGetGroup = (groupId: string): GetGroupResult => {
  const {
    data: groupData,
    error: groupError
  } = useSWR(`/management/group/${groupId}`, (url) =>
    fetcher(url, null, sampleGroup())
  );
  const { data: groupRolesData, error: roleError } = useSWR(
    `/management/group/${groupId}/roles`,
    (url) => {
      return fetcher(url, null, null);
    }
  );
  const { data: rolesData, error: rolesError } = useSWR(
    `/management/roles`,
    (url) => {
      return fetcher(
        url,
        { page_no: 1, page_size: 100, order_by: "role_name", sort: "desc" },
        null
      );
    }
  );
  const data: GroupFormInitialData = {
    group: {
      ...(groupData && groupData.data ? groupData.data : {}),
      roles:
        groupRolesData && groupRolesData.data ? groupRolesData.data.roles : []
    },

    roles: rolesData && rolesData.data ? rolesData.data.roles : []
  };

  var error = groupError;
  if (!error) error = rolesError;
  if (!error) error = roleError;

  const loading =
    !groupError &&
    !roleError &&
    !rolesError &&
    (!groupData || !rolesData || !groupRolesData);

  return {
    data: groupData && rolesData && groupRolesData ? data : null,
    loading,
    error
  };
};

export default useGetGroups;
