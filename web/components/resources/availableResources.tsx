import useGetUsers, { useGetUser } from "../../data/use-get-users";
import useGetRoles, { useGetRole } from "../../data/use-get-roles";
import useGetGroups, { useGetGroup } from "../../data/use-get-groups";
import { UsersPageView } from "./list/users";
import { GroupsPageView } from "./list/groups";
import { RolesPageView } from "./list/roles";
import UserForm from "./form/user";
import RoleForm from "./form/role";
import GroupForm from "./form/group";
import { DataPagingQueryType } from "../../data/fetcher";

export enum Resource {
  USERS = "users",
  ROLES = "roles",
  GROUPS = "groups"
}
export type ResourceType = {
  components: {
    list: React.ElementType;
    form: React.ElementType;
  };
  dataKey: string;
  useDataList: (query: DataPagingQueryType) => any;
  useDataSingle: (resourceId?: string) => any;
  orders: Array<string>;
  uneditableKeys: Array<string>;
};
type AvailableResourcesType = Record<Resource, ResourceType>;

export const availableResources: AvailableResourcesType = {
  users: {
    components: {
      list: UsersPageView,
      form: UserForm
    },
    dataKey: "users",
    useDataList: useGetUsers,
    useDataSingle: useGetUser,
    orders: ["email", "last_seen", "last_login"],
    uneditableKeys: ["enabled_2fa", "last_seen", "last_login", "email"]
  },
  roles: {
    components: {
      list: RolesPageView,
      form: RoleForm
    },
    dataKey: "roles",
    useDataList: useGetRoles,
    useDataSingle: useGetRole,
    orders: ["role_name"],
    uneditableKeys: []
  },
  groups: {
    components: {
      list: GroupsPageView,
      form: GroupForm
    },
    dataKey: "groups",
    useDataList: useGetGroups,
    useDataSingle: useGetGroup,
    orders: ["group_name"],
    uneditableKeys: []
  }
};
