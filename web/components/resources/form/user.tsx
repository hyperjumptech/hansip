import React, { useState, useContext, FormEvent } from "react";
import { UserType, EmptyUser } from "../../../data/use-get-users";
import { useLocale } from "../../locales";
import Select from "../../select";
import { LabelInput } from "../../label-input";
import { RoleType } from "../../../data/use-get-roles";
import { GroupType } from "../../../data/use-get-groups";
import { generateRandomPassword, useUser } from "../../../data/user";
import { post } from "../../../data/requests";
import { useRouter } from "next/router";
import SaveDeleteButtons from "./components/save-delete-buttons";

interface UserFormViewProps {
  user: UserType;
  onChange: (key: string, value: any) => void;
  onSubmit: (e: FormEvent) => void;
  onDelete: (e: FormEvent) => void;
  isEdit: boolean;
  roles?: Array<RoleType>;
  groups?: Array<GroupType>;
  userRoles?: Array<RoleType>;
  userGroups?: Array<GroupType>;
  isLoading: boolean;
  error?: string;
}
const UserFormView = ({
  user,
  onChange,
  onSubmit,
  isEdit,
  roles,
  groups,
  isLoading,
  error,
  onDelete
}: UserFormViewProps) => {
  const { strings } = useLocale();
  const loggedInUser = useUser();
  return (
    <form onSubmit={onSubmit} className="resource-form">
      {error && <div className="error-box">{error}</div>}

      <LabelInput
        id="name"
        disabled={isEdit || isLoading}
        value={user.email || "  "}
        inputType="email"
        labelText={strings("email")}
        placeholder="youremail@hansip.com"
        onChange={(e) => onChange("email", e.target.value)}
      />

      {!isEdit && (
        <LabelInput
          id="password"
          disabled={isEdit || isLoading}
          value={user.password}
          inputType="text"
          labelText={strings("password")}
          placeholder=""
          onChange={(e) => onChange("password", e.target.value)}
        />
      )}

      {isEdit &&
        ["suspended"].map((key, i) => {
          return (
            <div className="mb-4" key={i}>
              <label
                className="block text-gray-700 text-sm font-bold mb-2"
                htmlFor={key}>
                {strings(key)}
              </label>
              <Select
                disabled={loggedInUser.rec_id === user.rec_id}
                value={user[key]}
                options={[true, false].map((o) => ({
                  title: strings(o ? "yes" : "no"),
                  value: o
                }))}
                onChange={(e) => onChange(key, e.target.value === "true")}
              />
            </div>
          );
        })}

      <label
        className="block text-gray-700 text-sm font-bold mb-2"
        htmlFor="roles">
        {`${strings("roles")} ${
          user.roles && user.roles.length > 0 ? `(${user.roles.length})` : "(0)"
        }`}
      </label>

      <div className="mb-4">
        {roles
          .sort((a, b) => {
            if (a.rec_id < b.rec_id) return 1;
            else if (a.rec_id > b.rec_id) return -1;
            return 0;
          })
          .map((r, i) => {
            return (
              <div key={r.rec_id}>
                <input
                  type="checkbox"
                  id={`role-${i}`}
                  name={`role-${i}`}
                  className="mr-2"
                  checked={
                    user.roles.filter((ur) => ur.rec_id === r.rec_id).length > 0
                  }
                  onChange={(e) => {
                    var newRoles = [...user.roles];
                    if (e.target.checked) {
                      newRoles.push(r);
                    } else {
                      newRoles = newRoles.filter(
                        (ur) => ur.rec_id !== r.rec_id
                      );
                    }
                    onChange("roles", newRoles);
                  }}
                />
                <label htmlFor={`role-${i}`}>{r.role_name}</label>
              </div>
            );
          })}
      </div>

      <label
        className="block text-gray-700 text-sm font-bold mb-2"
        htmlFor="roles">
        {`${strings("groups")} ${
          user.groups && user.groups.length > 0
            ? `(${user.groups.length})`
            : "(0)"
        }`}
      </label>

      {groups.map((r, i) => {
        return (
          <div key={r.rec_id}>
            <input
              type="checkbox"
              id={`group-${i}`}
              name={`group-${i}`}
              className="mr-2"
              checked={
                user.groups.filter((ur) => ur.rec_id === r.rec_id).length > 0
              }
              onChange={(e) => {
                var newGroups = [...user.groups];
                if (e.target.checked) {
                  newGroups.push(r);
                } else {
                  newGroups = newGroups.filter((ur) => ur.rec_id !== r.rec_id);
                }
                onChange("groups", newGroups);
              }}
            />
            <label htmlFor={`group-${i}`}>{r.group_name}</label>
          </div>
        );
      })}

      <SaveDeleteButtons
        isLoading={isLoading}
        showDelete={isEdit && user.rec_id !== loggedInUser.rec_id}
        onDelete={onDelete}
      />
    </form>
  );
};

export interface UserFormInitialData {
  user: UserType;
  roles: Array<RoleType>;
  groups: Array<GroupType>;
}

interface UserFormProps {
  initialData: UserFormInitialData;
  isEdit: boolean;
}

const UserForm = ({
  initialData = {
    user: EmptyUser,
    roles: [],
    groups: []
  },
  isEdit
}: UserFormProps) => {
  const [user, setUser] = useState({
    ...initialData.user,
    password: generateRandomPassword()
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const router = useRouter();
  const { strings } = useLocale();

  const onChange = (key: string, value: any) => {
    setUser((u) => {
      const newU = {
        ...u,
        [key]: value
      };
      return newU;
    });
  };
  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    setIsLoading(true);

    const url = isEdit ? `/management/user/${user.rec_id}` : "/management/user";
    const body = isEdit
      ? {
          email: user.email,
          enabled: user.enabled,
          suspended: user.suspended,
          enabled_2fa: user["2fa_enabled"]
        }
      : {
          email: user.email,
          passphrase: user.password
        };

    post(url, body, null, isEdit ? "PUT" : "POST")
      .then((response) => {
        if (response.status === "SUCCESS") {
          if (!isEdit) {
            return response.data["rec_id"];
          } else {
            return user.rec_id;
          }
        } else {
          setIsLoading(false);
          setError(response.message);
          return null;
        }
      })
      .then((userRecId) => {
        // assign roles and groups
        if (!userRecId) return null;
        return Promise.all([
          post(
            `/management/user/${userRecId}/roles`,
            user.roles.map((r) => r.rec_id),
            null,
            "PUT"
          ),
          post(
            `/management/user/${userRecId}/groups`,
            user.groups.map((r) => r.rec_id),
            null,
            "PUT"
          )
        ]);
      })
      .then(([roleResponse, groupResponse]) => {
        if (!roleResponse || !groupResponse) {
          setIsLoading(false);
        } else {
          if (
            roleResponse.status === "SUCCESS" &&
            groupResponse.status === "SUCCESS"
          ) {
            router.push("/dashboard/users/list");
          } else {
            setError(roleResponse.message || groupResponse.message);
            setIsLoading(false);
          }
        }
      });
  };

  const onDelete = (e) => {
    e.preventDefault();

    if (confirm(strings("confirm-delete-user"))) {
      setIsLoading(true);

      post(`/management/user/${user.rec_id}`, {}, null, "DELETE").then(
        (response) => {
          if (response.status === "SUCCESS") {
            router.push("/dashboard/users/list");
          } else {
            setError(response.message);
            setIsLoading(false);
          }
        }
      );
    }
  };
  return (
    <UserFormView
      onDelete={onDelete}
      error={error}
      isLoading={isLoading}
      isEdit={isEdit}
      user={user}
      onChange={onChange}
      onSubmit={onSubmit}
      roles={initialData.roles}
      groups={initialData.groups}
    />
  );
};

export default UserForm;
