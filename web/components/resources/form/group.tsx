import React, { useState, FormEvent } from "react";
import { useLocale } from "../../locales";
import { GroupType, EmptyGroup } from "../../../data/use-get-groups";
import { LabelInput } from "../../label-input";
import { useRouter } from "next/router";
import { post } from "../../../data/requests";
import { RoleType } from "../../../data/use-get-roles";
import SaveDeleteButtons from "./components/save-delete-buttons";

interface GroupFormViewProps {
  group: GroupType;
  onChange: (key: string, value: any) => void;
  onSubmit: (e: FormEvent) => void;
  onDelete: (e: FormEvent) => void;
  error?: string;
  isLoading: boolean;
  roles?: Array<RoleType>;
  isEdit?: boolean;
}
const GroupFormView = ({
  group,
  isLoading,
  onChange,
  onSubmit,
  error,
  roles,
  isEdit,
  onDelete
}: GroupFormViewProps) => {
  const { strings } = useLocale();
  return (
    <form onSubmit={onSubmit} className="resource-form">
      {error && <div className="error-box">{error}</div>}

      <LabelInput
        id="name"
        disabled={isLoading}
        value={group.group_name || ""}
        inputType="text"
        labelText={strings("group_name")}
        placeholder="Group #1"
        onChange={(e) => onChange("group_name", e.target.value)}
      />

      <LabelInput
        value={group.description || ""}
        id="name"
        disabled={isLoading}
        inputType="text"
        labelText={strings("description")}
        placeholder="Description"
        onChange={(e) => onChange("description", e.target.value)}
      />

      <label
        className="block text-gray-700 text-sm font-bold mb-2"
        htmlFor="roles">
        {`${strings("roles")} ${
          group.roles && group.roles.length > 0
            ? `(${group.roles.length})`
            : "(0)"
        }`}
      </label>

      {roles &&
        roles.length > 0 &&
        roles
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
                    group.roles.filter((ur) => ur.rec_id === r.rec_id).length >
                    0
                  }
                  onChange={(e) => {
                    var newRoles = [...group.roles];
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

      <SaveDeleteButtons
        isLoading={isLoading}
        showDelete={isEdit}
        onDelete={onDelete}
      />
    </form>
  );
};

export interface GroupFormInitialData {
  group: GroupType;
  roles: Array<RoleType>;
}
interface GroupFormProps {
  initialData: GroupFormInitialData;
  isEdit?: boolean;
}
const GroupForm = ({
  initialData = {
    group: EmptyGroup,
    roles: []
  },
  isEdit
}: GroupFormProps) => {
  const [group, setGroup] = useState(initialData.group);
  const [error, setError] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const router = useRouter();
  const { strings } = useLocale();

  const onChange = (key: string, value: any) => {
    setGroup((u) => ({
      ...u,
      [key]: value
    }));
  };
  const onSubmit = (e: FormEvent) => {
    e.preventDefault();

    setIsLoading(true);

    post(
      isEdit ? `/management/group/${group.rec_id}` : "/management/group",
      {
        group_name: group.group_name,
        description: group.description
      },
      null,
      isEdit ? "PUT" : "POST"
    )
      .then((response) => {
        if (response.status === "SUCCESS") {
          return post(
            `/management/group/${response.data.rec_id}/roles`,
            group.roles && group.roles.length > 0
              ? group.roles?.map((r) => r.rec_id)
              : [],
            null,
            "PUT"
          );
        } else {
          setIsLoading(false);
          setError(response.message);
        }
      })
      .then((response) => {
        if (!response) {
          setIsLoading(false);
        } else {
          if (response.status === "SUCCESS") {
            router.push("/dashboard/groups/list");
          } else {
            setIsLoading(false);
            setError(response.message);
          }
        }
      });
  };
  const onDelete = (e) => {
    e.preventDefault();

    if (confirm(strings("confirm-delete-group"))) {
      setIsLoading(true);

      post(`/management/group/${group.rec_id}`, {}, null, "DELETE").then(
        (response) => {
          if (response.status === "SUCCESS") {
            router.push("/dashboard/groups/list");
          } else {
            setError(response.message);
            setIsLoading(false);
          }
        }
      );
    }
  };
  return (
    <GroupFormView
      isEdit={isEdit}
      onDelete={onDelete}
      roles={initialData.roles}
      isLoading={isLoading}
      error={error}
      group={group}
      onChange={onChange}
      onSubmit={onSubmit}
    />
  );
};

export default GroupForm;
