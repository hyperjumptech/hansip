import React, { useState, useContext, FormEvent } from "react";
import { useLocale } from "../../locales";
import { RoleType, EmptyRole } from "../../../data/use-get-roles";
import { LabelInput } from "../../label-input";
import { post } from "../../../data/requests";
import { useRouter } from "next/router";
import SaveDeleteButtons from "./components/save-delete-buttons";

interface RoleFormViewProps {
  role: RoleType;
  onChange: (key: string, value: any) => void;
  onDelete: (e: FormEvent) => void;
  onSubmit: (e: FormEvent) => void;
  isLoading: boolean;
  isEdit: boolean;
  error?: string;
}
const RoleFormView = ({
  role,
  onChange,
  onSubmit,
  isLoading,
  isEdit,
  error,
  onDelete
}: RoleFormViewProps) => {
  const { strings } = useLocale();
  return (
    <form onSubmit={onSubmit} className="resource-form">
      {error && <div className="error-box">{error}</div>}

      <LabelInput
        id="name"
        disabled={isLoading}
        value={role.role_name}
        inputType="text"
        labelText={strings("role_name")}
        placeholder="Group #1"
        onChange={(e) => onChange("role_name", e.target.value)}
      />

      <LabelInput
        value={role.description}
        id="name"
        disabled={isLoading}
        inputType="text"
        labelText={strings("description")}
        placeholder="Description"
        onChange={(e) => onChange("description", e.target.value)}
      />

      <SaveDeleteButtons
        isLoading={isLoading}
        showDelete={isEdit}
        onDelete={onDelete}
      />
    </form>
  );
};

interface RoleFormProps {
  initialData: RoleType;
  isEdit?: boolean;
}
const RoleForm = ({ initialData = EmptyRole, isEdit }: RoleFormProps) => {
  const [role, setRole] = useState(initialData);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const router = useRouter();
  const { strings } = useLocale();

  const onChange = (key: string, value: any) => {
    setRole((u) => ({
      ...u,
      [key]: value
    }));
  };
  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    setIsLoading(true);

    post(
      isEdit ? `/management/role/${role.rec_id}` : "/management/role",
      {
        role_name: role.role_name,
        description: role.description
      },
      null,
      isEdit ? "PUT" : "POST"
    ).then((response) => {
      if (response.status === "SUCCESS") {
        router.push("/dashboard/roles/list");
      } else {
        setIsLoading(false);
        setError(response.message);
      }
    });
  };
  const onDelete = (e) => {
    e.preventDefault();

    if (confirm(strings("confirm-delete-role"))) {
      setIsLoading(true);

      post(`/management/role/${role.rec_id}`, {}, null, "DELETE").then(
        (response) => {
          if (response.status === "SUCCESS") {
            router.push("/dashboard/roles/list");
          } else {
            setError(response.message);
            setIsLoading(false);
          }
        }
      );
    }
  };
  return (
    <RoleFormView
      onDelete={onDelete}
      isEdit={isEdit}
      error={error}
      isLoading={isLoading}
      role={role}
      onChange={onChange}
      onSubmit={onSubmit}
    />
  );
};

export default RoleForm;
