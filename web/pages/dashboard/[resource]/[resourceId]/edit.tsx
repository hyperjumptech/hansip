import React from "react";
import { useRouter } from "next/router";
import DashboardLayout from "../../../../components/dashboard-layout";
import {
  availableResources,
  ResourceType
} from "../../../../components/resources/availableResources";
import { useLocale } from "../../../../components/locales";
import { PageTitle } from "../../../../components/page";

export const EditResourceView = ({
  formComponent: FormComponent,
  data,
  pageTitle,
  isEdit
}) => {
  return (
    <div>
      <PageTitle title={pageTitle} />
      <FormComponent initialData={data} isEdit={isEdit} />
    </div>
  );
};

interface EditResourcePageProps {
  resource: ResourceType;
  resourceId?: string;
  isEdit: boolean;
}
const EditResourcePage = ({
  resource,
  resourceId,
  isEdit
}: EditResourcePageProps) => {
  const { data, loading, error } = resource.useDataSingle(resourceId);
  const { strings } = useLocale();

  return (
    <DashboardLayout>
      {error && !loading && <div>{error.message}</div>}
      {loading && <div>Loading ...</div>}
      {!loading && !error && (
        <div className="py-2 px-4 bg-white rounded shadow">
          <EditResourceView
            pageTitle={
              isEdit
                ? strings(`edit-${resource.dataKey}`)
                : strings(`add-${resource.dataKey}`)
            }
            formComponent={resource.components.form}
            data={data}
            isEdit={isEdit}
          />
        </div>
      )}
    </DashboardLayout>
  );
};

interface EditPageProps {
  isEdit?: boolean;
}
const EditPage = ({ isEdit = true }: EditPageProps) => {
  const router = useRouter();
  const { resource, resourceId } = router.query;

  const resourceToUse = availableResources[resource as string];

  if (!resourceToUse) {
    return <div>Resource not found</div>;
  }

  return (
    <EditResourcePage
      isEdit={isEdit}
      resource={resourceToUse}
      resourceId={resourceId as string}
    />
  );
};

export default EditPage;
