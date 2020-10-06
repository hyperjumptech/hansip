import React from "react";
import { useRouter } from "next/router";
import { ResourcesListView } from "../../../components/resources";
import { availableResources } from "../../../components/resources/availableResources";

const ResourceListPage = () => {
  const router = useRouter();
  const { resource } = router.query;

  if (Object.keys(availableResources).indexOf(resource as string) === -1) {
    return <div>Resource not found</div>;
  }

  const resourceToUse = availableResources[resource as string];

  return (
    <ResourcesListView
      key={resource as string}
      {...{
        ...resourceToUse,
        component: resourceToUse.components.list
      }}
    />
  );
};

export default ResourceListPage;
