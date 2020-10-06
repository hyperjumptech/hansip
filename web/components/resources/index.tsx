import React, { useState, useContext } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faPlus } from "@fortawesome/free-solid-svg-icons";
import {
  SortOption,
  DataPagingQueryType,
  BaseSWRResponseType
} from "../../data/fetcher";
import DashboardLayout from "../dashboard-layout";
import { PageTitle } from "../page";
import { useLocale } from "../locales";
import Link from "next/link";
import { useRouter } from "next/router";

export interface ResourcesListProps<T> {
  headers: Array<string>;
  rows: Array<T>;
  onChangeRow?: (row: T, key: string, value: string) => void;
}

export interface ResourcesListViewProps<T> {
  component: React.ElementType;
  useDataList: (query: DataPagingQueryType) => T;
  dataKey: string;
  orders?: Array<string>;
}
export const ResourcesListView = <T extends BaseSWRResponseType>({
  component: Component,
  useDataList,
  dataKey,
  orders = [""]
}: ResourcesListViewProps<T>) => {
  const router = useRouter();
  const { page = "1" } = router.query;
  const { strings } = useLocale();

  // if order and sort not needed in the front end, we don't need to use useState.
  const [order] = useState(orders[0]);
  const [sort] = useState<SortOption>("DESC");

  // fetch data
  const { loading, data, error } = useDataList({
    page_no: parseInt(page as string, 10),
    order_by: order,
    page_size:
      parseInt(process.env.NEXT_PUBLIC_DEFAULT_RESOURCE_PAGE_SIZE, 10) || 10,
    sort
  });

  // create the pages
  var pages = [];
  if (data) {
    const { page: pageData } = data;
    for (let p = 0; p < pageData.total_pages; p++) {
      pages.push(p + 1);
    }
  }

  return (
    <DashboardLayout>
      {loading && <div>Loading ...</div>}
      {error && <div>{error.message}</div>}
      {data && !loading && !error && (
        <div className="pb-4">
          <div className="flex flex-col items-start sm:justify-between sm:items-center sm:flex-row ">
            <PageTitle title={strings(dataKey)} />
            <Link
              href={"/dashboard/[resource]/new"}
              as={`/dashboard/${dataKey}/new`}>
              <a className="btn-blue">
                <FontAwesomeIcon icon={faPlus} className="mr-2" />
                {strings(`add-${dataKey}`)}
              </a>
            </Link>
          </div>
          <Component
            {...{
              [dataKey]: data[dataKey],
              page,
              order,
              sort
            }}
          />
          {pages.length > 1 && (
            <ul className="flex flex-row justify-end space-x-2 mt-8">
              {pages.map((p) => {
                return (
                  <li key={p}>
                    <Link
                      href={{
                        pathname: router.pathname,
                        query: {
                          page: p
                        }
                      }}
                      as={{
                        pathname: router.pathname.replace(
                          "[resource]",
                          router.query["resource"] as string
                        ),
                        query: {
                          page: p
                        }
                      }}>
                      <a
                        className={
                          page === `${p}`
                            ? "block text-center align-middle pt-1 w-8 h-8 text-white bg-blue-400 rounded"
                            : "block text-center align-middle pt-1 w-8 h-8 text-black bg-transparent rounded underline"
                        }>
                        {p}
                      </a>
                    </Link>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}
    </DashboardLayout>
  );
};
