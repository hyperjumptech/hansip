import { get } from "./requests";
import { getSavedTokens } from "./user";

export type SortOption = "ASC" | "DESC";

export interface DataPagingQueryType {
  page_no: number;
  page_size: number;
  order_by: string;
  sort: "ASC" | "DESC";
}

export interface BaseSWRResponseType {
  data: {
    page: DataPagingType;
  };
  loading: boolean;
  error: any;
}

export interface DataPagingType {
  page_no: number;
  total_pages: number;
  page_size: number;
  items: number;
  total_items: number;
  has_next: number;
  has_prev: number;
  is_first: number;
  is_last: number;
  first_page: number;
  last_page: number;
  prev_page: number;
  next_page: number;
  order_by: string;
  sort: SortOption;
}

const fetcher = (path, searchParams, sampleResponse) => {
  if (sampleResponse) {
    return Promise.resolve(sampleResponse);
  }

  return get(path, searchParams);
};

export default fetcher;
