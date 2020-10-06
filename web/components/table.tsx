import React, { ReactNode } from "react";

interface TableProps {
  headers: Array<{
    title: string;
    key: string;
  }>;
  rows: Array<any>;
  colFunc: (row: number, col: number, rowObj: any, headerObj: any) => ReactNode;
}

const Table = ({ headers, rows, colFunc }: TableProps) => {
  return (
    <table className="min-w-full bg-white">
      <thead className="bg-gray-800 text-white">
        <tr>
          {headers.map((header, i) => {
            return (
              <th
                key={i}
                className="text-left py-3 px-4 uppercase font-semibold text-sm">
                {header.title}
              </th>
            );
          })}
        </tr>
      </thead>
      <tbody className="text-gray-700">
        {rows.map((row, i) => {
          return (
            <tr key={row["rec_id"] ?? i}>
              {headers.map((header, j) => {
                return (
                  <td key={j} className="text-left py-3 px-4">
                    {colFunc ? colFunc(i, j, row, header) : row[header.title]}
                  </td>
                );
              })}
            </tr>
          );
        })}
      </tbody>
    </table>
  );
};

export default Table;
