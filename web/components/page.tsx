import React from "react";

export const PageTitle = ({ title }) => {
  return <h1 className="block text-4xl font-bold text-black">{title}</h1>;
};

export const PageBody = ({ children }) => {
  return (
    <div className="w-full mt-12">
      <div className="bg-white overflow-auto">{children}</div>
    </div>
  );
};
