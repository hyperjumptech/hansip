import React, { useState } from "react";

const Dropdown = ({ current, children }) => {
  const [isOpen, setIsOpen] = useState(false);
  return (
    <div className="relative">
      <button
        onClick={() => {
          setIsOpen((isOpen) => !isOpen);
        }}
        className={` z-10  h-12 px-2  overflow-hidden  hover:border-gray-300 focus:border-gray-300 focus:outline-none`}>
        {current}
      </button>
      <button
        onClick={() => {
          setIsOpen((isOpen) => !isOpen);
        }}
        className={`h-full w-full fixed inset-0 cursor-default ${
          !isOpen ? "hidden" : ""
        }`}
      />
      <div
        className={`absolute w-full bg-white rounded-lg shadow-lg py-2 mt-4  ${
          !isOpen ? "hidden" : ""
        }`}>
        {children}
      </div>
    </div>
  );
};

export default Dropdown;
