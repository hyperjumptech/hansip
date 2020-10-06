import React, { ChangeEvent } from "react";

interface SelectProps {
  options: Array<{
    title: string;
    value: any;
  }>;
  disabled?: boolean;
  value: any;
  onChange: (event: ChangeEvent<HTMLSelectElement>) => void;
}

export const CaretDown = () => {
  return (
    <svg
      className="fill-current h-4 w-4"
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 20 20">
      <path d="M9.293 12.95l.707.707L15.657 8l-1.414-1.414L10 10.828 5.757 6.586 4.343 8z" />
    </svg>
  );
};

const Select = ({
  options,
  value,
  onChange,
  disabled = false
}: SelectProps) => {
  return (
    <div className="inline-block relative">
      <select
        disabled={disabled}
        value={value}
        onChange={onChange}
        className="block appearance-none w-full bg-white border border-gray-400 hover:border-gray-500 px-4 py-2 pr-8 rounded shadow focus:outline-none focus:shadow-outline">
        {options.map((opt, i) => {
          return (
            <option value={opt.value} key={i}>
              {opt.title}
            </option>
          );
        })}
      </select>
      <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-gray-700">
        <CaretDown />
      </div>
    </div>
  );
};

export default Select;
