import React from "react";

import { ChangeEvent } from "react";

export interface LabelInputProps {
  id: string;
  labelText: string;
  placeholder: string;
  inputType: string;
  value: string;
  disabled?: boolean;
  note?: string;
  error?: string;
  className?: string;
  onChange: (e: ChangeEvent<HTMLInputElement>) => void;
}

export const LabelInput = ({
  id,
  labelText,
  inputType,
  placeholder,
  value,
  disabled,
  note,
  error,
  onChange,
  className
}: LabelInputProps) => {
  return (
    <div className={className || "mb-4"}>
      <label
        className="block text-gray-700 text-sm font-bold mb-2"
        htmlFor={id}>
        {labelText}
      </label>
      {error && <span className="text-sm text-red-600">{error}</span>}
      <input
        disabled={disabled}
        type={inputType}
        id={id}
        name={id}
        placeholder={placeholder}
        value={value}
        onChange={onChange}
      />
      {note && <span className="text-sm text-gray-600">{note}</span>}
    </div>
  );
};
