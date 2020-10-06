import { faSpinner } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import React, { FormEvent } from "react";
import { useLocale } from "../../../locales";

interface SaveDeleteButtonsProps {
  showDelete: boolean;
  onDelete: (e: FormEvent) => void;
  isLoading?: boolean;
}
const SaveDeleteButtons = ({
  showDelete,
  onDelete,
  isLoading
}: SaveDeleteButtonsProps) => {
  const { strings } = useLocale();
  return (
    <div className="mt-4 flex flex-row justify-between">
      <button disabled={isLoading} className="btn-blue" type="submit">
        {isLoading ? (
          <FontAwesomeIcon icon={faSpinner} className="animate-spin" />
        ) : (
          strings("save")
        )}
      </button>
      {showDelete && (
        <button
          disabled={isLoading}
          className="btn-red"
          type="button"
          onClick={onDelete}>
          {strings("delete")}
        </button>
      )}
    </div>
  );
};

export default SaveDeleteButtons;
