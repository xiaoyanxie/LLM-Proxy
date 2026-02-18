import { useEffect, useState } from "react";

export function useTabActive() {
  const [isActive, setIsActive] = useState(() => {
    if (typeof document === "undefined") return true;
    return !document.hidden;
  });

  useEffect(() => {
    const handleVisibility = () => {
      setIsActive(!document.hidden);
    };

    const handleFocus = () => {
      setIsActive(true);
    };

    const handleBlur = () => {
      // when window loses focus, but tab may still be visible – you can choose:
      // setIsActive(false);
      // or leave it alone; here we'll treat blur as "not active"
      setIsActive(false);
    };

    document.addEventListener("visibilitychange", handleVisibility);
    window.addEventListener("focus", handleFocus);
    window.addEventListener("blur", handleBlur);

    return () => {
      document.removeEventListener("visibilitychange", handleVisibility);
      window.removeEventListener("focus", handleFocus);
      window.removeEventListener("blur", handleBlur);
    };
  }, []);

  return isActive;
}
