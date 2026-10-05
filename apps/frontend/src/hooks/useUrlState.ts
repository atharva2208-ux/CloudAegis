import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router-dom";

/**
 * Keeps list filters in the URL so views are shareable and survive reloads.
 * Multi-value keys are stored as repeated query params.
 */
export function useUrlState(multiKeys: string[] = []) {
  const [params, setParams] = useSearchParams();

  const get = useCallback((key: string) => params.get(key) ?? undefined, [params]);
  const getAll = useCallback((key: string) => params.getAll(key), [params]);

  const update = useCallback(
    (changes: Record<string, string | string[] | number | boolean | undefined | null>, resetPage = true) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          for (const [key, value] of Object.entries(changes)) {
            next.delete(key);
            if (value === undefined || value === null || value === "" || value === false) continue;
            if (Array.isArray(value)) value.forEach((v) => next.append(key, v));
            else next.set(key, String(value));
          }
          if (resetPage && !("page" in changes)) next.delete("page");
          return next;
        },
        { replace: true },
      );
    },
    [setParams],
  );

  const snapshot = useMemo(() => {
    const out: Record<string, string | string[]> = {};
    params.forEach((value, key) => {
      if (multiKeys.includes(key)) out[key] = params.getAll(key);
      else out[key] = value;
    });
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params]);

  const clear = useCallback(() => setParams(new URLSearchParams(), { replace: true }), [setParams]);

  return { get, getAll, update, clear, snapshot, params };
}
