import type { Status } from "./api-types";

export class ApiError extends Error {
  readonly status: Status;
  constructor(status: Status) {
    super(status.message);
    this.status = status;
  }
}

export async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { Accept: "application/json", ...(init?.body ? { "Content-Type": "application/json" } : {}), ...init?.headers },
  });
  const text = await res.text();
  if (!res.ok) {
    let status: Status;
    try {
      status = JSON.parse(text) as Status;
    } catch {
      status = { kind: "Status", status: "Failure", message: text || res.statusText, code: res.status };
    }
    throw new ApiError(status);
  }
  return (text ? JSON.parse(text) : undefined) as T;
}

/** Diff errors intentionally use response.json without the JSON fallback. */
export async function requestText(path: string): Promise<string> {
  const res = await fetch(path);
  if (!res.ok) throw new ApiError((await res.json()) as Status);
  return res.text();
}
