import { describe, it, expect, vi } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";
import { useMutation } from "./useMutation.js";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("useMutation", () => {
  it("has the correct initial state", () => {
    const mutationFn = vi.fn().mockResolvedValue("ok");
    const { result } = renderHook(() => useMutation({ mutationFn }));

    expect(result.current.isPending).toBe(false);
    expect(result.current.isSuccess).toBe(false);
    expect(result.current.isError).toBe(false);
    expect(result.current.data).toBeUndefined();
    expect(result.current.error).toBeNull();
  });

  it("mutate() sets isPending, then isSuccess + data on resolve", async () => {
    const mutationFn = vi.fn().mockResolvedValue({ id: 1 });
    const { result } = renderHook(() => useMutation({ mutationFn }));

    act(() => {
      result.current.mutate("arg1");
    });

    // Immediately after mutate, should be pending
    expect(result.current.isPending).toBe(true);
    expect(result.current.isSuccess).toBe(false);
    expect(result.current.data).toBeUndefined();

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(result.current.isPending).toBe(false);
    expect(result.current.data).toEqual({ id: 1 });
    expect(result.current.error).toBeNull();
    expect(mutationFn).toHaveBeenCalledWith("arg1");
  });

  it("mutateAsync() returns a promise that resolves with the result", async () => {
    const mutationFn = vi.fn().mockResolvedValue(42);
    const { result } = renderHook(() => useMutation<string, number>({ mutationFn }));

    let resolved: number | undefined;

    await act(async () => {
      resolved = await result.current.mutateAsync("input");
    });

    expect(resolved).toBe(42);
    expect(result.current.isSuccess).toBe(true);
    expect(result.current.data).toBe(42);
  });

  it("sets isError and error when mutation rejects", async () => {
    const mutationFn = vi.fn().mockRejectedValue(new Error("fail"));
    const { result } = renderHook(() => useMutation({ mutationFn }));

    act(() => {
      result.current.mutate("bad-arg");
    });

    // Immediately pending
    expect(result.current.isPending).toBe(true);

    await waitFor(() => {
      expect(result.current.isError).toBe(true);
    });

    expect(result.current.isPending).toBe(false);
    expect(result.current.isSuccess).toBe(false);
    expect(result.current.error).not.toBeNull();
    expect(result.current.error!.message).toBe("fail");
    expect(result.current.data).toBeUndefined();
  });

  it("mutateAsync() rejects with TosError on failure", async () => {
    const mutationFn = vi.fn().mockRejectedValue(new Error("async-fail"));
    const { result } = renderHook(() => useMutation({ mutationFn }));

    let thrownError: Error | undefined;

    await act(async () => {
      try {
        await result.current.mutateAsync("bad");
      } catch (err) {
        thrownError = err as Error;
      }
    });

    expect(thrownError).toBeDefined();
    expect(thrownError!.message).toBe("async-fail");
    expect(result.current.isError).toBe(true);
  });

  it("reset() clears state back to idle", async () => {
    const mutationFn = vi.fn().mockResolvedValue("ok");
    const { result } = renderHook(() => useMutation({ mutationFn }));

    await act(async () => {
      await result.current.mutateAsync("arg");
    });

    expect(result.current.isSuccess).toBe(true);
    expect(result.current.data).toBe("ok");

    act(() => {
      result.current.reset();
    });

    expect(result.current.isPending).toBe(false);
    expect(result.current.isSuccess).toBe(false);
    expect(result.current.isError).toBe(false);
    expect(result.current.data).toBeUndefined();
    expect(result.current.error).toBeNull();
  });

  it("discards stale responses when multiple mutations fire rapidly", async () => {
    let resolvers: Array<(val: string) => void> = [];
    const mutationFn = vi.fn().mockImplementation(
      () =>
        new Promise<string>((resolve) => {
          resolvers.push(resolve);
        }),
    );

    const { result } = renderHook(() => useMutation({ mutationFn }));

    // Fire two mutations in quick succession
    act(() => {
      result.current.mutate("first");
    });
    act(() => {
      result.current.mutate("second");
    });

    expect(resolvers).toHaveLength(2);

    // Resolve the second one first
    await act(async () => {
      resolvers[1]!("result-2");
      // Small delay to let microtasks resolve
      await new Promise((r) => setTimeout(r, 0));
    });

    expect(result.current.data).toBe("result-2");
    expect(result.current.isSuccess).toBe(true);

    // Now resolve the first (stale) — it should be discarded
    await act(async () => {
      resolvers[0]!("result-1");
      await new Promise((r) => setTimeout(r, 0));
    });

    // Data should still be result-2
    expect(result.current.data).toBe("result-2");
  });
});
