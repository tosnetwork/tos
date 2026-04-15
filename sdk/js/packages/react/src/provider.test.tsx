import { describe, it, expect } from "vitest";
import { renderHook, render, screen } from "@testing-library/react";
import { TosProvider } from "./provider.js";
import { createTosConfig } from "./config.js";
import { useClient } from "./hooks/useClient.js";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("TosProvider", () => {
  it("renders children", () => {
    const config = createTosConfig();
    render(
      <TosProvider config={config}>
        <div data-testid="child">Hello</div>
      </TosProvider>,
    );

    expect(screen.getByTestId("child")).toBeDefined();
    expect(screen.getByTestId("child").textContent).toBe("Hello");
  });

  it("provides a TosClient via context", () => {
    const config = createTosConfig();

    const { result } = renderHook(() => useClient(), {
      wrapper: ({ children }) => (
        <TosProvider config={config}>{children}</TosProvider>
      ),
    });

    expect(result.current).toBeDefined();
    // Verify the returned client is the same instance from the config
    expect(result.current).toBe(config.client);
  });
});

describe("useClient", () => {
  it("throws when used outside TosProvider", () => {
    // renderHook will catch the error thrown during render
    expect(() => {
      renderHook(() => useClient());
    }).toThrow(/useClient must be used within a <TosProvider>/);
  });

  it("returns the same client instance on re-renders", () => {
    const config = createTosConfig();
    const clients: any[] = [];

    function CaptureClient() {
      const client = useClient();
      clients.push(client);
      return null;
    }

    const { rerender } = render(
      <TosProvider config={config}>
        <CaptureClient />
      </TosProvider>,
    );

    rerender(
      <TosProvider config={config}>
        <CaptureClient />
      </TosProvider>,
    );

    expect(clients.length).toBe(2);
    expect(clients[0]).toBe(clients[1]);
  });
});
