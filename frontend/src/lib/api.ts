const API_URL =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export async function getSystemStatus() {
  const response = await fetch(`${API_URL}/api/v1/status`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error("Failed to fetch system status");
  }

  return response.json();
}
