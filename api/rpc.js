const RIALO_RPC_URL = "https://devnet.rialo.io";

export default async function handler(request, response) {
  if (request.method !== "POST") {
    response.setHeader("Allow", "POST");
    response.status(405).json({ error: "Method Not Allowed" });
    return;
  }

  try {
    const upstream = await fetch(RIALO_RPC_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(request.body),
    });

    const text = await upstream.text();
    response.status(upstream.status).setHeader("Content-Type", "application/json").send(text);
  } catch (error) {
    response.status(502).json({
      error: "Upstream RPC request failed",
      details: error instanceof Error ? error.message : String(error),
    });
  }
}
