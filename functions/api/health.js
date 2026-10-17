
export async function onRequestGet({ env }) {
  try {
    const result = await env.DB
      .prepare("SELECT 1 AS ok")
      .first();

    return Response.json({
      status: "success",
      database: result?.ok === 1 ? "connected" : "error",
      storage: env.IMAGES ? "bound" : "missing"
    });
  } catch (error) {
    return Response.json({
      status: "error",
      message: "Database connection failed"
    }, { status: 500 });
  }
}
