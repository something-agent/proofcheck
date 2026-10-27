import { buildApp } from "./app";
let app: ReturnType<typeof buildApp> | undefined;
export default { fetch(req: Request, _env: unknown, ctx: ExecutionContext) { app ??= buildApp(); return app.fetch(req, _env, ctx); } };
