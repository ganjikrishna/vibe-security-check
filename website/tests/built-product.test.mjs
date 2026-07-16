import assert from "node:assert/strict";
import test from "node:test";
import worker from "../dist/server/index.js";

test("built homepage is served through the hardened worker",async()=>{
  const response=await worker.fetch(new Request("https://scanner.example/"),{ASSETS:{fetch:async()=>new Response("not found",{status:404})}});
  assert.equal(response.status,200);
  assert.match(await response.text(),/Ship fast/);
  assert.match(response.headers.get("content-security-policy"),/frame-ancestors 'none'/);
  assert.match(response.headers.get("strict-transport-security"),/max-age=31536000/);
});
