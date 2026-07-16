import assert from "node:assert/strict";
import test from "node:test";
import worker from "../worker/index.js";

const env={ASSETS:{fetch:async()=>new Response("<h1>Vibe Security Check</h1>",{status:200,headers:{"content-type":"text/html"}})}};

test("health endpoint identifies version 2",async()=>{
  const response=await worker.fetch(new Request("https://scanner.example/api/health"),env);
  assert.equal(response.status,200);
  assert.deepEqual(await response.json(),{status:"ok",version:"2.0"});
});

test("rejects private and non-HTTPS targets",async()=>{
  for(const url of ["http://example.com","https://localhost","https://127.0.0.1"]){
    const response=await worker.fetch(new Request("https://scanner.example/api/scan",{method:"POST",headers:{"content-type":"application/json","cf-connecting-ip":url},body:JSON.stringify({url})}),env);
    assert.equal(response.status,400);
  }
});

test("rejects recursive self-scans with a clear message",async()=>{
  const response=await worker.fetch(new Request("https://scanner.example/api/scan",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({url:"https://scanner.example/"})}),env);
  assert.equal(response.status,400);
  assert.match((await response.json()).error,/cannot scan its own hostname/i);
});

test("adds defensive headers to public assets",async()=>{
  const response=await worker.fetch(new Request("https://scanner.example/"),env);
  assert.equal(response.status,200);
  assert.equal(response.headers.get("x-frame-options"),"DENY");
  assert.match(response.headers.get("content-security-policy"),/frame-ancestors 'none'/);
});
