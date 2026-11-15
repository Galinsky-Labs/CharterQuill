import {before,after,test} from "node:test";
import assert from "node:assert/strict";
import {randomUUID,randomBytes} from "node:crypto";
import {PGlite} from "@electric-sql/pglite";
import {createIdentityStore,applyIdentityMigrations} from "@distributed-governance/engine/identity";
import {createPlatform,applyExtensionMigrations} from "@distributed-governance/engine/platform";
import {charterExtension} from "../server/charter-extension.mjs";
import {createEnterpriseExtension,enterpriseConfig} from "../server/enterprise-extension.mjs";
import {signWebhook,verifyWebhook,checkSsoClaims,seatReconciliation,normalizeCapTable,capTableMismatches,validateEndpoint,parseScimUser,applyScimPatch,esignEvidence,retryDelaySeconds} from "../src/enterprise.mjs";

const origin="https://charter.example";
const SCIM_TOKEN="scim-token-"+"x".repeat(40),CAP_SECRET="captable-secret-"+"y".repeat(40),ESIGN_SECRET="esign-secret-"+"z".repeat(40);
let db,platform,identity,owner,director,holder,tenantId,now,enterprise,outbox=[],failNext=0;
const transaction=fn=>db.transaction(async tx=>{await tx.exec("SET LOCAL ROLE dge_identity_runtime");return fn(tx);});
const user=async()=>({...await identity.establishSession({issuer:"https://id.example",subject:randomUUID(),authenticatedAt:Date.now()}),origin});
const request=async(path,{who=owner,method="GET",body,headers={},raw}={})=>{
  const response=await platform.application(new Request(origin+path,{method,headers:{
    ...(who?{cookie:"__Host-dge_session="+who.sessionToken,origin,"x-dge-csrf":who.csrfToken}:{}),
    ...(body!==undefined||raw!==undefined?{"content-type":"application/json"}:{}),...headers},
    ...(raw!==undefined?{body:raw}:body!==undefined?{body:JSON.stringify(body)}:{})}),{peerAddress:"127.0.0.1"});
  const text=await response.text();
  return {status:response.status,body:text?JSON.parse(text):null};
};
const ws=p=>`/api/workspaces/${tenantId}/charter/${p}`;
const scim=(path,init={})=>request("/api/charter/scim/v2/Users"+path,{who:null,...init,headers:{authorization:"Bearer "+SCIM_TOKEN,...init.headers}});
const hook=(provider,event,{secret=provider==="captable"?CAP_SECRET:ESIGN_SECRET,at=now}={})=>{
  const raw=JSON.stringify(event);
  return request(`/api/charter/integrations/${tenantId}/webhooks/${provider}`,{who:null,method:"POST",raw,headers:{"quill-signature":signWebhook({secret,timestamp:Math.floor(at/1000),body:raw})}});
};

before(async()=>{
  db=await PGlite.create();
  await applyIdentityMigrations(fn=>db.transaction(fn));
  identity=createIdentityStore({transaction,origin,sessionKey:randomBytes(32),stateKey:randomBytes(32)});
  owner=await user();director=await user();holder=await user();
  ({tenantId}=await identity.createTenant(owner));
  for(const [who,role] of [[director,"editor"],[holder,"participant"]]){
    const invite=await identity.invite(owner,tenantId,who.accountId,role);
    await identity.acceptInvitation(who,tenantId,invite.invitationToken);
  }
  now=Date.now();
  enterprise=createEnterpriseExtension({clock:()=>now,env:{CHARTER_SCIM_TOKEN:SCIM_TOKEN,CHARTER_SCIM_TENANT_ID:tenantId,CHARTER_CAPTABLE_WEBHOOK_SECRET:CAP_SECRET,
    CHARTER_ESIGN_WEBHOOK_SECRET:ESIGN_SECRET,CHARTER_WEBHOOK_ENCRYPTION_KEY:randomBytes(32).toString("hex")},
    fetcher:async(url,init)=>{outbox.push({url,init});if(failNext>0){failNext--;return new Response("no",{status:503});}return new Response("ok");}});
  await applyExtensionMigrations(fn=>db.transaction(fn),charterExtension);
  await applyExtensionMigrations(fn=>db.transaction(fn),enterprise);
  platform=createPlatform({identity,transaction,login:{},origin,product:"charter",clock:()=>now,extensions:[charterExtension,enterprise]});
  assert.equal((await request(ws("organization"),{method:"POST",body:{entityType:"corporation",legalName:"Acme, Inc.",jurisdiction:"Delaware"}})).status,200);
});
after(async()=>db?.close());

test("integrations are disabled without configuration and report status without secrets",async()=>{
  const off=enterpriseConfig({});
  assert.equal(off.scim,null);assert.equal(off.outboundKey,null);assert.equal(off.webhookSecrets.captable,null);assert.equal(off.sso,null);
  assert.equal(enterpriseConfig({CHARTER_SCIM_TOKEN:"short",CHARTER_SCIM_TENANT_ID:tenantId}).scim,null,"weak tokens are refused");
  const status=await request(ws("integrations"));
  assert.equal(status.status,200);assert.equal(status.body.scim,"enabled");assert.equal(status.body.outboundWebhooks,"enabled");
  assert.ok(!JSON.stringify(status.body).includes(SCIM_TOKEN)&&!JSON.stringify(status.body).includes(CAP_SECRET));
  assert.equal((await request(ws("integrations"),{who:holder})).status,403);
});

test("SSO policy pins issuer and audience, checks clock bounds and allowed domains",()=>{
  const t=Math.floor(Date.now()/1000),base={iss:"https://idp.example",aud:"charter-client",exp:t+300,iat:t,email:"a@acme.com",email_verified:true};
  const policy={issuer:"https://idp.example",clientId:"charter-client",allowedDomains:["acme.com"],now:Date.now()};
  assert.deepEqual(checkSsoClaims(base,policy),{ok:true,problems:[]});
  assert.deepEqual(checkSsoClaims({...base,aud:"other-client"},policy).problems,["audience"]);
  assert.deepEqual(checkSsoClaims({...base,aud:["charter-client","other"]},policy).problems,["authorized-party"]);
  assert.ok(checkSsoClaims({...base,aud:["charter-client","other"],azp:"charter-client"},policy).ok);
  assert.deepEqual(checkSsoClaims({...base,iss:"https://evil.example"},policy).problems,["issuer"]);
  assert.deepEqual(checkSsoClaims({...base,exp:t-1000},policy).problems,["expired"]);
  assert.deepEqual(checkSsoClaims({...base,email:"a@evil.com"},policy).problems,["domain"]);
  assert.deepEqual(checkSsoClaims({...base,email_verified:false},policy).problems,["domain"]);
});

test("SCIM: bearer auth, provisioning, and deprovision queues removal that only an owner applies",async()=>{
  assert.equal((await request("/api/charter/scim/v2/Users",{who:null,headers:{authorization:"Bearer wrong-"+"x".repeat(40)}})).status,401);
  assert.equal((await request("/api/charter/scim/v2/Users",{who:null})).status,401);
  const resource=accountId=>({schemas:["urn:ietf:params:scim:schemas:core:2.0:User"],externalId:"idp-"+accountId.slice(0,8),userName:accountId.slice(0,8)+"@acme.com",active:true,
    "urn:ietf:params:scim:schemas:extension:quill:2.0:User":{accountId}});
  const created=await scim("",{method:"POST",raw:JSON.stringify(resource(holder.accountId))});
  assert.equal(created.status,201);assert.equal(created.body.active,true);
  const ownerRes=resource(owner.accountId);
  await scim("",{method:"POST",raw:JSON.stringify(ownerRes)});
  const listed=await scim("");assert.equal(listed.body.totalResults,2);
  assert.equal((await scim("/"+created.body.id,{method:"PATCH",raw:JSON.stringify({Operations:[{op:"replace",path:"displayName",value:"x"}]})})).status,400);
  const patched=await scim("/"+created.body.id,{method:"PATCH",raw:JSON.stringify({schemas:["urn:ietf:params:scim:api:messages:2.0:PatchOp"],Operations:[{op:"replace",value:{active:false}}]})});
  assert.equal(patched.status,200);assert.equal(patched.body.active,false);
  // Repeating the deactivation does not queue twice.
  await scim("/"+created.body.id,{method:"PATCH",raw:JSON.stringify({Operations:[{op:"replace",path:"active",value:false}]})});
  assert.equal((await scim("/"+ownerRes.externalId,{method:"DELETE"})).status,204);
  // Still a member until an owner applies the queue through the engine.
  assert.equal((await request(ws("organization"),{who:holder})).status,200);
  const queue=await request(ws("integrations/scim/deprovisions"));
  assert.equal(queue.body.items.length,2);assert.ok(queue.body.items.every(i=>i.appliedAt===null));
  assert.equal((await request(ws("integrations/scim/deprovisions/apply"),{who:director,method:"POST"})).status,403);
  const applied=await request(ws("integrations/scim/deprovisions/apply"),{method:"POST"});
  assert.equal(applied.status,200);
  assert.deepEqual(applied.body.applied.map(a=>a.outcome).sort(),["owner-protected","removed"]);
  assert.equal((await request(ws("organization"),{who:holder})).status,403,"deprovisioned member loses access");
  assert.equal((await request(ws("integrations/scim/deprovisions/apply"),{method:"POST"})).body.applied.length,0);
});

test("SCIM parsing refuses unknown schemas, attributes and malformed accounts",()=>{
  assert.throws(()=>parseScimUser({schemas:["x"],userName:"a"}),/SCIM_INVALID_SCHEMA/);
  assert.throws(()=>parseScimUser({schemas:["urn:ietf:params:scim:schemas:core:2.0:User"],externalId:"a",userName:"a","urn:ietf:params:scim:schemas:extension:quill:2.0:User":{accountId:"nope"}}),/SCIM_INVALID_ACCOUNT/);
  assert.throws(()=>applyScimPatch({active:true,userName:"a"},{Operations:[{op:"remove",path:"active"}]}),/UNSUPPORTED_OPERATION/);
});

test("forged, stale and replayed provider webhooks are refused; duplicates are idempotent",async()=>{
  const event={id:"evt-esign-1",type:"envelope.completed",data:{envelopeId:"env-1",status:"completed"}};
  assert.equal((await hook("esign",event,{secret:"forged-secret-"+"q".repeat(40)})).status,401);
  assert.equal((await hook("esign",event,{at:now-3600000})).status,401);
  assert.equal((await request(`/api/charter/integrations/${tenantId}/webhooks/esign`,{who:null,method:"POST",raw:JSON.stringify(event)})).status,401);
  const first=await hook("esign",event);
  assert.equal(first.status,200);assert.deepEqual(first.body,{received:true,duplicate:false,outcome:"recorded"});
  assert.equal((await hook("esign",event)).body.duplicate,true,"provider retry is idempotent");
  assert.equal((await hook("esign",{...event,data:{envelopeId:"env-1",status:"voided"}})).status,409,"reused event id with different body");
  const events=await request(ws("integrations/events"));
  assert.equal(events.body.items[0].report.authoritative,false);
  assert.equal(esignEvidence({envelopeId:"e",status:"signed"}).state,"externally-completed");
  assert.throws(()=>esignEvidence({envelopeId:"e",status:"teleported"}),/UNKNOWN_STATUS/);
  assert.equal((await hook("esign",{id:"x",type:"t",data:{envelopeId:"e",status:"teleported"}})).status,400);
});

test("verifyWebhook rejects malformed headers and length mismatches in constant time",()=>{
  const body=Buffer.from("{}"),secret="s".repeat(40),ts=Math.floor(Date.now()/1000);
  assert.equal(verifyWebhook({secret,header:"t="+ts+",v1=abc",body,now:Date.now()}).reason,"malformed-signature");
  assert.equal(verifyWebhook({secret,header:signWebhook({secret,timestamp:ts,body}),body,now:Date.now()}).ok,true);
  assert.equal(verifyWebhook({secret,header:signWebhook({secret,timestamp:ts,body}),body:Buffer.from("{ }"),now:Date.now()}).reason,"bad-signature");
});

test("cap-table mismatch is reported against the register; the register and frozen snapshots never change",async()=>{
  await request(ws("share-classes"),{method:"POST",body:{id:"common",name:"Common",votesPerShare:"1"}});
  const csv=["holder_account_id,class_id,quantity,effective_date",`${director.accountId},common,1000,2026-01-01`].join("\n");
  assert.equal((await request(ws("register-imports"),{method:"POST",body:{csv}})).status,200);
  const snapshot=await request(ws("snapshots"),{method:"POST",body:{recordDate:"2026-02-01"}});
  const before=await db.query("SELECT snapshot,digest FROM app_charter.record_snapshots");
  const registerBefore=(await db.query("SELECT count(*)::int AS n FROM app_charter.register_entries")).rows[0].n;
  const matching=await hook("captable",{id:"cap-1",type:"captable.export",data:{asOf:"2026-02-01",holdings:[{accountId:director.accountId,classId:"common",quantity:"1000"}]}});
  assert.equal(matching.body.outcome,"captable-matches");
  const mismatched=await hook("captable",{id:"cap-2",type:"captable.export",data:{asOf:"2026-02-01",holdings:[
    {accountId:director.accountId,classId:"common",quantity:"900"},{accountId:holder.accountId,classId:"preferred",quantity:"5"}]}});
  assert.equal(mismatched.body.outcome,"captable-mismatch");
  const report=(await request(ws("integrations/events"))).body.items.find(i=>i.eventId==="cap-2").report;
  assert.deepEqual(report.mismatches.map(m=>m.problem).sort(),["quantity","unknown-class"]);
  assert.deepEqual((await db.query("SELECT snapshot,digest FROM app_charter.record_snapshots")).rows,before.rows);
  assert.equal((await db.query("SELECT count(*)::int AS n FROM app_charter.register_entries")).rows[0].n,registerBefore);
  assert.equal(snapshot.status,200);
  assert.deepEqual(capTableMismatches(normalizeCapTable({asOf:"2026-01-01",holdings:[{accountId:director.accountId,classId:"common",quantity:"1.5"}]}),[],{common:0}).mismatches[0].problem,"precision");
  assert.throws(()=>normalizeCapTable({asOf:"2026-01-01",holdings:[{accountId:director.accountId,classId:"common",quantity:"1"},{accountId:director.accountId,classId:"common",quantity:"2"}]}),/DUPLICATE/);
});

test("outbound webhooks: owner-only, HTTPS public hosts, signed deliveries, retry with backoff and no content",async()=>{
  assert.throws(()=>validateEndpoint({url:"http://hooks.acme.com/x",scopes:["minute-book.entry"]}),/INVALID_URL/);
  assert.throws(()=>validateEndpoint({url:"https://localhost/x",scopes:["minute-book.entry"]}),/PRIVATE_HOST/);
  assert.throws(()=>validateEndpoint({url:"https://10.0.0.1/x",scopes:["minute-book.entry"]}),/PRIVATE_HOST/);
  assert.throws(()=>validateEndpoint({url:"https://hooks.acme.com/x",scopes:["votes.cast"]}),/INVALID_SCOPES/);
  assert.equal((await request(ws("webhooks"),{who:director,method:"POST",body:{url:"https://hooks.acme.com/q",scopes:["minute-book.entry"]}})).status,403);
  const created=await request(ws("webhooks"),{method:"POST",body:{url:"https://hooks.acme.com/q",scopes:["minute-book.entry","integration.captable-mismatch"]}});
  assert.equal(created.status,200);assert.match(created.body.signingSecret,/^[a-f0-9]{64}$/);
  assert.ok(!JSON.stringify((await request(ws("webhooks"))).body).includes(created.body.signingSecret),"secret is shown once");
  // A minute-book entry and a cap-table mismatch become deliveries.
  const meeting=await request(ws("meetings"),{method:"POST",body:{kind:"regular",body:"board",title:"Q1",startsAt:new Date(now+30*86400000).toISOString()}});
  assert.equal(meeting.status,200,JSON.stringify(meeting.body));
  assert.equal((await request(ws(`meetings/${meeting.body.id}/minutes`),{method:"POST",body:{text:"Confidential minute text."}})).status,200);
  await hook("captable",{id:"cap-3",type:"captable.export",data:{asOf:"2026-02-01",holdings:[]}});
  failNext=1;outbox=[];
  const services=platform.services;
  const worker=enterprise.createWorkers(services)[0];
  const first=await worker.tick();
  assert.equal(first.failed,1);assert.ok(first.delivered>=1);
  const sent=outbox.map(o=>o.init.body).join("\n");
  assert.ok(!sent.includes("Confidential minute text"),"payloads carry digests, not minute text");
  const sample=outbox.at(-1);
  assert.equal(verifyWebhook({secret:created.body.signingSecret,header:sample.init.headers["quill-signature"],body:Buffer.from(sample.init.body),now}).ok,true);
  assert.equal((await worker.tick()).delivered,0,"failed delivery waits for its backoff");
  now+=retryDelaySeconds(1)*1000+1;
  assert.equal((await worker.tick()).delivered,1,"retried after backoff");
  const listed=(await request(ws("webhooks"))).body.items[0];
  assert.equal(listed.pending,0);assert.ok(listed.delivered>=2);
  assert.equal((await request(ws(`webhooks/${created.body.id}/disable`),{method:"POST"})).status,200);
});

test("seat reconciliation reads shared engine seat grants and never removes members",async()=>{
  const none=await request(ws("seats"));
  assert.equal(none.status,200);assert.equal(none.body.status,"unlicensed");
  await db.query("INSERT INTO dge_billing.grants(id,tenant_id,resource,quantity,period,effective_at,provenance,idempotency_key,created_at) VALUES($1,$2,'seats',1,'none',$3,'enterprise-license',$4,$3)",
    [randomUUID(),tenantId,new Date(now-1000),"seat-test-"+randomUUID()]);
  const over=await request(ws("seats"));
  assert.equal(over.body.status,"over-license");assert.equal(over.body.licensedSeats,1);assert.equal(over.body.overBy,over.body.activeMembers-1);
  assert.deepEqual(seatReconciliation({licensedSeats:5,activeMembers:3}),{status:"within-license",licensedSeats:5,activeMembers:3,overBy:0,available:2});
  assert.equal(seatReconciliation({unlimited:true,activeMembers:9}).status,"within-license");
  assert.equal((await request(ws("seats"),{who:director})).status,403);
});
