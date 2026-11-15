// CORP-005/007 consumer journey: a CharterQuill record-date snapshot feeds the
// engine's unit register; a multi-class resolution, proxy race and proxy
// cycle run through the engine's weighted decision store. CharterQuill never
// tallies: it only supplies frozen holdings.
import {before,after,test} from "node:test";
import assert from "node:assert/strict";
import {randomUUID,randomBytes} from "node:crypto";
import {PGlite} from "@electric-sql/pglite";
import {createIdentityStore,applyIdentityMigrations} from "@distributed-governance/engine/identity";
import {createPlatform,applyExtensionMigrations} from "@distributed-governance/engine/platform";
import {createLegalDocument} from "@distributed-governance/engine/legal-structure";
import {charterExtension} from "../server/charter-extension.mjs";

const origin="https://charter.example",HOUR=3600000;
let db,platform,identity,s,secretary,common1,common2,pref1,pref2,tenantId,now,doc;
const transaction=fn=>db.transaction(async tx=>{await tx.exec("SET LOCAL ROLE dge_identity_runtime");return fn(tx);});
const user=async()=>({...await identity.establishSession({issuer:"https://id.example",subject:randomUUID(),authenticatedAt:Date.now()}),origin});
const call=async(path,{who=secretary,method="GET",body}={})=>{
  const response=await platform.application(new Request(origin+path,{method,headers:{
    cookie:"__Host-dge_session="+who.sessionToken,origin,"x-dge-csrf":who.csrfToken,...(body!==undefined?{"content-type":"application/json"}:{})},
    ...(body!==undefined?{body:JSON.stringify(body)}:{})}),{peerAddress:"127.0.0.1"});
  const text=await response.text();return {status:response.status,body:text?JSON.parse(text):null};
};
const ws=p=>`/api/workspaces/${tenantId}/charter/${p}`;
const iso=ms=>new Date(ms).toISOString();

async function rosterFromCharter(recordDate){
  const snap=(await call(ws("snapshots"),{method:"POST",body:{recordDate}})).body;
  const roster=await s.electorates.createRoster(secretary,tenantId,{kind:"unit-register",name:"Shares "+recordDate,commandId:randomUUID()});
  for(const e of snap.rosterEntries)
    await s.electorates.recordEntry(secretary,tenantId,roster.id,{principalId:e.principalId,units:e.units,class:e.class,validFrom:iso(now-HOUR),expectedVersion:0,commandId:randomUUID()});
  now+=1000;
  return {roster,snap};
}
async function proposal(){
  const p=await s.proposals.create(secretary,tenantId,doc.id,{baseVersion:1,selection:{blockId:doc.content[0].id,start:0,end:3,quote:"The"},
    replacement:"This",rationale:"Resolution text.",commandId:randomUUID(),disclosure:"publish-proposal-v1"});
  return p.proposal.id;
}

before(async()=>{
  db=await PGlite.create();
  await applyIdentityMigrations(fn=>db.transaction(fn));
  await applyExtensionMigrations(fn=>db.transaction(fn),charterExtension);
  identity=createIdentityStore({transaction,origin,sessionKey:randomBytes(32),stateKey:randomBytes(32)});
  now=Date.now();
  platform=createPlatform({identity,transaction,login:{},origin,product:"charter",clock:()=>now,enforceEntitlements:false,extensions:[charterExtension]});
  s=platform.services;
  secretary=await user();[common1,common2,pref1,pref2]=[await user(),await user(),await user(),await user()];
  ({tenantId}=await identity.createTenant(secretary));
  for(const who of [common1,common2,pref1,pref2]){const i=await identity.invite(secretary,tenantId,who.accountId,"participant");await identity.acceptInvitation(who,tenantId,i.invitationToken);}
  await call(ws("organization"),{method:"POST",body:{entityType:"corporation",legalName:"Acme, Inc.",jurisdiction:"Delaware"}});
  await call(ws("share-classes"),{method:"POST",body:{id:"common",name:"Common",votesPerShare:"1"}});
  await call(ws("share-classes"),{method:"POST",body:{id:"preferred",name:"Series A Preferred",votesPerShare:"1"}});
  const csv=["holder_account_id,class_id,quantity,effective_date",`${common1.accountId},common,6000,2026-01-01`,`${common2.accountId},common,3000,2026-01-01`,
    `${pref1.accountId},preferred,600,2026-01-01`,`${pref2.accountId},preferred,400,2026-01-01`].join("\n");
  assert.equal((await call(ws("register-imports"),{method:"POST",body:{csv}})).status,200);
  doc=structuredClone(createLegalDocument({id:randomUUID(),tenantId,title:"Board resolution"}));
  doc.content[0].inlines=[{kind:"text",text:"The Company amends its charter."}];
  await s.documents.create(secretary,tenantId,{document:doc,commandId:randomUUID(),disclosure:"publish-all-revisions-v1"});
});
after(async()=>db?.close());

const preferredMajority={class:"preferred",quorum:{numerator:"1",denominator:"2"},approval:{basis:"decisive",comparison:"gt",numerator:"1",denominator:"2"}};

test("multi-class resolution: the common majority cannot carry a charter amendment without the preferred class",async()=>{
  const {roster,snap}=await rosterFromCharter("2026-02-01");
  assert.equal(snap.rosterEntries.length,4);
  const proposalId=await proposal();
  const opened=await s.decisions.open(secretary,tenantId,doc.id,proposalId,{hours:1,commandId:randomUUID(),
    electorate:{source:"roster",rosterId:roster.id,recordDate:iso(now-1)},weighting:"units",
    policySettings:{quorum:{kind:"fraction-weight",numerator:"1",denominator:"2"},classRequirements:[preferredMajority]}});
  assert.equal(opened.eligibleWeight,"10000000000","9,000 common + 1,000 preferred at 6-decimal scale");
  const cast=(who,choice)=>s.decisions.cast(who,tenantId,doc.id,proposalId,{choice,expectedVersion:0,commandId:randomUUID()});
  await cast(common1,"yes");await cast(common2,"yes");
  // Class quorum: only 400 of 1,000 preferred units participate.
  await cast(pref2,"yes");
  now+=HOUR+1;
  const {certificate}=await s.decisions.close(secretary,tenantId,doc.id,proposalId);
  assert.equal(certificate.outcome.overall.approval.met,true);
  assert.equal(certificate.outcome.classes[0].quorum.met,false,"preferred class quorum is a separate requirement");
  assert.equal(certificate.outcome.status,"failed");
});

test("proxy race and cycle: concurrent direct and proxy ballots resolve to the direct vote; reciprocal proxies are refused",async()=>{
  const {roster}=await rosterFromCharter("2026-02-02");
  const proxy=await s.electorates.grantProxy(pref1,tenantId,{granteeId:pref2.accountId,rosterId:roster.id,allocation:null,commandId:randomUUID()});
  await assert.rejects(s.electorates.grantProxy(pref2,tenantId,{granteeId:pref1.accountId,rosterId:roster.id,allocation:null,commandId:randomUUID()}),{code:"PROXY_CYCLE"});
  const proposalId=await proposal();
  await s.decisions.open(secretary,tenantId,doc.id,proposalId,{hours:1,commandId:randomUUID(),
    electorate:{source:"roster",rosterId:roster.id,recordDate:iso(now-1)},weighting:"units",
    policySettings:{quorum:{kind:"fraction-weight",numerator:"1",denominator:"2"},classRequirements:[preferredMajority]}});
  const results=await Promise.allSettled([
    s.decisions.cast(pref2,tenantId,doc.id,proposalId,{choice:"yes",expectedVersion:0,commandId:randomUUID(),onBehalfOf:proxy.id}),
    s.decisions.cast(pref1,tenantId,doc.id,proposalId,{choice:"no",expectedVersion:0,commandId:randomUUID()}),
  ]);
  assert.ok(results.every(r=>r.status==="fulfilled"),JSON.stringify(results.map(r=>r.reason?.code)));
  await s.decisions.cast(pref2,tenantId,doc.id,proposalId,{choice:"yes",expectedVersion:0,commandId:randomUUID()});
  await s.decisions.cast(common1,tenantId,doc.id,proposalId,{choice:"yes",expectedVersion:0,commandId:randomUUID()});
  now+=HOUR+1;
  const {certificate}=await s.decisions.close(secretary,tenantId,doc.id,proposalId);
  assert.equal(certificate.outcome.proxies.supersededByDirect,1,"the principal's direct ballot wins regardless of arrival order");
  const preferred=certificate.outcome.classes[0];
  assert.equal(preferred.quorum.met,true);
  assert.equal(preferred.approval.met,false,"600 no vs 400 yes in the preferred class");
  assert.equal(certificate.outcome.status,"failed");
});
