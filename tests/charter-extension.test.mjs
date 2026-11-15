import {before,after,test} from "node:test";
import assert from "node:assert/strict";
import {randomUUID,randomBytes} from "node:crypto";
import {PGlite} from "@electric-sql/pglite";
import {createIdentityStore,applyIdentityMigrations} from "@distributed-governance/engine/identity";
import {createPlatform,applyExtensionMigrations} from "@distributed-governance/engine/platform";
import {charterExtension} from "../server/charter-extension.mjs";

const origin="https://charter.example";
let db,platform,identity,secretary,director,holder,outsider,tenantId,now;
const transaction=fn=>db.transaction(async tx=>{await tx.exec("SET LOCAL ROLE dge_identity_runtime");return fn(tx);});
const user=async()=>({...await identity.establishSession({issuer:"https://id.example",subject:randomUUID(),authenticatedAt:Date.now()}),origin});
const call=async(path,{who=secretary,method="GET",body}={})=>{
  const response=await platform.application(new Request(origin+path,{method,headers:{
    ...(who?{cookie:"__Host-dge_session="+who.sessionToken,origin,"x-dge-csrf":who.csrfToken}:{}),
    ...(body!==undefined?{"content-type":"application/json"}:{})},...(body!==undefined?{body:JSON.stringify(body)}:{})}),{peerAddress:"127.0.0.1"});
  const text=await response.text();
  return {status:response.status,body:text?JSON.parse(text):null};
};
const ws=p=>`/api/workspaces/${tenantId}/charter/${p}`;
before(async()=>{
  db=await PGlite.create();
  await applyIdentityMigrations(fn=>db.transaction(fn));
  await applyExtensionMigrations(fn=>db.transaction(fn),charterExtension);
  identity=createIdentityStore({transaction,origin,sessionKey:randomBytes(32),stateKey:randomBytes(32)});
  now=Date.now();
  platform=createPlatform({identity,transaction,login:{},origin,product:"charter",clock:()=>now,extensions:[charterExtension]});
  secretary=await user();director=await user();holder=await user();outsider=await user();
  ({tenantId}=await identity.createTenant(secretary));
  for(const [who,role] of [[director,"editor"],[holder,"participant"]]){
    const invite=await identity.invite(secretary,tenantId,who.accountId,role);
    await identity.acceptInvitation(who,tenantId,invite.invitationToken);
  }
});
after(async()=>db?.close());

test("organization profile and governing rules cite their source and stay tenant-private",async()=>{
  assert.equal((await call(ws("organization"),{method:"POST",body:{entityType:"corporation",legalName:"Acme Widgets, Inc.",jurisdiction:"Delaware"}})).status,200);
  assert.equal((await call(ws("organization"),{method:"POST",body:{entityType:"llc",legalName:"Again",jurisdiction:"Delaware"}})).status,409);
  const rule=await call(ws("rules"),{method:"POST",body:{body:"shareholders",matter:"Charter amendment",reserved:true,source:"Certificate of Incorporation, Art. IX",authority:"DGCL §242 as configured by counsel",
    rule:{weighting:"units",quorum:{kind:"fraction-weight",numerator:"1",denominator:"2"},approval:{basis:"eligible",comparison:"gt",numerator:"1",denominator:"2"},classRequirements:[{class:"preferred",approval:{basis:"eligible",comparison:"gt",numerator:"1",denominator:"2"}}]}}});
  assert.equal(rule.status,200,JSON.stringify(rule.body));
  assert.match(rule.body.disclaimer,/does not verify legal validity/);
  const profile=await call(ws("organization"),{who:holder});
  assert.equal(profile.body.rules[0].matter,"Charter amendment");
  assert.equal((await call(ws("organization"),{who:outsider})).status,403);
  assert.equal((await call(ws("rules"),{who:holder,method:"POST",body:{body:"board",matter:"x",source:"x",authority:"x"}})).status,403);
});

test("record-date snapshots apply class votes per share and ignore later transfers",async()=>{
  await call(ws("share-classes"),{method:"POST",body:{id:"common",name:"Common Stock",votesPerShare:"1"}});
  await call(ws("share-classes"),{method:"POST",body:{id:"preferred",name:"Series A Preferred",votesPerShare:"10"}});
  await call(ws("share-classes"),{method:"POST",body:{id:"nonvoting",name:"Class B Non-voting",votesPerShare:"0"}});
  const csv=["holder_account_id,class_id,quantity,effective_date",
    `${director.accountId},common,1000,2026-01-01`,
    `${holder.accountId},preferred,50.5,2026-01-01`,
    `${holder.accountId},nonvoting,99,2026-01-01`,
    `${director.accountId},common,0,2026-06-01`,
    `${holder.accountId},common,1000,2026-06-01`].join("\n");
  const imported=await call(ws("register-imports"),{method:"POST",body:{csv}});
  assert.equal(imported.body.rows,5,JSON.stringify(imported.body));
  const bad=await call(ws("register-imports"),{method:"POST",body:{csv:"holder_account_id,class_id,quantity,effective_date\n"+outsider.accountId+",common,5,2026-01-01"}});
  assert.equal(bad.status,409,"holders must be workspace members");
  const malformed=await call(ws("register-imports"),{method:"POST",body:{csv:"holder_account_id,class_id,quantity,effective_date\n"+holder.accountId+",common,1.0000001,2026-01-01"}});
  assert.equal(malformed.status,400,"precision beyond the class scale is rejected, never rounded");
  const march=await call(ws("snapshots"),{method:"POST",body:{recordDate:"2026-03-01"}});
  const byHolder=Object.fromEntries(march.body.members.map(m=>[m.principalId+"/"+m.class,m.votingUnits]));
  assert.equal(byHolder[director.accountId+"/common"],"1000000000");
  assert.equal(byHolder[holder.accountId+"/preferred"],"505000000","10 votes per share at 6-decimal scale");
  assert.equal(march.body.nonVoting,1);
  assert.equal(march.body.rosterEntries.length,2);
  const july=await call(ws("snapshots"),{method:"POST",body:{recordDate:"2026-07-01"}});
  assert.equal(july.body.members.some(m=>m.principalId===director.accountId),false,"transfer after March is reflected only in a later record date");
  assert.notEqual(march.body.digest,july.body.digest);
  assert.equal((await call(ws("snapshots"),{who:holder,method:"POST",body:{recordDate:"2026-03-01"}})).status,403);
});

test("meetings track notice compliance; minutes form a verifiable chain",async()=>{
  const meeting=await call(ws("meetings"),{method:"POST",body:{kind:"special",body:"board",title:"Special board meeting",startsAt:new Date(now+10*86400000).toISOString(),minimumNoticeDays:5,agenda:[{title:"Approve budget"}]}});
  assert.equal(meeting.status,200,JSON.stringify(meeting.body));
  let status=await call(ws(`meetings/${meeting.body.id}/notices`));
  assert.equal(status.body.compliant,false);
  for(const who of [secretary,director,holder])
    await call(ws(`meetings/${meeting.body.id}/notices`),{method:"POST",body:{recipientId:who.accountId,method:"email",deliveredAt:new Date(now-1000).toISOString()}});
  status=await call(ws(`meetings/${meeting.body.id}/notices`));
  assert.equal(status.body.compliant,true);
  assert.equal(status.body.notified,3);
  await call(ws(`meetings/${meeting.body.id}/minutes`),{method:"POST",body:{text:"The board approved the budget unanimously."}});
  const book=await call(ws("minute-book"),{who:holder});
  assert.equal(book.body.intact,true);
  assert.equal(book.body.entries.at(-1).kind,"minutes");
  await assert.rejects(transaction(async tx=>{await tx.query("SELECT set_config('dge.tenant_id',$1,true)",[tenantId]);await tx.query("UPDATE app_charter.minute_entries SET entry=entry")}),/append-only|permission denied/);
});

test("written consent passes only on the exact text and records itself in the minute book",async()=>{
  const opened=await call(ws("consents"),{method:"POST",body:{title:"Approve option grant",body:"board",resolutionText:"RESOLVED, that the Company grant 10,000 options to the CFO.",eligible:[secretary.accountId,director.accountId],hours:72}});
  assert.equal(opened.status,200,JSON.stringify(opened.body));
  assert.equal((await call(ws(`consents/${opened.body.id}/signatures`),{who:holder,method:"POST",body:{choice:"consent",textDigest:opened.body.textDigest}})).status,403);
  assert.equal((await call(ws(`consents/${opened.body.id}/signatures`),{who:director,method:"POST",body:{choice:"consent",textDigest:"0".repeat(64)}})).status,409);
  let r=await call(ws(`consents/${opened.body.id}/signatures`),{who:director,method:"POST",body:{choice:"consent",textDigest:opened.body.textDigest}});
  assert.equal(r.body.outcome.passed,false,"unanimity needs every eligible director");
  assert.equal((await call(ws(`consents/${opened.body.id}/signatures`),{who:director,method:"POST",body:{choice:"withhold",textDigest:opened.body.textDigest}})).status,409);
  r=await call(ws(`consents/${opened.body.id}/signatures`),{method:"POST",body:{choice:"consent",textDigest:opened.body.textDigest}});
  assert.equal(r.body.outcome.passed,true);
  const book=await call(ws("minute-book"));
  assert.match(book.body.entries.at(-1).text,/Action by written consent adopted/);
  assert.equal(book.body.intact,true);
});

test("conflicts produce recusals that change the electorate under the disclosed policy",async()=>{
  await call(ws("interests"),{who:holder,method:"POST",body:{kind:"financial",description:"Owns the vendor.",subject:"Vendor contract",recusal:true}});
  const snaps=(await call(ws("snapshots"))).body.items;
  const march=snaps.find(s=>s.recordDate==="2026-03-01");
  const electorate=await call(ws("electorates"),{method:"POST",body:{snapshotId:march.id,subject:"Vendor contract"}});
  assert.deepEqual(electorate.body.recused,[holder.accountId]);
  assert.equal(electorate.body.voters.some(v=>v.principalId===holder.accountId),false);
  assert.equal((await call(ws("interests"),{who:holder})).status,403,"only managers see the interest register");
});

test("legal holds override retention and are final once released",async()=>{
  await call(ws("retention"),{method:"POST",body:{recordClass:"minutes",retainYears:1}});
  const hold=await call(ws("holds"),{method:"POST",body:{name:"Pending litigation",recordClasses:["minutes"]}});
  let records=await call(ws("records"));
  assert.equal(records.body.disposal.find(d=>d.recordClass==="minutes").reason,"legal-hold");
  assert.equal((await call(ws(`holds/${hold.body.id}/release`),{who:director,method:"POST",body:{}})).status,403);
  assert.equal((await call(ws(`holds/${hold.body.id}/release`),{method:"POST",body:{}})).status,200);
  assert.equal((await call(ws(`holds/${hold.body.id}/release`),{method:"POST",body:{}})).status,409);
  records=await call(ws("records"));
  assert.notEqual(records.body.disposal.find(d=>d.recordClass==="minutes").reason,"legal-hold");
  assert.ok(records.body.access.some(a=>a.action==="register-import"));
});
