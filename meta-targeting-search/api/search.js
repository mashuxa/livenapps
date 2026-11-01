'use strict';
const {decode,send,sameOrigin,limitBody,cleanse}=require('./_security');
const TYPES=new Set(['adworkposition','adinterest','adworkemployer','adbehavior']);
module.exports=async function(req,res){
 if(req.method!=='POST')return send(res,405,{error:'Method not allowed'});
 if(!sameOrigin(req))return send(res,403,{error:'Origin mismatch'});
 const token=decode(req);
 if(!token)return send(res,401,{error:'Token missing or expired; save it again'});
 let body;
 try{body=await limitBody(req)}catch{return send(res,400,{error:'Invalid request body'})}
 const {q,type='adworkposition',version='v26.0',after=null}=body;
 if(typeof q!=='string'||!q.trim()||q.length>150||!TYPES.has(type)||!/^v\d{2}\.\d$/.test(version)||(after!==null&&(typeof after!=='string'||after.length>500)))return send(res,400,{error:'Invalid search parameters'});
 const url=new URL('https://graph.facebook.com/'+version+'/search');
 url.searchParams.set('type',type);url.searchParams.set('q',q.trim());url.searchParams.set('limit','100');if(after)url.searchParams.set('after',after);
 const started=Date.now();
 try{
  const response=await fetch(url,{headers:{Authorization:'Bearer '+token,Accept:'application/json'},signal:AbortSignal.timeout(23000)});
  const bodyText=await response.text();
  let payload;try{payload=JSON.parse(bodyText)}catch{payload={nonJsonResponse:bodyText.slice(0,1800)}}
  const clean=cleanse(payload,token);
  const nextAfter=clean?.paging?.cursors?.after||null;
  // Only expose pagination cursor; never forward Meta URLs that may include access tokens.
  if(clean&&typeof clean==='object')delete clean.paging;
  return send(res,200,{query:{q:q.trim(),type,version},upstream:{status:response.status,ok:response.ok,durationMs:Date.now()-started},meta:clean,nextAfter:typeof nextAfter==='string'?nextAfter:null});
 }catch(e){return send(res,502,{query:{q,type,version},upstream:{status:null,ok:false,durationMs:Date.now()-started},meta:{error:{message:e.name==='TimeoutError'?'Meta request timed out':'Meta request failed'}}})}
};
