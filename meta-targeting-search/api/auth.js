'use strict';
const {COOKIE,setCookie,encode,decode,send,sameOrigin,limitBody}=require('./_security');
module.exports=async function(req,res){
 try{
  if(req.method==='GET')return send(res,200,{authenticated:!!decode(req)});
  if(!['POST','DELETE'].includes(req.method))return send(res,405,{error:'Method not allowed'});
  if(!sameOrigin(req))return send(res,403,{error:'Origin mismatch'});
  if(req.method==='DELETE'){setCookie(res,COOKIE,'',req,0);return send(res,200,{authenticated:false})}
  const body=await limitBody(req);
  const token=typeof body.token==='string'?body.token.trim():'';
  if(!/^[A-Za-z0-9._|\-]{15,4096}$/.test(token))return send(res,400,{error:'Invalid token format'});
  setCookie(res,COOKIE,encode(token),req,3600*12);
  return send(res,200,{authenticated:true,expiresInSeconds:3600*12});
 }catch(e){return send(res,500,{error:'Unable to save token; check COOKIE_ENCRYPTION_KEY'})}
};
