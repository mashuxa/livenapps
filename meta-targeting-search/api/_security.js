'use strict';
const crypto=require('node:crypto');
const COOKIE='lmt_meta_token';
function key(){const raw=process.env.COOKIE_ENCRYPTION_KEY;if(!raw||!/^[a-f0-9]{64}$/i.test(raw))throw Error('COOKIE_ENCRYPTION_KEY is missing or invalid');return Buffer.from(raw,'hex')}
function secure(req){return (req.headers['x-forwarded-proto']||'https')==='https'}
function setCookie(res,name,value,req,maxAge){const parts=[name+'='+value,'Path=/','HttpOnly','SameSite=Strict',maxAge?'Max-Age='+maxAge:'Max-Age=0'];if(secure(req))parts.push('Secure');res.setHeader('Set-Cookie',parts.join('; '))}
function encode(token){const iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',key(),iv);const payload=Buffer.concat([cipher.update(token,'utf8'),cipher.final()]);return Buffer.concat([iv,cipher.getAuthTag(),payload]).toString('base64url')}
function decode(req){const raw=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(COOKIE+'='));if(!raw)return null;try{const buf=Buffer.from(raw.slice(COOKIE.length+1),'base64url');if(buf.length<29)throw Error('bad');const dec=crypto.createDecipheriv('aes-256-gcm',key(),buf.subarray(0,12));dec.setAuthTag(buf.subarray(12,28));return Buffer.concat([dec.update(buf.subarray(28)),dec.final()]).toString('utf8')}catch{return null}}
function send(res,status,obj){res.statusCode=status;res.setHeader('Content-Type','application/json; charset=utf-8');res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');res.end(JSON.stringify(obj))}
function sameOrigin(req){const o=req.headers.origin;if(!o)return false;try{const u=new URL(o);const forwarded=req.headers['x-forwarded-host']||req.headers.host;return u.host===forwarded&&['https:','http:'].includes(u.protocol)}catch{return false}}
function limitBody(req,max=8192){return new Promise((resolve,reject)=>{let size=0,s='';req.on('data',c=>{size+=Buffer.byteLength(c);if(size>max){reject(Error('Body too large'));req.destroy();return}s+=c});req.on('end',()=>{try{resolve(JSON.parse(s||'{}'))}catch{reject(Error('Invalid JSON'))}});req.on('error',reject)})}
function cleanse(v,token){const string=JSON.stringify(v);return JSON.parse(string.replaceAll(token,'[REDACTED]').replace(/EA[A-Za-z0-9]{30,}/g,'[REDACTED]').replace(/access_token(?:%3D|=)[^&"\\ ]+/gi,'access_token=[REDACTED]'))}
module.exports={COOKIE,setCookie,encode,decode,send,sameOrigin,limitBody,cleanse};
