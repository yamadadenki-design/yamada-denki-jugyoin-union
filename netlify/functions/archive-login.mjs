import {equal,signature,headers} from './_auth.mjs';

// Netlify-side per-IP throttling (also applies when passwords are correct).
// Enforcement is not instantaneous; see Netlify deploy post-processing logs.
export const config = {
  path: '/.netlify/functions/archive-login',
  rateLimit: { windowLimit: 5, windowSize: 60, aggregateBy: ['ip','domain'] }
};

export default async function handler(req){
  if(req.method !== 'POST') return new Response('{}',{status:405,headers:{...headers,Allow:'POST'}});
  const expected=process.env.ARCHIVE_PASSWORD;
  if(typeof expected!=='string'|| !/^\d{7}$/.test(expected) || !process.env.ARCHIVE_ENCRYPTION_KEY)
    return new Response(JSON.stringify({error:'設定が未完了です'}),{status:503,headers});
  let password='';
  try{
    const body=await req.text();
    if(body.length>300) return new Response('{}',{status:400,headers});
    const parsed=JSON.parse(body);
    password=parsed?.password;
  }catch{return new Response('{}',{status:400,headers});}
  if(typeof password!=='string' || !/^\d{7}$/.test(password) || !equal(password,expected)){
    await new Promise(resolve=>setTimeout(resolve,1300));
    return new Response('{}',{status:401,headers});
  }
  const exp=String(Date.now()+4*60*60*1000);
  return new Response(JSON.stringify({ok:true}),{headers:{...headers,'Set-Cookie':`archive_session=${exp}.${signature(exp)}; Path=/; Max-Age=14400; Secure; HttpOnly; SameSite=Strict`}});
}
