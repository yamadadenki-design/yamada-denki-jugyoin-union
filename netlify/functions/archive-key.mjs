import {validCookie,headers} from './_auth.mjs';
export default async (req)=>{const key=process.env.ARCHIVE_ENCRYPTION_KEY;if(!validCookie(req)||!key)return new Response('{}',{status:401,headers});return new Response(JSON.stringify({key}),{headers})};
