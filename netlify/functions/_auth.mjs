import {createHmac,timingSafeEqual} from 'node:crypto';
export const headers={'Cache-Control':'no-store','Content-Type':'application/json; charset=utf-8','X-Content-Type-Options':'nosniff'};
export function equal(a,b){if(typeof a!=='string'||typeof b!=='string')return false;const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&timingSafeEqual(x,y)}
export function signature(text){const key=process.env.ARCHIVE_ENCRYPTION_KEY;if(!key)throw new Error('Missing encryption key');return createHmac('sha256',key).update(text).digest('base64url')}
export function validCookie(req){if(!process.env.ARCHIVE_ENCRYPTION_KEY)return false;const value=(req.headers.get('cookie')||'').match(/(?:^|;\s*)archive_session=([^;]+)/)?.[1];if(!value)return false;let [expiry,sig]=value.split('.');const t=Number(expiry);if(!/^\d{13}$/.test(expiry||'')||!sig||!Number.isSafeInteger(t)||t<Date.now()||t>Date.now()+4*60*60*1000)return false;return equal(sig,signature(expiry))}
