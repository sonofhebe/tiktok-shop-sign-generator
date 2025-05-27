import { VercelRequest, VercelResponse } from '@vercel/node';
import crypto from 'crypto';

const excludeKeys = ['access_token', 'sign'] as const;

interface RequestOptions {
  uri: string;
  qs?: Record<string, string>;
  headers?: Record<string, string>;
  body?: Record<string, any>;
}

const generateSign = (requestOption: RequestOptions, app_secret: string): string => {
  let signString = '';

  // Step 1: Extract and sort query parameters
  const params = requestOption.qs || {};
  const sortedParams = Object.keys(params)
    .filter((key) => !excludeKeys.includes(key as any))
    .sort()
    .map((key) => ({ key, value: params[key] }));

  // Step 2: Concatenate parameters
  const paramString = sortedParams
    .map(({ key, value }) => `${key}${value}`)
    .join('');

  // Step 3: Append to pathname
  const pathname = new URL(requestOption.uri).pathname;
  signString = `${pathname}${paramString}`;

  // Step 4: Append body if not multipart/form-data
  if (
    requestOption.headers?.['content-type'] !== 'multipart/form-data' &&
    requestOption.body &&
    Object.keys(requestOption.body).length
  ) {
    const body = JSON.stringify(requestOption.body);
    signString += body;
  }

  // Step 5: Wrap with app_secret
  signString = `${app_secret}${signString}${app_secret}`;

  // Step 6: Generate HMAC-SHA256
  const hmac = crypto.createHmac('sha256', app_secret);
  hmac.update(signString);
  const sign = hmac.digest('hex');

  return sign;
};

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { requestOption, app_secret } = req.body;
    if (!requestOption || !app_secret) {
      return res.status(400).json({ error: 'Missing requestOption or app_secret' });
    }

    const sign = generateSign(requestOption, app_secret);
    return res.status(200).json({ status: 'success', signature: sign });
  } catch (error) {
    return res.status(500).json({ error: error });
  }
}