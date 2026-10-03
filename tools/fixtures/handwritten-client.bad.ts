// A known-bad file for tools/check-handwritten-client.mjs: a request written by hand, outside the
// generated operation table. The check must fail on it (its self-test proves it does).
export async function handwritten(token: string): Promise<unknown> {
  const response = await fetch('https://api.ever.co/v1/instances/me', { headers: { authorization: `Bearer ${token}` } });
  return response.json();
}

export const request = () => new Request('https://api.ever.co/v1/lookup/salt');
