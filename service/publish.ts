import {FleekSdk, PersonalAccessTokenService} from '@fleek-platform/sdk';

const sdk = new FleekSdk({
  accessTokenService: new PersonalAccessTokenService({
    projectId: Deno.env.get('FLEEK_PROJECT_ID') ?? '',
    personalAccessToken: Deno.env.get('FLEEK_PERSONAL_ACCESS_TOKEN') ?? '',
  }),
});

export async function publish(
  index: ArrayBuffer,
  assets: ArrayBuffer[],
  manifests: ArrayBuffer[],
) {
  const {id} = await sdk.ipns().getRecord({name: 'ubi'});
  const list = await sdk.ipfs().add({path: 'index', content: index});
  const hash = list.cid.toString();
  try {
    await sdk.ipns().publishRecord({id, hash});
    await pin(manifests);
    await pin(assets);
    return true;
  } catch (e) {
    console.error(e);
    return false;
  }
}

async function pin(files: ArrayBuffer[]) {
  const batches: ArrayBuffer[][] = [];
  const batchSize = 1000;
  for (let i = 0; i < files.length; i += batchSize) {
    const batch = files.slice(i, i + batchSize);
    batches.push(batch);
  }
  for (const batch of batches) {
    await Promise.all(batch.map(content =>
      sdk.ipfs().add({content})));
  }
}
