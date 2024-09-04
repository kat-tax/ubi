import {parse} from './service/parse.ts';
// import {publish} from './service/publish.ts';

const start = performance.now();
parse();
console.log(`Parsing took ${performance.now() - start}ms`);

// publish();