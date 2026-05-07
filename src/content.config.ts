import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';

const blocks = defineCollection({
  loader: glob({
    pattern: '**/*.json',
    base: './src/content/blocks',
    generateId: ({ entry }) => entry.replace(/\.json$/, ''),
  }),
});

export const collections = { blocks };
